package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/apache/arrow/go/v13/arrow"
	"github.com/apache/arrow/go/v13/arrow/array"
	"github.com/apache/arrow/go/v13/arrow/memory"
	"github.com/apache/arrow/go/v13/parquet/pqarrow"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/yawning/cryptopan"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
)

func readConfig(configFile string) (dtmConfig, error) {
	conf := dtmConfig{}
	if _, err := toml.DecodeFile(configFile, &conf); err != nil {
		return dtmConfig{}, fmt.Errorf("readConfig: %w", err)
	}
	return conf, nil
}

func main() {

	// Handle flags
	debug := flag.Bool("debug", false, "print debug logging during operation")
	configFile := flag.String("config", "dtm.toml", "config file for sensitive information")
	fileformat := flag.String("file-format", "json", "output format when writing to a file ('json' or 'fstrm')")
	inputUnixSocketPath := flag.String("input-unix", "/var/lib/unbound/dnstap.sock", "create unix socket for reading dnstap")
	outputFilename := flag.String("output-file", "", "the file to write dnstap streams to ('-' means stdout)")
	outputTCP := flag.String("output-tcp", "", "the target and port to write dnstap streams to, e.g. '127.0.0.1:5555'")
	cryptoPanKey := flag.String("cryptopan-key", "", "override the secret used for Crypto-PAn pseudonymization")
	cryptoPanKeySalt := flag.String("cryptopan-key-salt", "dtm-kdf-salt-val", "the salt used for key derivation")
	simpleRandomSamplingN := flag.Int("simple-random-sampling-n", 0, "only capture random 1-out-of-N dnstap messages, 0 disables sampling")
	flag.Parse()

	// For now we only support a single output at a time
	if *outputFilename != "" && *outputTCP != "" {
		slog.Error("flags -output-file and -output-tcp are mutually exclusive, use only one")
		os.Exit(1)
	}

	conf, err := readConfig(*configFile)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	if conf.CryptoPanKey == "" {
		slog.Error(fmt.Sprintf("missing required setting 'cryptopan-key' in %s", *configFile))
		os.Exit(1)
	}

	// While we require setting the Crypto-PAn key in the config file it can be
	// overridden with a flag for testing purposes
	if *cryptoPanKey != "" {
		conf.CryptoPanKey = *cryptoPanKey
	}

	// Logger used for the different background workers, logged to stderr
	// so stdout only includes dnstap data if anything.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// This makes any calls to the standard "log" package to use slog as
	// well
	slog.SetDefault(logger)

	// Configure the selected output writer
	var dnstapOutput dnstap.Output

	if *outputFilename != "" {
		switch *fileformat {
		case "fstrm":
			dnstapOutput, err = dnstap.NewFrameStreamOutputFromFilename(*outputFilename)
			if err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		case "json":
			dnstapOutput, err = dnstap.NewTextOutputFromFilename(*outputFilename, dnstap.JSONFormat, false)
			if err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		default:
			slog.Error("-file-format must be 'fstrm' or 'json'")
			os.Exit(1)
		}
	} else if *outputTCP != "" {
		var naddr net.Addr
		naddr, err := net.ResolveTCPAddr("tcp", *outputTCP)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		dnstapOutput, err = dnstap.NewFrameStreamSockOutput(naddr)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	} else {
		slog.Error("must set -output-file or -output-tcp")
		os.Exit(1)
	}

	// Enable logging for the selected output worker, we depend on
	// slog.SetDefault above to get structed logging.
	switch v := dnstapOutput.(type) {
	case *dnstap.FrameStreamOutput:
		v.SetLogger(log.Default())
	case *dnstap.TextOutput:
		v.SetLogger(log.Default())
	}

	// Create a 32 byte length secret based on the supplied -crypto-pan key,
	// this way the user can supply a -cryptopan-key of any length and
	// we still end up with the 32 byte length expected by AES.
	//
	// Using a proper password KDF (argon2) might be overkill as we are not
	// storing the resulting hash anywhere, but it only affects startup
	// time of a mostly long running tool.
	var aesKeyLen uint32 = 32
	aesKey := argon2.IDKey([]byte(conf.CryptoPanKey), []byte(*cryptoPanKeySalt), 1, 64*1024, 4, aesKeyLen)

	dnsSessionRowSchema := dnsSessionRowArrowSchema()
	fmt.Println(dnsSessionRowSchema)

	arrowPool := memory.NewGoAllocator()

	// Create an instance of the filter
	dtf, err := newDnstapFilter(log.Default(), dnstapOutput, aesKey, *simpleRandomSamplingN, *debug)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	// Setup the unix socket dnstap.Input
	dti, err := dnstap.NewFrameStreamSockInputFromPath(*inputUnixSocketPath)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	dti.SetTimeout(time.Second * 5)
	dti.SetLogger(log.Default())

	// Exit gracefully on SIGINT or SIGTERM
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
		<-sigs

		// We received a signal, tell runFilter() to stop
		close(dtf.stop)
	}()

	dnsSessionRowBuilder := array.NewRecordBuilder(arrowPool, dnsSessionRowSchema)
	defer dnsSessionRowBuilder.Release()

	// Start filter
	go dtf.runFilter(arrowPool, dnsSessionRowSchema, dnsSessionRowBuilder)

	// Start dnstap.Output
	go dnstapOutput.RunOutputLoop()

	// Start dnstap.Input
	go dti.ReadInto(dtf.inputChannel)

	// Wait here until runFilter() is done
	<-dtf.done
}

type dtmConfig struct {
	CryptoPanKey string `toml:"cryptopan-key"`
}

type dnstapFilter struct {
	inputChannel chan []byte          // the channel expected to be passed to dnstap ReadInto()
	dnstapOutput dnstap.Output        // the dnstap.Output we send modified dnstap messages to
	log          dnstap.Logger        // any information logging is sent here
	cryptopan    *cryptopan.Cryptopan // used for pseudonymizing IP addresses
	stop         chan struct{}        // close this channel to gracefully stop runFilter()
	done         chan struct{}        // block on this channel to make sure output is flushed before exiting
	simpleSample int                  // only capture random 1-out-of-N dnstap messages and discard the rest, the value 0 disables sampling
	debug        bool                 // if we should print debug messages during operation
}

func newDnstapFilter(logger dnstap.Logger, dnstapOutput dnstap.Output, cryptoPanKey []byte, simpleRandomSamplingN int, debug bool) (*dnstapFilter, error) {
	cpn, err := cryptopan.New(cryptoPanKey)
	if err != nil {
		return nil, err
	}
	dtf := &dnstapFilter{}
	dtf.cryptopan = cpn
	dtf.stop = make(chan struct{})
	dtf.done = make(chan struct{})
	dtf.inputChannel = make(chan []byte, cap(dnstapOutput.GetOutputChannel()))
	dtf.dnstapOutput = dnstapOutput
	dtf.simpleSample = simpleRandomSamplingN
	dtf.log = logger
	dtf.debug = debug

	return dtf, nil
}

// runFilter reads frames from the inputChannel, doing any modifications and
// then passes them on to a dnstap.Output. To gracefully stop
// runFilter() you need to close the dtf.stop channel.
func (dtf *dnstapFilter) runFilter(arrowPool *memory.GoAllocator, arrowSchema *arrow.Schema, dnsSessionRowBuilder *array.RecordBuilder) {
	dt := &dnstap.Dnstap{}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	label0 := dnsSessionRowBuilder.Field(0).(*array.StringBuilder)
	defer label0.Release()
	label1 := dnsSessionRowBuilder.Field(1).(*array.StringBuilder)
	defer label1.Release()
	label2 := dnsSessionRowBuilder.Field(2).(*array.StringBuilder)
	defer label1.Release()
	label3 := dnsSessionRowBuilder.Field(3).(*array.StringBuilder)
	defer label3.Release()
	label4 := dnsSessionRowBuilder.Field(4).(*array.StringBuilder)
	defer label4.Release()
	label5 := dnsSessionRowBuilder.Field(5).(*array.StringBuilder)
	defer label5.Release()
	label6 := dnsSessionRowBuilder.Field(6).(*array.StringBuilder)
	defer label6.Release()
	label7 := dnsSessionRowBuilder.Field(7).(*array.StringBuilder)
	defer label7.Release()
	label8 := dnsSessionRowBuilder.Field(8).(*array.StringBuilder)
	defer label8.Release()
	label9 := dnsSessionRowBuilder.Field(9).(*array.StringBuilder)
	defer label9.Release()

	// Store labels in a slice so we can reference them by index
	labelSlice := []*array.StringBuilder{label0, label1, label2, label3, label4, label5, label6, label7, label8, label9}
	lastLabelOffset := len(labelSlice) - 1

	// Keep track of if we have recorded any dnstap packets or not at rotation time
	var dnstap_seen bool

	var queryAddress, responseAddress string

filterLoop:
	for {
		select {
		case frame := <-dtf.inputChannel:
			if dtf.simpleSample > 0 {
				// #nosec G404 -- Deterministic math/rand should be OK for sampling purposes
				if rand.Intn(dtf.simpleSample) != 0 {
					if dtf.debug {
						dtf.log.Printf("skipping dnstap message due to sampling")
					}
					continue
				}
			}
			if err := proto.Unmarshal(frame, dt); err != nil {
				dtf.log.Printf("dnstapFilter.runFilter: proto.Unmarshal() failed: %s, returning", err)
				break filterLoop
			}

			isQuery := strings.HasSuffix(dnstap.Message_Type_name[int32(*dt.Message.Type)], "_QUERY")

			// For now we only care about response type dnstap packets
			if isQuery {
				continue
			}

			if dtf.debug {
				dtf.log.Printf("dnstapFilter.runFilter: modifying dnstap message")
			}
			dtf.pseudonymizeDnstap(dt)

			msg := new(dns.Msg)

			//var t time.Time
			var err error

			qa := net.IP(dt.Message.QueryAddress)
			ra := net.IP(dt.Message.ResponseAddress)

			// Query address: 10.10.10.10:31337 or ?
			if qa != nil {
				queryAddress = qa.String() + ":" + strconv.FormatUint(uint64(*dt.Message.QueryPort), 10)
			} else {
				queryAddress = "?"
			}

			// Response address: 10.10.10.10:31337 or ?
			if ra != nil {
				responseAddress = ra.String() + ":" + strconv.FormatUint(uint64(*dt.Message.ResponsePort), 10)
			} else {
				responseAddress = "?"
			}

			if isQuery {
				err = msg.Unpack(dt.Message.QueryMessage)
				if err != nil {
					log.Printf("unable to unpack query message (%s -> %s): %s", queryAddress, responseAddress, err)
					msg = nil
				}
				//t = time.Unix(int64(*dt.Message.QueryTimeSec), int64(*dt.Message.QueryTimeNsec))
			} else {
				err = msg.Unpack(dt.Message.ResponseMessage)
				if err != nil {
					log.Printf("unable to unpack response message (%s <- %s): %s", queryAddress, responseAddress, err)
					msg = nil
				}
				//t = time.Unix(int64(*dt.Message.ResponseTimeSec), int64(*dt.Message.ResponseTimeNsec))
			}

			// For cases where we were unable to unpack the DNS message we
			// skip parsing.
			if msg == nil || len(msg.Question) == 0 {
				dtf.log.Printf("unable to parse dnstap message, or no question section, skipping parsing")
				continue
			}

			if _, ok := dns.IsDomainName(msg.Question[0].Name); !ok {
				dtf.log.Printf("unable to parse question name, skipping parsing")
				continue
			}

			// Store the labels in reverse order (example.com ->
			// ["com", "example"] to map to label0 being the TLD
			labels := dns.SplitDomainName(msg.Question[0].Name)

			// labels is nil if this is the root domain (.)
			if labels == nil {
				fmt.Println("setting all labels to null")
				for _, arrowLabel := range labelSlice {
					arrowLabel.AppendNull()
				}
			} else {
				// Since arrow label0-label9 is the reverse
				// order from our dns labels we need to map the
				// last dns label to label0, the second last to
				// label1 etc.
				//
				// Also, we only store up to the ninth label
				// (label8) separately, after that the
				// remainder goes in the tenth label (label9)
				var leftMostLabel int
				if len(labels) > lastLabelOffset {
					leftMostLabel = len(labels) - lastLabelOffset
				} else {
					leftMostLabel = 0
				}

				dtf.log.Printf("leftMostLabel: ", leftMostLabel)

				// Iterate backwards over the labels in dnstap
				// packet, and iterate forward over the arrow
				// label0-9 fields
				arrowLabelIndex := 0
				for i := len(labels) - 1; i >= leftMostLabel; i-- {
					fmt.Printf("setting label%d to %s (%d)\n", arrowLabelIndex, labels[i], i)
					labelSlice[arrowLabelIndex].Append(labels[i])
					arrowLabelIndex++
				}

				if leftMostLabel > 0 {
					// There remains labels that did not fit
					// in label0-label8, insert the rest of
					// them in label9
					remainderSlice := labels[0:leftMostLabel]

					// We store the labels backwards to match label0-label8
					slices.Reverse(remainderSlice)
					dtf.log.Printf("setting label%d to remainderSlice to %s\n", lastLabelOffset, remainderSlice)
					labelSlice[lastLabelOffset].Append(strings.Join(remainderSlice, "."))
				} else {
					// We managed to fit all labels inside
					// label0-8, fill out any remaining
					// labelX fields with null
					for i := arrowLabelIndex; i <= lastLabelOffset; i++ {
						fmt.Printf("setting remaining label%d to null\n", i)
						labelSlice[i].AppendNull()
					}
				}
			}

			b, err := proto.Marshal(dt)
			if err != nil {
				dtf.log.Printf("dnstapFilter.runFilter: proto.Marshal() failed: %s, returning", err)
				break filterLoop
			}
			dtf.dnstapOutput.GetOutputChannel() <- b

			dnstap_seen = true

		case <-ticker.C:
			if !dnstap_seen {
				dtf.log.Printf("no dnstap seen, we have not received any dnstap frames, printing nothing")
				continue
			}

			// Prepare for next collection phase
			dnstap_seen = false

			err := writeParquet(dtf, arrowSchema, dnsSessionRowBuilder)
			if err != nil {
				continue
			}
		case <-dtf.stop:
			break filterLoop
		}
	}
	// We close the dnstap.Output so it has a chance to flush out its messages
	dtf.dnstapOutput.Close()
	// Signal main() that we are done and ready to exit
	close(dtf.done)
}

func writeParquet(dtf *dnstapFilter, arrowSchema *arrow.Schema, dnsSessionRowBuilder *array.RecordBuilder) error {
	outFileName := "/tmp/dns_session_block.parquet"
	dtf.log.Printf("writing out parquet file %s", outFileName)
	outFile, err := os.Create(outFileName)
	if err != nil {
		dtf.log.Printf("unable to open %s", outFileName)
	}
	defer outFile.Close()
	parquetWriter, err := pqarrow.NewFileWriter(arrowSchema, outFile, nil, pqarrow.DefaultWriterProps())
	if err != nil {
		dtf.log.Printf("unable to create parquet writer: %w", err)
	}

	rec1 := dnsSessionRowBuilder.NewRecord()
	defer rec1.Release()

	err = parquetWriter.Write(rec1)
	if err != nil {
		return fmt.Errorf("unable to write parquet file: %w", err)
	}
	err = parquetWriter.Close()
	if err != nil {
		return fmt.Errorf("unable to close parquet file: %w", err)
	}

	jsonBytes, err := rec1.MarshalJSON()
	if err != nil {
		return fmt.Errorf("error marshalling json fron rec: %w", err)
	}
	fmt.Println(string(jsonBytes))

	return nil
}

// Anonymize IP address fields in a dnstap message
func (dtf *dnstapFilter) pseudonymizeDnstap(dt *dnstap.Dnstap) {
	dt.Message.QueryAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.QueryAddress))
	dt.Message.ResponseAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.ResponseAddress))
}
