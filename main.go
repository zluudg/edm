package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"hash"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/apache/arrow/go/v13/arrow"
	"github.com/apache/arrow/go/v13/arrow/array"
	"github.com/apache/arrow/go/v13/arrow/memory"
	"github.com/apache/arrow/go/v13/parquet/pqarrow"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/segmentio/go-hll"
	"github.com/smhanov/dawg"
	"github.com/spaolacci/murmur3"
	"github.com/xitongsys/parquet-go/writer"
	"github.com/yaronf/httpsign"
	"github.com/yawning/cryptopan"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
)

type histogramData struct {
	// label fields must be exported as we set them using reflection,
	// otherwise: "panic: reflect: reflect.Value.SetString using value obtained using unexported field"
	// Also store them as pointers so we can signal them being unset as
	// opposed to an empty string
	Label0     *string `parquet:"name=label0, type=BYTE_ARRAY"`
	Label1     *string `parquet:"name=label1, type=BYTE_ARRAY"`
	Label2     *string `parquet:"name=label2, type=BYTE_ARRAY"`
	Label3     *string `parquet:"name=label3, type=BYTE_ARRAY"`
	Label4     *string `parquet:"name=label4, type=BYTE_ARRAY"`
	Label5     *string `parquet:"name=label5, type=BYTE_ARRAY"`
	Label6     *string `parquet:"name=label6, type=BYTE_ARRAY"`
	Label7     *string `parquet:"name=label7, type=BYTE_ARRAY"`
	Label8     *string `parquet:"name=label8, type=BYTE_ARRAY"`
	Label9     *string `parquet:"name=label9, type=BYTE_ARRAY"`
	ACount     int64   `parquet:"name=a_count, type=INT64, convertedtype=UINT_64"`
	OtherCount int64   `parquet:"name=other_count, type=INT64, convertedtype=UINT_64"`
	// The hll.HLL structs are not expected to be included in the output
	// parquet file, and thus do not need to be exported
	v4ClientHLL           hll.Hll
	v6ClientHLL           hll.Hll
	V4ClientCountHLLBytes []byte `parquet:"name=v4client_count, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY"`
	V6ClientCountHLLBytes []byte `parquet:"name=v6client_count, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY"`
}

func readConfig(configFile string) (dtmConfig, error) {
	conf := dtmConfig{}
	if _, err := toml.DecodeFile(configFile, &conf); err != nil {
		return dtmConfig{}, fmt.Errorf("readConfig: %w", err)
	}
	return conf, nil
}

func setHistogramLabels(labels []string, labelLimit int, hd *histogramData) *histogramData {
	// If labels is nil (the "." zone) we can depend on the zero type of
	// the label fields being nil, so nothing to do
	if labels == nil {
		return hd
	}

	reverseLabels := reverseLabelsBounded(labels, labelLimit)

	s := reflect.ValueOf(hd).Elem()

	for index := range reverseLabels {
		s.FieldByName("Label" + strconv.Itoa(index)).Set(reflect.ValueOf(&reverseLabels[index]))
	}

	return hd
}

func reverseLabelsBounded(labels []string, maxLen int) []string {
	// If labels is nil (the "." zone) there is nothing to do
	if labels == nil {
		return nil
	}

	boundedReverseLabels := []string{}

	remainderElems := 0
	if len(labels) > maxLen {
		remainderElems = len(labels) - maxLen
	}

	// Append all labels except the last one
	for i := len(labels) - 1; i > remainderElems; i-- {
		fmt.Printf("appending %s (%d)\n", labels[i], i)
		boundedReverseLabels = append(boundedReverseLabels, labels[i])
	}

	// If the labels fit inside maxLen then just append the last remaining
	// label as-is
	if len(labels) <= maxLen {
		fmt.Printf("appending final label %s (%d)\n", labels[0], 0)
		boundedReverseLabels = append(boundedReverseLabels, labels[0])
	} else {
		// If there are more labels than maxLen we need to concatenate
		// them before appending the last element
		if remainderElems > 0 {
			fmt.Println("building slices of remainders")
			remainderLabels := []string{}
			for i := remainderElems; i >= 0; i-- {
				remainderLabels = append(remainderLabels, labels[i])
			}

			boundedReverseLabels = append(boundedReverseLabels, strings.Join(remainderLabels, "."))
		}

	}
	return boundedReverseLabels
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
	dawgFile := flag.String("well-known-domains", "well-known-domains.dawg", "the dawg file used for filtering well-known domains")
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
	dtf, err := newDnstapFilter(log.Default(), dnstapOutput, aesKey, *debug)
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

	// Set default values for HLL
	err = hll.Defaults(hll.Settings{
		Log2m:             10,
		Regwidth:          4,
		ExplicitThreshold: hll.AutoExplicitThreshold,
		SparseEnabled:     true,
	})
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

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
	go dtf.runFilter(arrowPool, dnsSessionRowSchema, dnsSessionRowBuilder, *dawgFile)

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
	debug        bool                 // if we should print debug messages during operation
}

func newDnstapFilter(logger dnstap.Logger, dnstapOutput dnstap.Output, cryptoPanKey []byte, debug bool) (*dnstapFilter, error) {
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
	dtf.log = logger
	dtf.debug = debug

	return dtf, nil
}

type wellKnownDomainsTracker struct {
	mutex sync.RWMutex
	wellKnownDomainsData
}

type wellKnownDomainsData struct {
	// Store a pointer to histogramCounters so we can assign to it without
	// "cannot assign to struct field in map" issues
	m             map[int]*histogramData
	dawgFinder    dawg.Finder
	murmur3Hasher hash.Hash64
}

func newWellKnownDomainsTracker(dawgFinder dawg.Finder) (*wellKnownDomainsTracker, error) {

	// Create random uint32, rand.Int takes a half-open range so we give it [0,4294967296)
	randInt, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return nil, err
	}
	murmur3Seed := uint32(randInt.Uint64())

	murmur3Hasher := murmur3.New64WithSeed(murmur3Seed)

	return &wellKnownDomainsTracker{
		wellKnownDomainsData: wellKnownDomainsData{
			m:             map[int]*histogramData{},
			dawgFinder:    dawgFinder,
			murmur3Hasher: murmur3Hasher,
		},
	}, nil
}

func (wkd *wellKnownDomainsTracker) isKnown(ipBytes []byte, q dns.Question) bool {

	wkd.mutex.Lock()
	defer wkd.mutex.Unlock()

	index := wkd.dawgFinder.IndexOf(q.Name)

	// If this is is not a well-known domain just return as fast as
	// possible
	if index == -1 {
		return false
	}

	if _, exists := wkd.m[index]; !exists {
		// We leave the label0-9 fields set to nil here. Since this is in
		// the hot path of dealing with dnstap packets the less work we do the
		// better. They are filled in prior to writing out the parquet file.
		wkd.m[index] = &histogramData{}
	}

	// Create hash from IP address for use in HLL data
	ip, ok := netip.AddrFromSlice(ipBytes)
	if ok {
		//fmt.Printf("ip: %s\n", ip.String())
		wkd.murmur3Hasher.Write(ipBytes) // #nosec G104 -- Write() on hash.Hash never returns an error (https://pkg.go.dev/hash#Hash)
		if ip.Unmap().Is4() {
			wkd.m[index].v4ClientHLL.AddRaw(wkd.murmur3Hasher.Sum64())
		} else {
			wkd.m[index].v6ClientHLL.AddRaw(wkd.murmur3Hasher.Sum64())
		}
		wkd.murmur3Hasher.Reset()
	}

	switch q.Qtype {
	case dns.TypeA:
		wkd.m[index].ACount++
	default:
		wkd.m[index].OtherCount++
	}

	return true
}

func (wkd *wellKnownDomainsTracker) rotateTracker(dawgFile string) (*wellKnownDomainsData, error) {

	dawgFinder, err := dawg.Load(dawgFile)
	if err != nil {
		return nil, err
	}

	prevWKD := &wellKnownDomainsData{}

	// Swap the map in use so we can write parquet data outside of the write lock
	wkd.mutex.Lock()
	prevWKD.m = wkd.m
	prevWKD.dawgFinder = wkd.dawgFinder
	wkd.m = map[int]*histogramData{}
	wkd.dawgFinder = dawgFinder
	wkd.mutex.Unlock()

	return prevWKD, nil
}

// runFilter reads frames from the inputChannel, doing any modifications and
// then passes them on to a dnstap.Output. To gracefully stop
// runFilter() you need to close the dtf.stop channel.
func (dtf *dnstapFilter) runFilter(arrowPool *memory.GoAllocator, arrowSchema *arrow.Schema, dnsSessionRowBuilder *array.RecordBuilder, dawgFile string) {
	dt := &dnstap.Dnstap{}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Labels
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

	// Timestamps
	queryTime := dnsSessionRowBuilder.Field(10).(*array.TimestampBuilder)
	defer queryTime.Release()
	responseTime := dnsSessionRowBuilder.Field(11).(*array.TimestampBuilder)
	defer responseTime.Release()

	// Store labels in a slice so we can reference them by index
	labelSlice := []*array.StringBuilder{label0, label1, label2, label3, label4, label5, label6, label7, label8, label9}
	labelLimit := len(labelSlice)

	// Keep track of if we have recorded any dnstap packets in arrow data
	var arrow_updated bool

	// Channel used to feed the session writer, buffered so we do not block
	// filterLoop if writing is slow
	sessionWriterCh := make(chan arrow.Record, 100)

	// Channel used to feed the histogram writer, buffered so we do not block
	// filterLoop if writing is slow
	histogramWriterCh := make(chan *wellKnownDomainsData, 100)

	// Start the record writers in the background
	go sessionWriter(dtf, arrowSchema, sessionWriterCh)
	go histogramWriter(dtf, histogramWriterCh, labelLimit)

	dawgFinder, err := dawg.Load(dawgFile)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	wkdTracker, err := newWellKnownDomainsTracker(dawgFinder)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

filterLoop:
	for {
		select {
		case frame := <-dtf.inputChannel:
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

			msg, timestamp := parsePacket(dt, isQuery)

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

			// We pass on the client address for cardinality
			// measurements.
			if wkdTracker.isKnown(dt.Message.QueryAddress, msg.Question[0]) {
				dtf.log.Printf("skipping well-known domain %s", msg.Question[0].Name)
				continue
			}

			setLabels(dtf, msg, labelLimit, labelSlice)

			setTimestamp(dtf, isQuery, timestamp, queryTime, responseTime)

			// Since we have set fields in the arrow data at this
			// point we have things to write out
			arrow_updated = true

			b, err := proto.Marshal(dt)
			if err != nil {
				dtf.log.Printf("dnstapFilter.runFilter: proto.Marshal() failed: %s, returning", err)
				break filterLoop
			}
			dtf.dnstapOutput.GetOutputChannel() <- b

		case <-ticker.C:
			if arrow_updated {
				record := dnsSessionRowBuilder.NewRecord()
				// We have created a record and therefore the recordbuilder is reset
				arrow_updated = false

				sessionWriterCh <- record
			}

			prevWKD, err := wkdTracker.rotateTracker(dawgFile)
			if err != nil {
				dtf.log.Printf("unable to rotate histogram map: %s", err)
				continue
			}

			// Only write out parquet file if there is something to write
			if len(prevWKD.m) > 0 {
				histogramWriterCh <- prevWKD
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

func sessionWriter(dtf *dnstapFilter, arrowSchema *arrow.Schema, ch chan arrow.Record) {
	for {
		record := <-ch
		err := writeSession(dtf, arrowSchema, record)
		if err != nil {
			dtf.log.Printf(err.Error())
		}

	}
}

func histogramWriter(dtf *dnstapFilter, ch chan *wellKnownDomainsData, labelLimit int) {
	for {
		prevWellKnownDomainsData := <-ch
		dtf.log.Printf("in histogramWriter")
		err := writeHistogramParquet(dtf, prevWellKnownDomainsData, labelLimit)
		if err != nil {
			dtf.log.Printf(err.Error())
		}

	}
}

func parsePacket(dt *dnstap.Dnstap, isQuery bool) (*dns.Msg, time.Time) {
	var t time.Time
	var err error
	var queryAddress, responseAddress string

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
	msg := new(dns.Msg)
	if isQuery {
		err = msg.Unpack(dt.Message.QueryMessage)
		if err != nil {
			log.Printf("unable to unpack query message (%s -> %s): %s", queryAddress, responseAddress, err)
			msg = nil
		}
		t = time.Unix(int64(*dt.Message.QueryTimeSec), int64(*dt.Message.QueryTimeNsec))
	} else {
		err = msg.Unpack(dt.Message.ResponseMessage)
		if err != nil {
			log.Printf("unable to unpack response message (%s <- %s): %s", queryAddress, responseAddress, err)
			msg = nil
		}
		t = time.Unix(int64(*dt.Message.ResponseTimeSec), int64(*dt.Message.ResponseTimeNsec))
	}

	return msg, t
}

func setLabels(dtf *dnstapFilter, msg *dns.Msg, labelLimit int, labelSlice []*array.StringBuilder) {
	labels := dns.SplitDomainName(msg.Question[0].Name)

	// labels is nil if this is the root domain (.)
	if labels == nil {
		dtf.log.Printf("setting all labels to null")
		for _, arrowLabel := range labelSlice {
			arrowLabel.AppendNull()
		}
	} else {
		reverseLabels := reverseLabelsBounded(labels, labelLimit)
		for i, label := range reverseLabels {
			dtf.log.Printf("setting label%d to %s", i, label)
			labelSlice[i].Append(label)
		}

		// Fill out remaining labels with null if needed
		if len(reverseLabels) < labelLimit {
			for i := len(reverseLabels); i < labelLimit; i++ {
				dtf.log.Printf("setting remaining label%d to null\n", i)
				labelSlice[i].AppendNull()
			}
		}
	}
}

func setTimestamp(dtf *dnstapFilter, isQuery bool, timestamp time.Time, queryTime *array.TimestampBuilder, responseTime *array.TimestampBuilder) {
	if isQuery {
		responseTime.AppendNull()
		arrowTimeQuery, err := arrow.TimestampFromTime(timestamp, arrow.Nanosecond)
		if err != nil {
			dtf.log.Printf("unable to parse query_time: %s, appending null", err)
			queryTime.AppendNull()
		} else {
			queryTime.Append(arrowTimeQuery)
		}
	} else {
		queryTime.AppendNull()
		arrowTimeResponse, err := arrow.TimestampFromTime(timestamp, arrow.Nanosecond)
		if err != nil {
			dtf.log.Printf("unable to parse response_time: %s, appending null", err)
			responseTime.AppendNull()
		} else {
			responseTime.Append(arrowTimeResponse)
		}
	}
}

func writeSession(dtf *dnstapFilter, arrowSchema *arrow.Schema, record arrow.Record) error {
	defer record.Release()
	outFileName := "/tmp/dns_session_block.parquet"
	dtf.log.Printf("writing out parquet file %s", outFileName)
	outFile, err := os.Create(outFileName)
	if err != nil {
		return fmt.Errorf("unable to open %s", outFileName)
	}
	// No need to defer outFile.Close(), handled by parquetWriter.Close() below.

	parquetWriter, err := pqarrow.NewFileWriter(arrowSchema, outFile, nil, pqarrow.DefaultWriterProps())
	if err != nil {
		return fmt.Errorf("unable to create parquet writer: %w", err)
	}

	err = parquetWriter.Write(record)
	if err != nil {
		return fmt.Errorf("unable to write parquet file: %w", err)
	}
	err = parquetWriter.Close()
	if err != nil {
		return fmt.Errorf("unable to close parquet file: %w", err)
	}

	jsonBytes, err := record.MarshalJSON()
	if err != nil {
		return fmt.Errorf("error marshalling json fron rec: %w", err)
	}
	fmt.Println(string(jsonBytes))

	return nil
}

func writeHistogramParquet(dtf *dnstapFilter, prevWellKnownDomainsData *wellKnownDomainsData, labelLimit int) error {
	dtf.log.Printf("in writeHistogramParquet")
	outFileName := "/tmp/dns_histogram.parquet"
	//dtf.log.Printf("writing out histogram file %s", outFileName)
	outFile, err := os.Create(outFileName)
	if err != nil {
		return fmt.Errorf("unable to open %s", outFileName)
	}
	defer func() {
		err := outFile.Close()
		if err != nil {
			dtf.log.Printf("unable to close histogram outfile: %s", err)
		}
	}()

	parquetWriter, err := writer.NewParquetWriterFromWriter(outFile, new(histogramData), 4)
	if err != nil {
		return fmt.Errorf("writeHistogramParquet: %w", err)
	}

	for index, hGramData := range prevWellKnownDomainsData.m {
		domain, err := prevWellKnownDomainsData.dawgFinder.AtIndex(index)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %#v\n", domain, *hGramData)

		labels := dns.SplitDomainName(domain)

		// Setting the labels now when we are out of the hot path.
		setHistogramLabels(labels, labelLimit, hGramData)

		dtf.log.Printf("ipv4 cardinality: %d", hGramData.v4ClientHLL.Cardinality())
		dtf.log.Printf("ipv6 cardinality: %d", hGramData.v6ClientHLL.Cardinality())

		// Write out the bytes from our hll data structures
		hGramData.V4ClientCountHLLBytes = hGramData.v4ClientHLL.ToBytes()
		hGramData.V6ClientCountHLLBytes = hGramData.v6ClientHLL.ToBytes()

		err = parquetWriter.Write(hGramData)
		if err != nil {
			return err
		}
	}

	err = parquetWriter.WriteStop()
	if err != nil {
		return fmt.Errorf("unable to call WriteStop on parquet writer: %w", err)
	}

	return nil
}

// Pseudonymize IP address fields in a dnstap message
func (dtf *dnstapFilter) pseudonymizeDnstap(dt *dnstap.Dnstap) {
	dt.Message.QueryAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.QueryAddress))
	dt.Message.ResponseAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.ResponseAddress))
}

// Send histogram data via signed HTTP message to aggregate-receiver (https://github.com/dnstapir/aggregate-receiver)
func sendHistogramParquet(aggrecURL url.URL, fileName string, privKey *ecdsa.PrivateKey) error {

	baseDir := "/var/lib/dtm"
	histogramFileName := filepath.Join(baseDir, fileName)

	histogramFileName = filepath.Clean(histogramFileName)

	if !strings.HasPrefix(histogramFileName, baseDir+"/") {
		return fmt.Errorf("sendHistogramParquet: bad prefix for histogram directory: '%s', must start with: '%s'", histogramFileName, baseDir)
	}
	file, err := os.Open(histogramFileName)
	if err != nil {
		return fmt.Errorf("sendAggregateFile: unable to open file: %w", err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("sendAggregateFile: unable to stat file: %w", err)
	}

	fileSize := fileInfo.Size()

	// Set some timouts to protect from hanging connections
	httpClient := http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	// Create signer and wrapped HTTP client
	signer, _ := httpsign.NewP256Signer("key1", *privKey,
		httpsign.NewSignConfig(),
		httpsign.Headers("content-type", "content-length", "content-digest")) // The Content-Digest header will be auto-generated
	client := httpsign.NewClient(httpClient, httpsign.NewClientConfig().SetSignatureName("sig1").SetSigner(signer)) // sign requests, don't verify responses

	// Send signed HTTP POST message
	req, err := http.NewRequest("POST", aggrecURL.String(), bufio.NewReader(file))
	if err != nil {
		return fmt.Errorf("sendAggregateFile: unable to create request: %w", err)
	}

	// From https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-digest-headers-13#section-6.3:
	// ===
	// Digests explicitly depend on the "representation metadata" (e.g.,
	// the values of Content-Type, Content-Encoding etc.). A signature that
	// protects Integrity fields but not other "representation metadata"
	// can expose the communication to tampering.
	// ===
	req.Header.Add("Content-Type", "application/vnd.apache.parquet")

	// This is set automatically by the transport, but we need to add it
	// here as well to make the signer see it, otherwise it errors out:
	// ===
	// failed to sign request: header content-length not found
	// ===
	req.Header.Add("Content-Length", strconv.FormatInt(fileSize, 10))

	// Beacuse we are using a bufio.Reader we need to set the length
	// here as well, otherwise net/http will set the header
	// "Transfer-Encoding: chunked" and remove the Content-Length header.
	req.ContentLength = fileSize

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sendAggregateFile: unable to send request: %w", err)
	}

	err = res.Body.Close()
	if err != nil {
		return fmt.Errorf("sendAggregateFile: unable to close HTTP body: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("sendAggregateFile: unexpected status code: %d", res.StatusCode)
	}

	return nil
}
