package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
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
	"github.com/xitongsys/parquet-go/writer"
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
}

func readConfig(configFile string) (dtmConfig, error) {
	conf := dtmConfig{}
	if _, err := toml.DecodeFile(configFile, &conf); err != nil {
		return dtmConfig{}, fmt.Errorf("readConfig: %w", err)
	}
	return conf, nil
}

func mapLabelsToHistogramData(labels []string, hgd *histogramData, labelLimit int) {
	// If labels is nil (the "." zone) we can depend on the zero type of
	// the label fields being nil, so nothing to do
	if labels == nil {
		return
	}

	reverseLabels := reverseLabelsBounded(labels, labelLimit)

	s := reflect.ValueOf(hgd).Elem()

	for index := range reverseLabels {
		s.FieldByName("Label" + strconv.Itoa(index)).Set(reflect.ValueOf(&reverseLabels[index]))
	}
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

func newWellKnownDomainsMap(domainsList []string, labelLimit int) (map[string]*histogramData, error) {
	m := map[string]*histogramData{}

	for _, domain := range domainsList {
		if _, ok := dns.IsDomainName(domain); !ok {
			return nil, fmt.Errorf("string '%s' is not a valid domain name", domain)
		}

		labels := dns.SplitDomainName(domain)

		hgd := &histogramData{}

		mapLabelsToHistogramData(labels, hgd, labelLimit)

		m[dns.Fqdn(domain)] = hgd
	}

	return m, nil
}

type wellKnownDomainsTracker struct {
	mutex sync.RWMutex
	// Store a pointer to histogramData so we can assign to it without
	// "cannot assign to struct field in map" issues
	m map[string]*histogramData
}

func newWellKnownDomainsTracker(domainsList []string, labelLimit int) (*wellKnownDomainsTracker, error) {
	m, err := newWellKnownDomainsMap(domainsList, labelLimit)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	return &wellKnownDomainsTracker{
		m: m,
	}, nil
}

func (wkd *wellKnownDomainsTracker) isKnown(q dns.Question) bool {
	wkd.mutex.Lock()
	defer wkd.mutex.Unlock()

	if _, exists := wkd.m[q.Name]; exists {
		switch q.Qtype {
		case dns.TypeA:
			wkd.m[q.Name].ACount++
		default:
			wkd.m[q.Name].OtherCount++
		}

		return true
	}

	return false
}

func (wkd *wellKnownDomainsTracker) rotateMap() (map[string]*histogramData, error) {

	newMap, err := newWellKnownDomainsMap([]string{"www.google.com.", "www.facebook.com."}, 9)
	if err != nil {
		return nil, err
	}

	// Swap the map in use so we can write parquet data outside of the write lock
	wkd.mutex.Lock()
	lastMap := wkd.m
	wkd.m = newMap
	wkd.mutex.Unlock()

	return lastMap, nil
}

// runFilter reads frames from the inputChannel, doing any modifications and
// then passes them on to a dnstap.Output. To gracefully stop
// runFilter() you need to close the dtf.stop channel.
func (dtf *dnstapFilter) runFilter(arrowPool *memory.GoAllocator, arrowSchema *arrow.Schema, dnsSessionRowBuilder *array.RecordBuilder) {
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

	// Channel used to feed the output writer, buffered so we do not block
	// filterLoop if writing is slow
	parquetWriterCh := make(chan arrow.Record, 100)

	// Channel used to feed the histogram writer, buffered so we do not block
	// filterLoop if writing is slow
	histogramWriterCh := make(chan map[string]*histogramData, 100)

	// Start the record writers in the background
	go parquetWriter(dtf, arrowSchema, parquetWriterCh)
	go histogramWriter(dtf, histogramWriterCh)

	// TODO: read real data
	wellKnownDomains := []string{"www.google.com.", "www.facebook.com."}

	wkdTracker, err := newWellKnownDomainsTracker(wellKnownDomains, labelLimit)
	if err != nil {
		dtf.log.Printf("unable to initialize wkdTracker")
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

			if wkdTracker.isKnown(msg.Question[0]) {
				dtf.log.Printf("skipping well known domain")
				continue
			}

			fmt.Println(wkdTracker.m["www.google.com."].ACount)

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

				parquetWriterCh <- record
			}

			hd, err := wkdTracker.rotateMap()
			if err != nil {
				dtf.log.Printf("unable to rotate histogram map: %s", err)
				continue
			}

			histogramWriterCh <- hd

		case <-dtf.stop:
			break filterLoop
		}
	}
	// We close the dnstap.Output so it has a chance to flush out its messages
	dtf.dnstapOutput.Close()
	// Signal main() that we are done and ready to exit
	close(dtf.done)
}

func parquetWriter(dtf *dnstapFilter, arrowSchema *arrow.Schema, ch chan arrow.Record) {
	for {
		record := <-ch
		err := writeParquet(dtf, arrowSchema, record)
		if err != nil {
			dtf.log.Printf(err.Error())
		}

	}
}

func histogramWriter(dtf *dnstapFilter, ch chan map[string]*histogramData) {
	for {
		lastMap := <-ch
		dtf.log.Printf("in histogramWriter")
		err := writeHistogramParquet(dtf, lastMap)
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

func writeParquet(dtf *dnstapFilter, arrowSchema *arrow.Schema, record arrow.Record) error {
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

func writeHistogramParquet(dtf *dnstapFilter, lastMap map[string]*histogramData) error {
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
		return err
	}

	for domain, hGram := range lastMap {
		fmt.Printf("%s: %#v\n", domain, *hGram)
		err = parquetWriter.Write(*hGram)
		if err != nil {
			return err
		}
	}

	err = parquetWriter.WriteStop()
	if err != nil {
		return err
	}

	return nil
}

// Anonymize IP address fields in a dnstap message
func (dtf *dnstapFilter) pseudonymizeDnstap(dt *dnstap.Dnstap) {
	dt.Message.QueryAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.QueryAddress))
	dt.Message.ResponseAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.ResponseAddress))
}
