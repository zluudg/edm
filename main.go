package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	"github.com/dnstapir/dtm/pkg/protocols"
	"github.com/eclipse/paho.golang/paho"
	lru "github.com/hashicorp/golang-lru/v2"
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

// Histogram struct implementing description at https://github.com/dnstapir/datasets/blob/main/HistogramReport.fbs
type histogramData struct {
	// label fields must be exported as we set them using reflection,
	// otherwise: "panic: reflect: reflect.Value.SetString using value obtained using unexported field"
	// Also store them as pointers so we can signal them being unset as
	// opposed to an empty string
	Label0     *string `parquet:"name=label0, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label1     *string `parquet:"name=label1, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label2     *string `parquet:"name=label2, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label3     *string `parquet:"name=label3, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label4     *string `parquet:"name=label4, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label5     *string `parquet:"name=label5, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label6     *string `parquet:"name=label6, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label7     *string `parquet:"name=label7, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label8     *string `parquet:"name=label8, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Label9     *string `parquet:"name=label9, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	ACount     int64   `parquet:"name=a_count, type=INT64, convertedtype=UINT_64"`
	AAAACount  int64   `parquet:"name=aaaa_count, type=INT64, convertedtype=UINT_64"`
	MXCount    int64   `parquet:"name=mx_count, type=INT64, convertedtype=UINT_64"`
	NSCount    int64   `parquet:"name=ns_count, type=INT64, convertedtype=UINT_64"`
	OtherCount int64   `parquet:"name=other_count, type=INT64, convertedtype=UINT_64"`
	NonINCount int64   `parquet:"name=non_in_count, type=INT64, convertedtype=UINT_64"`
	OKCount    int64   `parquet:"name=ok_count, type=INT64, convertedtype=UINT_64"`
	NXCount    int64   `parquet:"name=nx_count, type=INT64, convertedtype=UINT_64"`
	FailCount  int64   `parquet:"name=fail_count, type=INT64, convertedtype=UINT_64"`
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
	inputUnixSocketPath := flag.String("input-unix", "/var/lib/unbound/dnstap.sock", "create unix socket for reading dnstap")
	cryptoPanKey := flag.String("cryptopan-key", "", "override the secret used for Crypto-PAn pseudonymization")
	cryptoPanKeySalt := flag.String("cryptopan-key-salt", "dtm-kdf-salt-val", "the salt used for key derivation")
	dawgFile := flag.String("well-known-domains", "well-known-domains.dawg", "the dawg file used for filtering well-known domains")
	dataDir := flag.String("data-dir", "/var/lib/dtm", "directory where output data is written")
	mqttSigningKeyFile := flag.String("mqtt-signing-key-file", "dtm-mqtt-signer-key.pem", "ECSDSA key used for signing MQTT messages")
	mqttClientKeyFile := flag.String("mqtt-client-key-file", "dtm-mqtt-client-key.pem", "ECSDSA client key used for authenticating to MQTT bus")
	mqttClientCertFile := flag.String("mqtt-client-cert-file", "dtm-mqtt-client.pem", "ECSDSA client cert used for authenticating to MQTT bus")
	mqttServer := flag.String("mqtt-server", "127.0.0.1:8883", "MQTT server we will publish events to")
	mqttTopic := flag.String("mqtt-topic", "events/up/dtm/new_qname", "MQTT topic to publish events to")
	mqttClientID := flag.String("mqtt-client-id", "dtm-pub", "MQTT client id used for publishing events")
	mqttCAFile := flag.String("mqtt-ca", "mqtt-ca.crt", "CA cert used for validating MQTT TLS connection")
	mqttKeepAlive := flag.Int("mqtt-keepalive", 30, "Keepalive interval fo MQTT connection")
	mqttCleanStart := flag.Bool("mqtt-clean-start", true, "Control if a new MQTT session is created when connecting")
	qnameSeenEntries := flag.Int("qname-seen-entries", 10000000, "Number of 'seen' qnames stored in LRU cache, need to be changed based on RAM")
	flag.Parse()

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

	mqttSigningKeyBytes, err := os.ReadFile(*mqttSigningKeyFile)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to read 'mqtt-signing-key-file': %s", err))
		os.Exit(1)
	}

	pemBlock, _ := pem.Decode(mqttSigningKeyBytes)
	if pemBlock == nil || pemBlock.Type != "EC PRIVATE KEY" {
		slog.Error("failed to decode PEM block containing ECDSA private key")
		os.Exit(1)
	}
	mqttSigningKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to parse key material from 'mqtt-signing-key-file': %s", err))
		os.Exit(1)
	}

	// Setup CA cert for validating the MQTT connection
	caCert, err := os.ReadFile(*mqttCAFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(caCert))
	if !ok {
		slog.Error(fmt.Sprintf("failed to append certs from pem: %s", err))
		os.Exit(1)
	}

	// Setup client cert/key for mTLS authentication
	clientCert, err := tls.LoadX509KeyPair(*mqttClientCertFile, *mqttClientKeyFile)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to load x509 mqtt client cert: %s", err))
		os.Exit(1)
	}

	mqttPub, err := newMQTTPublisher(caCertPool, *mqttServer, *mqttTopic, *mqttClientID, clientCert, mqttSigningKey)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to create MQTT publisher: %s", err))
		os.Exit(1)
	}

	err = mqttPub.connect(uint16(*mqttKeepAlive), *mqttClientID, *mqttCleanStart)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to connect to MQTT server: %s", err))
		os.Exit(1)
	}

	// Logger used for the different background workers, logged to stderr
	// so stdout only includes dnstap data if anything.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// This makes any calls to the standard "log" package to use slog as
	// well
	slog.SetDefault(logger)

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

	// Create an instance of the minimiser
	dtm, err := newDnstapMinimiser(log.Default(), aesKey, *debug)
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
		ExplicitThreshold: 0,
		SparseEnabled:     true,
	})
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	// We need to keep track of domains that are not on the well-known
	// domain list yet we have seen since we started. To limit the
	// possibility of unbounded memory usage we use a LRU cache instead of
	// something simpler like a map. This does mean that we can potentially
	// re-send a new_qname event if the LRU is full.
	seenQnameLRU, _ := lru.New[string, struct{}](*qnameSeenEntries)

	// Exit gracefully on SIGINT or SIGTERM
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
		<-sigs

		// We received a signal, tell runMinimiser() to stop
		close(dtm.stop)
	}()

	dnsSessionRowBuilder := array.NewRecordBuilder(arrowPool, dnsSessionRowSchema)
	defer dnsSessionRowBuilder.Release()

	// Start minimiser
	go dtm.runMinimiser(arrowPool, dnsSessionRowSchema, dnsSessionRowBuilder, *dawgFile, *dataDir, mqttPub, seenQnameLRU)

	// Start dnstap.Input
	go dti.ReadInto(dtm.inputChannel)

	// Wait here until runMinimiser() is done
	<-dtm.done

	// Gracefully disconnect from MQTT bus
	if mqttPub.pahoClient != nil {
		d := &paho.Disconnect{ReasonCode: 0}
		err := mqttPub.pahoClient.Disconnect(d)
		if err != nil {
			slog.Error(fmt.Sprintf("unable to disconnect from MQTT server: %s", err))
			os.Exit(1)
		}
	}

}

type dtmConfig struct {
	CryptoPanKey string `toml:"cryptopan-key"`
}

type dnstapMinimiser struct {
	inputChannel chan []byte          // the channel expected to be passed to dnstap ReadInto()
	log          dnstap.Logger        // any information logging is sent here
	cryptopan    *cryptopan.Cryptopan // used for pseudonymizing IP addresses
	stop         chan struct{}        // close this channel to gracefully stop runMinimiser()
	done         chan struct{}        // block on this channel to make sure output is flushed before exiting
	debug        bool                 // if we should print debug messages during operation
}

func newDnstapMinimiser(logger dnstap.Logger, cryptoPanKey []byte, debug bool) (*dnstapMinimiser, error) {
	cpn, err := cryptopan.New(cryptoPanKey)
	if err != nil {
		return nil, fmt.Errorf("newDnstapMinimiser: %w", err)
	}
	dtm := &dnstapMinimiser{}
	dtm.cryptopan = cpn
	dtm.stop = make(chan struct{})
	dtm.done = make(chan struct{})
	// Size 32 matches unexported "const outputChannelSize = 32" in
	// https://github.com/dnstap/golang-dnstap/blob/master/dnstap.go
	dtm.inputChannel = make(chan []byte, 32)
	dtm.log = logger
	dtm.debug = debug

	return dtm, nil
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
		return nil, fmt.Errorf("newWellKnownDomainsTracker: %w", err)
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

func (wkd *wellKnownDomainsTracker) isKnown(ipBytes []byte, msg *dns.Msg) bool {

	wkd.mutex.Lock()
	defer wkd.mutex.Unlock()

	index := wkd.dawgFinder.IndexOf(msg.Question[0].Name)

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

	// Counters based on header
	switch msg.Rcode {
	case dns.RcodeSuccess:
		wkd.m[index].OKCount++
	case dns.RcodeNXRrset:
		wkd.m[index].NXCount++
	case dns.RcodeServerFailure:
		wkd.m[index].FailCount++
	}

	// Counters based on question class and type
	if msg.Question[0].Qclass == dns.ClassINET {
		switch msg.Question[0].Qtype {
		case dns.TypeA:
			wkd.m[index].ACount++
		case dns.TypeAAAA:
			wkd.m[index].AAAACount++
		case dns.TypeMX:
			wkd.m[index].MXCount++
		case dns.TypeNS:
			wkd.m[index].NSCount++
		default:
			wkd.m[index].OtherCount++
		}
	} else {
		wkd.m[index].NonINCount++
	}

	return true
}

func (wkd *wellKnownDomainsTracker) rotateTracker(dawgFile string) (*wellKnownDomainsData, error) {

	dawgFinder, err := dawg.Load(dawgFile)
	if err != nil {
		return nil, fmt.Errorf("rotateTracker: dawg.Load(): %w", err)
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

// runMinimiser reads frames from the inputChannel, doing any modifications and
// then passes them on to a dnstap.Output. To gracefully stop
// runMinimiser() you need to close the dtm.stop channel.
func (dtm *dnstapMinimiser) runMinimiser(arrowPool *memory.GoAllocator, arrowSchema *arrow.Schema, dnsSessionRowBuilder *array.RecordBuilder, dawgFile string, dataDir string, mqttPub mqttPublisher, seenQnameLRU *lru.Cache[string, struct{}]) {
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
	// minimiserLoop if writing is slow
	sessionWriterCh := make(chan arrow.Record, 100)

	// Channel used to feed the histogram writer, buffered so we do not block
	// minimiserLoop if writing is slow
	histogramWriterCh := make(chan *wellKnownDomainsData, 100)

	// Start the record writers in the background
	go sessionWriter(dtm, arrowSchema, sessionWriterCh, dataDir)
	go histogramWriter(dtm, histogramWriterCh, labelLimit, dataDir)

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

minimiserLoop:
	for {
		select {
		case frame := <-dtm.inputChannel:
			if err := proto.Unmarshal(frame, dt); err != nil {
				dtm.log.Printf("dnstapMinimiser.runMinimiser: proto.Unmarshal() failed: %s, returning", err)
				break minimiserLoop
			}

			isQuery := strings.HasSuffix(dnstap.Message_Type_name[int32(*dt.Message.Type)], "_QUERY")

			// For now we only care about response type dnstap packets
			if isQuery {
				continue
			}

			if dtm.debug {
				dtm.log.Printf("dnstapMinimiser.runMinimiser: modifying dnstap message")
			}
			dtm.pseudonymizeDnstap(dt)

			msg, timestamp := parsePacket(dt, isQuery)

			// For cases where we were unable to unpack the DNS message we
			// skip parsing.
			if msg == nil || len(msg.Question) == 0 {
				dtm.log.Printf("unable to parse dnstap message, or no question section, skipping parsing")
				continue
			}

			if _, ok := dns.IsDomainName(msg.Question[0].Name); !ok {
				dtm.log.Printf("unable to parse question name, skipping parsing")
				continue
			}

			// We pass on the client address for cardinality
			// measurements.
			if wkdTracker.isKnown(dt.Message.QueryAddress, msg) {
				dtm.log.Printf("skipping well-known domain %s", msg.Question[0].Name)
				continue
			}

			// Check if we have already seen this qname since we started.
			//
			// NOTE: This looks like it might be a race (calling
			// Get() followed by separate Add()) but since we want
			// to keep often looked-up names in the cache we need to
			// use Get() for updating recent-ness, and there is no
			// GetOrAdd() method available. However, it should be
			// safe for multiple threads to call Add() as this will
			// only move an already added entry to the front of the
			// eviction list which should be OK.
			if _, qnameSeen := seenQnameLRU.Get(msg.Question[0].Name); !qnameSeen {
				seenQnameLRU.Add(msg.Question[0].Name, struct{}{})
				dtm.log.Printf("sending new_qname")
				// TODO(patlu): send mqtt messages outside of the hot path
				// Create new_qname structure
				newQname := protocols.NewQnameEvent(msg, timestamp)

				newQnameJSON, err := json.Marshal(newQname)
				if err != nil {
					dtm.log.Printf("unable to create json for new_qname event: %w", err)
					continue
				}

				// This is an unkown domain name, message the bus
				err = mqttPub.publishMQTT(newQnameJSON)
				if err != nil {
					dtm.log.Printf("unable to publish new_qname event: %w", err)
					continue
				}
			} else {
				dtm.log.Printf("already seen domain name, not sending new_qname")
			}

			setLabels(dtm, msg, labelLimit, labelSlice)

			setTimestamp(dtm, isQuery, timestamp, queryTime, responseTime)

			// Since we have set fields in the arrow data at this
			// point we have things to write out
			arrow_updated = true
		case <-ticker.C:
			if arrow_updated {
				record := dnsSessionRowBuilder.NewRecord()
				// We have created a record and therefore the recordbuilder is reset
				arrow_updated = false

				sessionWriterCh <- record
			}

			prevWKD, err := wkdTracker.rotateTracker(dawgFile)
			if err != nil {
				dtm.log.Printf("unable to rotate histogram map: %s", err)
				continue
			}

			// Only write out parquet file if there is something to write
			if len(prevWKD.m) > 0 {
				histogramWriterCh <- prevWKD
			}

		case <-dtm.stop:
			break minimiserLoop
		}
	}
	// Signal main() that we are done and ready to exit
	close(dtm.done)
}

func sessionWriter(dtm *dnstapMinimiser, arrowSchema *arrow.Schema, ch chan arrow.Record, dataDir string) {
	for {
		record := <-ch
		err := writeSession(dtm, arrowSchema, record, dataDir)
		if err != nil {
			dtm.log.Printf(err.Error())
		}

	}
}

func histogramWriter(dtm *dnstapMinimiser, ch chan *wellKnownDomainsData, labelLimit int, dataDir string) {
	for {
		prevWellKnownDomainsData := <-ch
		dtm.log.Printf("in histogramWriter")
		err := writeHistogramParquet(dtm, prevWellKnownDomainsData, labelLimit, dataDir)
		if err != nil {
			dtm.log.Printf(err.Error())
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

func setLabels(dtm *dnstapMinimiser, msg *dns.Msg, labelLimit int, labelSlice []*array.StringBuilder) {
	labels := dns.SplitDomainName(msg.Question[0].Name)

	// labels is nil if this is the root domain (.)
	if labels == nil {
		dtm.log.Printf("setting all labels to null")
		for _, arrowLabel := range labelSlice {
			arrowLabel.AppendNull()
		}
	} else {
		reverseLabels := reverseLabelsBounded(labels, labelLimit)
		for i, label := range reverseLabels {
			dtm.log.Printf("setting label%d to %s", i, label)
			labelSlice[i].Append(label)
		}

		// Fill out remaining labels with null if needed
		if len(reverseLabels) < labelLimit {
			for i := len(reverseLabels); i < labelLimit; i++ {
				dtm.log.Printf("setting remaining label%d to null\n", i)
				labelSlice[i].AppendNull()
			}
		}
	}
}

func setTimestamp(dtm *dnstapMinimiser, isQuery bool, timestamp time.Time, queryTime *array.TimestampBuilder, responseTime *array.TimestampBuilder) {
	if isQuery {
		responseTime.AppendNull()
		arrowTimeQuery, err := arrow.TimestampFromTime(timestamp, arrow.Nanosecond)
		if err != nil {
			dtm.log.Printf("unable to parse query_time: %s, appending null", err)
			queryTime.AppendNull()
		} else {
			queryTime.Append(arrowTimeQuery)
		}
	} else {
		queryTime.AppendNull()
		arrowTimeResponse, err := arrow.TimestampFromTime(timestamp, arrow.Nanosecond)
		if err != nil {
			dtm.log.Printf("unable to parse response_time: %s, appending null", err)
			responseTime.AppendNull()
		} else {
			responseTime.Append(arrowTimeResponse)
		}
	}
}

func writeSession(dtm *dnstapMinimiser, arrowSchema *arrow.Schema, record arrow.Record, dataDir string) error {
	defer record.Release()

	// Write session file to a sessions dir where it will be read by clickhouse
	sessionsDir := filepath.Join(dataDir, "parquet", "sessions")

	absoluteTmpFileName, absoluteFileName := buildParquetFilenames(sessionsDir, "dns_session_block")

	absoluteTmpFileName = filepath.Clean(absoluteTmpFileName) // Make gosec happy
	dtm.log.Printf("writing out session parquet file %s", absoluteTmpFileName)
	outFile, err := os.Create(absoluteTmpFileName)
	if err != nil {
		return fmt.Errorf("writeSession: unable to open session file: %w", err)
	}
	fileOpen := true
	defer func() {
		// Closing a *os.File twice returns an error, so only do it if
		// we have not already tried to close it.
		if fileOpen {
			err := outFile.Close()
			if err != nil {
				dtm.log.Printf("writeSession: unable to do deferred close of outFile: %w", err)
			}
		}
	}()

	parquetWriter, err := pqarrow.NewFileWriter(arrowSchema, outFile, nil, pqarrow.DefaultWriterProps())
	if err != nil {
		return fmt.Errorf("writeSession: unable to create parquet writer: %w", err)
	}
	defer func() {
		err := parquetWriter.Close()
		// Closing the parquetWriter automatically closes the underlying file
		fileOpen = false
		if err != nil {
			dtm.log.Printf("writeSession: unable to do deferred close of parquetWriter: %w", err)
		}
	}()

	err = parquetWriter.Write(record)
	if err != nil {
		return fmt.Errorf("writeSession: unable to write parquet file: %w", err)
	}

	err = parquetWriter.Close()
	// Closing the parquetWriter automatically closes the underlying file
	// so lets not try do it again in the deferred func when we return. At
	// the same time it is documented to be a no-op to call Close() on the
	// parquetWriter multiple times, so just let that one be called again.
	fileOpen = false
	if err != nil {
		return fmt.Errorf("writeSession: unable to close parquet file: %w", err)
	}

	jsonBytes, err := record.MarshalJSON()
	if err != nil {
		return fmt.Errorf("writeSession: error marshalling json fron rec: %w", err)
	}
	fmt.Println(string(jsonBytes))

	dtm.log.Printf("renaming session file '%s' -> '%s'", absoluteTmpFileName, absoluteFileName)
	err = os.Rename(absoluteTmpFileName, absoluteFileName)
	if err != nil {
		return fmt.Errorf("writeSession: unable to rename output file: %w", err)
	}

	return nil
}

func buildParquetFilenames(baseDir string, baseName string) (string, string) {
	// Use timestamp for files, replace ":" with "-" to not have to escape
	// characters in the shell, e.g: 2009-11-10T23-00-00Z
	datetime := strings.ReplaceAll(time.Now().UTC().Format(time.RFC3339), ":", "-")
	fileName := baseName + "-" + datetime + ".parquet"

	// Write output to a .tmp file so we can atomically rename it to the real
	// name when the file has been written in full
	tmpFileName := fileName + ".tmp"

	absoluteFileName := filepath.Join(baseDir, fileName)
	absoluteTmpFileName := filepath.Join(baseDir, tmpFileName)

	return absoluteTmpFileName, absoluteFileName
}

func writeHistogramParquet(dtm *dnstapMinimiser, prevWellKnownDomainsData *wellKnownDomainsData, labelLimit int, dataDir string) error {
	dtm.log.Printf("in writeHistogramParquet")

	// Write histogram file to an outbox dir where it will get picked up by
	// the histogram sender
	outboxDir := filepath.Join(dataDir, "parquet", "histograms", "outbox")

	absoluteTmpFileName, absoluteFileName := buildParquetFilenames(outboxDir, "dns_histogram")

	dtm.log.Printf("writing out histogram file %s", absoluteTmpFileName)

	absoluteTmpFileName = filepath.Clean(absoluteTmpFileName)
	outFile, err := os.Create(absoluteTmpFileName)
	if err != nil {
		return fmt.Errorf("writeHistogramParquet: unable to open histogram file: %w", err)
	}
	fileOpen := true
	defer func() {
		// Closing a *os.File twice returns an error, so only do it if
		// we have not already tried to close it.
		if fileOpen {
			err := outFile.Close()
			if err != nil {
				dtm.log.Printf("writeHistogramParquet: unable to do deferred close of histogram outFile: %w", err)
			}
		}
	}()

	parquetWriter, err := writer.NewParquetWriterFromWriter(outFile, new(histogramData), 4)
	if err != nil {
		return fmt.Errorf("writeHistogramParquet: unable to create parquet writer: %w", err)
	}

	for index, hGramData := range prevWellKnownDomainsData.m {
		domain, err := prevWellKnownDomainsData.dawgFinder.AtIndex(index)
		if err != nil {
			return fmt.Errorf("writeHistogramParquet: unable to find DAWG index %d: %w", index, err)
		}
		fmt.Printf("%s: %#v\n", domain, *hGramData)

		labels := dns.SplitDomainName(domain)

		// Setting the labels now when we are out of the hot path.
		setHistogramLabels(labels, labelLimit, hGramData)

		dtm.log.Printf("ipv4 cardinality: %d", hGramData.v4ClientHLL.Cardinality())
		dtm.log.Printf("ipv6 cardinality: %d", hGramData.v6ClientHLL.Cardinality())

		// Write out the bytes from our hll data structures
		hGramData.V4ClientCountHLLBytes = hGramData.v4ClientHLL.ToBytes()
		hGramData.V6ClientCountHLLBytes = hGramData.v6ClientHLL.ToBytes()

		err = parquetWriter.Write(hGramData)
		if err != nil {
			return fmt.Errorf("writeHistogramParquet: unable to call Write() on parquet writer: %w", err)
		}
	}

	err = parquetWriter.WriteStop()
	if err != nil {
		return fmt.Errorf("writeHistogramParquet: unable to call WriteStop() on parquet writer: %w", err)
	}

	// We need to close the file before renaming it
	err = outFile.Close()
	// at this point we do not want the defer to close the file for us when returning
	fileOpen = false
	if err != nil {
		return fmt.Errorf("writeHistogramParquet: unable to call WriteStop() on parquet writer: %w", err)
	}

	// Atomically rename the file to its real name so it can be picked up by the histogram sender
	dtm.log.Printf("renaming histogram file '%s' -> '%s'", absoluteTmpFileName, absoluteFileName)
	err = os.Rename(absoluteTmpFileName, absoluteFileName)
	if err != nil {
		return fmt.Errorf("writeHistogramParquet: unable to rename output file: %w", err)
	}

	return nil
}

// Pseudonymize IP address fields in a dnstap message
func (dtm *dnstapMinimiser) pseudonymizeDnstap(dt *dnstap.Dnstap) {
	dt.Message.QueryAddress = dtm.cryptopan.Anonymize(net.IP(dt.Message.QueryAddress))
	dt.Message.ResponseAddress = dtm.cryptopan.Anonymize(net.IP(dt.Message.ResponseAddress))
}

// Send histogram data via signed HTTP message to aggregate-receiver (https://github.com/dnstapir/aggregate-receiver)
func sendHistogramParquet(aggrecURL url.URL, baseDir string, fileName string, privKey *ecdsa.PrivateKey, caCertPool *x509.CertPool, clientCert tls.Certificate) error {

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

	// Set some timouts to protect from hanging connections as well as
	// configuring mTLS.
	httpClient := http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{clientCert},
				MinVersion:   tls.VersionTLS13,
			},
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
