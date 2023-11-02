package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"hash"
	"log"
	"log/slog"
	"math/big"
	"net"
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
	mqttCAFile := flag.String("mqtt-ca-file", "", "CA cert used for validating MQTT TLS connection, defaults to using OS CA certs")
	mqttKeepAlive := flag.Int("mqtt-keepalive", 30, "Keepalive interval fo MQTT connection")
	mqttCleanStart := flag.Bool("mqtt-clean-start", true, "Control if a new MQTT session is created when connecting")
	qnameSeenEntries := flag.Int("qname-seen-entries", 10000000, "Number of 'seen' qnames stored in LRU cache, need to be changed based on RAM")
	newQnameBuffer := flag.Int("newqname-buffer", 1000, "Number of slots in new_qname publisher channel, if this is filled up we skip new_qname events")
	httpCAFile := flag.String("http-ca-file", "", "CA cert used for validating aggregate-receiver connection, defaults to using OS CA certs")
	httpSigningKeyFile := flag.String("http-signing-key-file", "dtm-http-signer-key.pem", "ECSDSA key used for signing HTTP messages to aggregate-receiver")
	httpSigningKeyID := flag.String("http-signing-key-id", "key1", "ID for the HTTP signing key")
	httpClientKeyFile := flag.String("http-client-key-file", "dtm-http-client-key.pem", "ECSDSA client key used for authenticating to aggregate-receiver")
	httpClientCertFile := flag.String("http-client-cert-file", "dtm-http-client.pem", "ECSDSA client cert used for authenticating to aggregate-receiver")
	httpURLString := flag.String("http-url", "https://127.0.0.1:8443", "Service we will POST aggregates to")
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

	httpURL, err := url.Parse(*httpURLString)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to parse 'aggrec-url' setting: %s", err))
		os.Exit(1)
	}

	mqttSigningKey, err := ecdsaPrivateKeyFromFile(*mqttSigningKeyFile)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to parse key material from 'mqtt-signing-key-file': %s", err))
		os.Exit(1)
	}

	httpSigningKey, err := ecdsaPrivateKeyFromFile(*httpSigningKeyFile)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to parse key material from 'http-signing-key-file': %s", err))
		os.Exit(1)
	}

	// Leaving these nil will use the OS default CA certs
	var mqttCACertPool *x509.CertPool
	var httpCACertPool *x509.CertPool

	if *mqttCAFile != "" {
		// Setup CA cert for validating the MQTT connection
		mqttCACertPool, err = certPoolFromFile(*mqttCAFile)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to create CA cert pool for '-mqtt-ca-file': %s", err))
			os.Exit(1)
		}
	}

	// Setup client cert/key for mTLS authentication
	mqttClientCert, err := tls.LoadX509KeyPair(*mqttClientCertFile, *mqttClientKeyFile)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to load x509 mqtt client cert: %s", err))
		os.Exit(1)
	}

	if *httpCAFile != "" {
		// Setup CA cert for validating the aggregate-receiver connection
		httpCACertPool, err = certPoolFromFile(*mqttCAFile)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to create CA cert pool for '-http-ca-file': %s", err))
			os.Exit(1)
		}
	}

	httpClientCert, err := tls.LoadX509KeyPair(*httpClientCertFile, *httpClientKeyFile)
	if err != nil {
		slog.Error(fmt.Sprintf("unable to load x509 HTTP client cert: %s", err))
		os.Exit(1)
	}

	mqttPub, err := newMQTTPublisher(mqttCACertPool, *mqttServer, *mqttTopic, *mqttClientID, mqttClientCert, mqttSigningKey)
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

	aggregSender := newAggregateSender(dtm, httpURL, *httpSigningKeyID, httpSigningKey, httpCACertPool, httpClientCert)

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
	go dtm.runMinimiser(arrowPool, dnsSessionRowSchema, dnsSessionRowBuilder, *dawgFile, *dataDir, mqttPub, seenQnameLRU, *newQnameBuffer, aggregSender)

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
func (dtm *dnstapMinimiser) runMinimiser(arrowPool *memory.GoAllocator, arrowSchema *arrow.Schema, dnsSessionRowBuilder *array.RecordBuilder, dawgFile string, dataDir string, mqttPub mqttPublisher, seenQnameLRU *lru.Cache[string, struct{}], newQnameBuffer int, aggSender aggregateSender) {
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

	// Server ID
	serverID := dnsSessionRowBuilder.Field(12).(*array.BinaryBuilder)
	defer serverID.Release()

	// Source IPv4
	sourceIPv4Address := dnsSessionRowBuilder.Field(13).(*array.Uint32Builder)
	defer sourceIPv4Address.Release()

	// Destination IPv4
	destIPv4Address := dnsSessionRowBuilder.Field(14).(*array.Uint32Builder)
	defer destIPv4Address.Release()

	// Source IPv6 split into network:host uint64 parts
	sourceIPv6Network := dnsSessionRowBuilder.Field(15).(*array.Uint64Builder)
	defer sourceIPv6Network.Release()
	sourceIPv6Host := dnsSessionRowBuilder.Field(16).(*array.Uint64Builder)
	defer sourceIPv6Host.Release()

	// Dest IPv6 split into network:host uint64 parts
	destIPv6Network := dnsSessionRowBuilder.Field(17).(*array.Uint64Builder)
	defer destIPv6Network.Release()
	destIPv6Host := dnsSessionRowBuilder.Field(18).(*array.Uint64Builder)
	defer destIPv6Host.Release()

	// Source port
	sourcePort := dnsSessionRowBuilder.Field(19).(*array.Uint16Builder)
	defer sourcePort.Release()

	// Dest port
	destPort := dnsSessionRowBuilder.Field(20).(*array.Uint16Builder)
	defer destPort.Release()

	// DNS protocol (UDP, TCP, DOT, DOH...)
	dnsProtocol := dnsSessionRowBuilder.Field(21).(*array.Uint8Builder)
	defer dnsProtocol.Release()

	// Query header struct
	qHeader := dnsSessionRowBuilder.Field(22).(*array.StructBuilder)
	defer qHeader.Release()
	qHeaderID := qHeader.FieldBuilder(0).(*array.Uint16Builder)
	defer qHeaderID.Release()

	// Query header counters, - set only if not [1,0,0,0]
	qCounters := dnsSessionRowBuilder.Field(23).(*array.StructBuilder)
	defer qCounters.Release()
	qCounterQD := qCounters.FieldBuilder(0).(*array.Uint16Builder)
	defer qCounterQD.Release()
	qCounterAN := qCounters.FieldBuilder(1).(*array.Uint16Builder)
	defer qCounterAN.Release()
	qCounterNS := qCounters.FieldBuilder(2).(*array.Uint16Builder)
	defer qCounterNS.Release()
	qCounterAR := qCounters.FieldBuilder(3).(*array.Uint16Builder)
	defer qCounterAR.Release()

	// Response header struct
	rHeader := dnsSessionRowBuilder.Field(24).(*array.StructBuilder)
	defer rHeader.Release()
	rHeaderID := rHeader.FieldBuilder(0).(*array.Uint16Builder)
	defer rHeaderID.Release()

	// Response header counters, - set only if not [1,0,0,0]
	rCounters := dnsSessionRowBuilder.Field(25).(*array.StructBuilder)
	defer rCounters.Release()
	rCounterQD := rCounters.FieldBuilder(0).(*array.Uint16Builder)
	defer rCounterQD.Release()
	rCounterAN := rCounters.FieldBuilder(1).(*array.Uint16Builder)
	defer rCounterAN.Release()
	rCounterNS := rCounters.FieldBuilder(2).(*array.Uint16Builder)
	defer rCounterNS.Release()
	rCounterAR := rCounters.FieldBuilder(3).(*array.Uint16Builder)
	defer rCounterAR.Release()

	// Store labels in a slice so we can reference them by index
	labelSlice := []*array.StringBuilder{label0, label1, label2, label3, label4, label5, label6, label7, label8, label9}
	labelLimit := len(labelSlice)

	// Keep track of if we have recorded any dnstap packets in arrow data
	var arrow_updated bool

	// Setup channels for feeding writers and data senders that should do
	// their work outside the main minimiser loop. They are buffered to
	// to not block the loop if writing/sending data is slow.
	// NOTE: Remember to close all of these channels at the end of the
	// minimiser loop, otherwise the program can hang on shutdown.
	sessionWriterCh := make(chan arrow.Record, 100)
	histogramWriterCh := make(chan *wellKnownDomainsData, 100)
	// This channel is only used for stopping the goroutine, so no buffer needed
	histogramSenderCloserCh := make(chan struct{})
	newQnamePublisherCh := make(chan *protocols.EventsMqttMessageNewQnameJson, newQnameBuffer)

	var wg sync.WaitGroup

	// Write histogram file to an outbox dir where it will get picked up by
	// the histogram sender. Upon being sent it will be moved to the sent dir.
	outboxDir := filepath.Join(dataDir, "parquet", "histograms", "outbox")
	sentDir := filepath.Join(dataDir, "parquet", "histograms", "sent")

	// Make sure the directories exist
	err := os.MkdirAll(outboxDir, 0750)
	if err != nil {
		slog.Error(fmt.Sprintf("runMinimiser: unable to create outbox dir: %s", err))
		os.Exit(1)
	}
	err = os.MkdirAll(sentDir, 0750)
	if err != nil {
		slog.Error(fmt.Sprintf("runMinimiser: unable to create sent dir: %s", err))
		os.Exit(1)
	}

	// Start record writers and data senders in the background
	wg.Add(1)
	go sessionWriter(dtm, arrowSchema, sessionWriterCh, dataDir, &wg)
	wg.Add(1)
	go histogramWriter(dtm, histogramWriterCh, labelLimit, outboxDir, &wg)
	wg.Add(1)
	go histogramSender(dtm, histogramSenderCloserCh, outboxDir, sentDir, aggSender, &wg)
	wg.Add(1)
	go newQnamePublisher(dtm, newQnamePublisherCh, mqttPub, &wg)

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

			fmt.Printf("%#v\n", dt.Message)

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
				newQname := protocols.NewQnameEvent(msg, timestamp)

				// If the queue is full we skip sending new_qname events on the bus
				select {
				case newQnamePublisherCh <- &newQname:
				default:
					dtm.log.Printf("new_qname publisher channel is full, skipping event")
				}

			}

			// Set arrow fields
			setLabels(dtm, msg, labelLimit, labelSlice)
			setTimestamp(dtm, isQuery, timestamp, queryTime, responseTime)
			setServerID(dt, serverID)
			switch *dt.Message.SocketFamily {
			case dnstap.SocketFamily_INET:
				setIPv4(dtm, dt.Message.QueryAddress, sourceIPv4Address)
				setIPv4(dtm, dt.Message.ResponseAddress, destIPv4Address)
				sourceIPv6Network.AppendNull()
				sourceIPv6Host.AppendNull()
				destIPv6Network.AppendNull()
				destIPv6Host.AppendNull()
			case dnstap.SocketFamily_INET6:
				sourceIPv4Address.AppendNull()
				destIPv4Address.AppendNull()
				setIPv6(dtm, dt.Message.QueryAddress, sourceIPv6Network, sourceIPv6Host)
				setIPv6(dtm, dt.Message.QueryAddress, destIPv6Network, destIPv6Host)
			default:
				dtm.log.Printf("packet is neither INET or INET6")
				sourceIPv4Address.AppendNull()
				destIPv4Address.AppendNull()
				sourceIPv6Network.AppendNull()
				sourceIPv6Host.AppendNull()
				destIPv6Network.AppendNull()
				destIPv6Host.AppendNull()
			}
			setPort(*dt.Message.QueryPort, sourcePort)
			setPort(*dt.Message.ResponsePort, destPort)
			setDNSProtocol(*dt.Message.SocketProtocol, dnsProtocol)
			if isQuery {
				rHeader.AppendNull()
				rCounters.AppendNull()
				setHeader(msg, qHeader, qHeaderID)
				setCounters(msg, qCounters, qCounterQD, qCounterAN, qCounterNS, qCounterAR)
			} else {
				qHeader.AppendNull()
				qCounters.AppendNull()
				setHeader(msg, rHeader, rHeaderID)
				setCounters(msg, rCounters, rCounterQD, rCounterAN, rCounterNS, rCounterAR)
			}

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
			// Make sure writers have completed their work
			close(sessionWriterCh)
			close(histogramWriterCh)
			close(histogramSenderCloserCh)
			close(newQnamePublisherCh)
			wg.Wait()

			break minimiserLoop
		}
	}
	// Signal main() that we are done and ready to exit
	close(dtm.done)
}

func sessionWriter(dtm *dnstapMinimiser, arrowSchema *arrow.Schema, ch chan arrow.Record, dataDir string, wg *sync.WaitGroup) {
	defer wg.Done()
	for record := range ch {
		err := writeSession(dtm, arrowSchema, record, dataDir)
		if err != nil {
			dtm.log.Printf(err.Error())
		}
	}

	dtm.log.Printf("sessionWriter: exiting loop")
}

func histogramWriter(dtm *dnstapMinimiser, ch chan *wellKnownDomainsData, labelLimit int, outboxDir string, wg *sync.WaitGroup) {
	defer wg.Done()
	for prevWellKnownDomainsData := range ch {
		dtm.log.Printf("in histogramWriter")
		err := writeHistogramParquet(dtm, prevWellKnownDomainsData, labelLimit, outboxDir)
		if err != nil {
			dtm.log.Printf(err.Error())
		}

	}
	dtm.log.Printf("histogramWriter: exiting loop")
}

func histogramSender(dtm *dnstapMinimiser, closerCh chan struct{}, outboxDir string, sentDir string, aggSender aggregateSender, wg *sync.WaitGroup) {
	defer wg.Done()

	// We will scan the outbox directory each tick for histogram parquet
	// files to send
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

timerLoop:
	for {
		select {
		case <-ticker.C:
			dirEntries, err := os.ReadDir(outboxDir)
			if err != nil {
				dtm.log.Printf("histogramSender: unable to read outbox dir: %w", err)
				continue
			}
			for _, dirEntry := range dirEntries {
				if dirEntry.IsDir() {
					continue
				}
				if strings.HasPrefix(dirEntry.Name(), "dns_histogram-") && strings.HasSuffix(dirEntry.Name(), ".parquet") {
					absPath := filepath.Join(outboxDir, dirEntry.Name())
					absPathSent := filepath.Join(sentDir, dirEntry.Name())
					err := aggSender.send(absPath)
					if err != nil {
						dtm.log.Printf("histogramSender: unable to send histogram file: %s", err)
					}
					err = os.Rename(absPath, absPathSent)
					if err != nil {
						dtm.log.Printf("histogramSender: unable to rename sent histogram file: %s", err)
					}
				}
			}
		case <-closerCh:
			// If this channel is closed it is time to exit
			break timerLoop
		}
	}
	dtm.log.Printf("histogramSender: exiting loop")
}

func newQnamePublisher(dtm *dnstapMinimiser, ch chan *protocols.EventsMqttMessageNewQnameJson, mqttPub mqttPublisher, wg *sync.WaitGroup) {
	defer wg.Done()
	for newQname := range ch {
		newQnameJSON, err := json.Marshal(newQname)
		if err != nil {
			dtm.log.Printf("unable to create json for new_qname event: %w", err)
			continue
		}

		err = mqttPub.publishMQTT(newQnameJSON)
		if err != nil {
			dtm.log.Printf("unable to publish new_qname event: %w", err)
			continue
		}
	}
	dtm.log.Printf("newQnamePublisher: exiting loop")
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

func setLabels(dtm *dnstapMinimiser, msg *dns.Msg, labelLimit int, labelBuilderSlice []*array.StringBuilder) {
	labels := dns.SplitDomainName(msg.Question[0].Name)

	// labels is nil if this is the root domain (.)
	if labels == nil {
		dtm.log.Printf("setting all labels to null")
		for _, arrowLabelBuilder := range labelBuilderSlice {
			arrowLabelBuilder.AppendNull()
		}
	} else {
		reverseLabels := reverseLabelsBounded(labels, labelLimit)
		for i, label := range reverseLabels {
			dtm.log.Printf("setting label%d to %s", i, label)
			labelBuilderSlice[i].Append(label)
		}

		// Fill out remaining labels with null if needed
		if len(reverseLabels) < labelLimit {
			for i := len(reverseLabels); i < labelLimit; i++ {
				dtm.log.Printf("setting remaining label%d to null\n", i)
				labelBuilderSlice[i].AppendNull()
			}
		}
	}
}

func setTimestamp(dtm *dnstapMinimiser, isQuery bool, timestamp time.Time, queryTimeBuilder *array.TimestampBuilder, responseTimeBuilder *array.TimestampBuilder) {
	if isQuery {
		responseTimeBuilder.AppendNull()
		arrowTimeQuery, err := arrow.TimestampFromTime(timestamp, arrow.Nanosecond)
		if err != nil {
			dtm.log.Printf("unable to parse query_time: %s, appending null", err)
			queryTimeBuilder.AppendNull()
		} else {
			queryTimeBuilder.Append(arrowTimeQuery)
		}
	} else {
		queryTimeBuilder.AppendNull()
		arrowTimeResponse, err := arrow.TimestampFromTime(timestamp, arrow.Nanosecond)
		if err != nil {
			dtm.log.Printf("unable to parse response_time: %s, appending null", err)
			responseTimeBuilder.AppendNull()
		} else {
			responseTimeBuilder.Append(arrowTimeResponse)
		}
	}
}

func setServerID(dt *dnstap.Dnstap, serverIDBuilder *array.BinaryBuilder) {
	if len(dt.Identity) == 0 {
		serverIDBuilder.AppendNull()
	} else {
		serverIDBuilder.Append(dt.Identity)
	}
}

func setIPv4(dtm *dnstapMinimiser, dtIPBytes []byte, arrowIPv4Builder *array.Uint32Builder) {
	ip, ok := netip.AddrFromSlice(dtIPBytes)
	if !ok {
		dtm.log.Printf("setIPv4: unable to create netip address from dnstap address")
		arrowIPv4Builder.AppendNull()
		return
	}

	// Make sure we are dealing with 4 byte IPv4 address data (and deal with IPv4-in-IPv6 addresses)
	ip4 := ip.As4()

	ipInt := binary.BigEndian.Uint32(ip4[:])
	arrowIPv4Builder.Append(ipInt)
}

func setIPv6(dtm *dnstapMinimiser, dtIPBytes []byte, arrowIPv6NetworkBuilder *array.Uint64Builder, arrowIPv6HostBuilder *array.Uint64Builder) {
	ip, ok := netip.AddrFromSlice(dtIPBytes)
	if !ok {
		dtm.log.Printf("setIPv6: unable to create netip address from dnstap address")
		arrowIPv6NetworkBuilder.AppendNull()
		arrowIPv6HostBuilder.AppendNull()
		return
	}

	ip16 := ip.As16()

	ipIntNetwork := binary.BigEndian.Uint64(ip16[:8])
	ipIntHost := binary.BigEndian.Uint64(ip16[8:])
	arrowIPv6NetworkBuilder.Append(ipIntNetwork)
	arrowIPv6HostBuilder.Append(ipIntHost)
}

func setPort(dnstapPort uint32, arrowPortBuilder *array.Uint16Builder) {
	arrowPortBuilder.Append(uint16(dnstapPort))
}

func setDNSProtocol(socketProtocol dnstap.SocketProtocol, arrowDNSProtocolBuilder *array.Uint8Builder) {
	arrowDNSProtocolBuilder.Append(uint8(socketProtocol))
}

func setHeader(msg *dns.Msg, arrowHeaderBuilder *array.StructBuilder, arrowHeaderIDBuilder *array.Uint16Builder) {
	arrowHeaderBuilder.Append(true)
	arrowHeaderIDBuilder.Append(msg.Id)
}

func setCounters(msg *dns.Msg, arrowCountersBuilder *array.StructBuilder, arrowCounterQDBuilder, arrowCounterANBuilder, arrowCounterNSBuilder, arrowCounterARBuilder *array.Uint16Builder) {
	qd := uint16(len(msg.Question))
	an := uint16(len(msg.Answer))
	ns := uint16(len(msg.Ns))
	ar := uint16(len(msg.Extra))

	// From https://github.com/dnstapir/datasets/blob/main/dnstap2clickhouse.schema
	// Counters in the query package should
	// always be just one query and nothing else
	// - set only if not [1,0,0,0]
	if qd == 1 && an == 0 && ns == 0 && ar == 0 {
		arrowCountersBuilder.AppendNull()
		return
	}

	arrowCountersBuilder.Append(true)
	arrowCounterQDBuilder.Append(qd)
	arrowCounterANBuilder.Append(an)
	arrowCounterNSBuilder.Append(ns)
	arrowCounterARBuilder.Append(ar)
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

func writeHistogramParquet(dtm *dnstapMinimiser, prevWellKnownDomainsData *wellKnownDomainsData, labelLimit int, outboxDir string) error {
	dtm.log.Printf("in writeHistogramParquet")

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

func ecdsaPrivateKeyFromFile(fileName string) (*ecdsa.PrivateKey, error) {
	fileName = filepath.Clean(fileName)
	keyBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("ecdsaPrivateKeyFromFile: unable to read ECDSA private key file: %w", err)
	}

	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil || pemBlock.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("ecdsaPrivateKeyFromFile: failed to decode PEM block containing ECDSA private key")
	}
	privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key material from: %w", err)
	}

	return privateKey, nil
}

func certPoolFromFile(fileName string) (*x509.CertPool, error) {
	fileName = filepath.Clean(fileName)
	cert, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("certPoolFromFile: unable to read file: %w", err)
	}
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(cert))
	if !ok {
		return nil, fmt.Errorf("certPoolFromFile: failed to append certs from pem: %w", err)
	}

	return certPool, nil
}

// Pseudonymize IP address fields in a dnstap message
func (dtm *dnstapMinimiser) pseudonymizeDnstap(dt *dnstap.Dnstap) {
	dt.Message.QueryAddress = dtm.cryptopan.Anonymize(net.IP(dt.Message.QueryAddress))
	dt.Message.ResponseAddress = dtm.cryptopan.Anonymize(net.IP(dt.Message.ResponseAddress))
}
