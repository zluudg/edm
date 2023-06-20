package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/yawning/cryptopan"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
)

func readConfig(configFile string) (dtaConfig, error) {
	conf := dtaConfig{}
	if _, err := toml.DecodeFile(configFile, &conf); err != nil {
		return dtaConfig{}, fmt.Errorf("readConfig: %w", err)
	}

	return conf, nil
}

func main() {

	// Handle flags
	debug := flag.Bool("debug", false, "print debug logging during operation")
	configFile := flag.String("config", "dta.toml", "config file for sensitive information")
	fileformat := flag.String("file-format", "json", "output format ('json' or 'fstrm')")
	unixSocketPath := flag.String("unix-socket-path", "/var/lib/unbound/dnstap.sock", "the unix socket we create for dnstap senders")
	outputFilename := flag.String("output-filename", "", "the filename to write dnstap streams to (empty or '-' means stdout)")
	cryptoPanKey := flag.String("cryptopan-key", "", "override the secret used for Crypto-PAn anonymization")
	cryptoPanKeySalt := flag.String("cryptopan-key-salt", "dta-kdf-salt-val", "the salt used for key derivation")
	simpleRandomSamplingN := flag.Int("simple-random-sampling-n", 0, "only capture random 1-out-of-N dnstap messages, 0 disables sampling")
	flag.Parse()

	conf, err := readConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	if conf.CryptoPanKey == "" {
		log.Fatalf("missing required setting 'cryptopan-key' in %s", *configFile)
	}

	// While we require setting the Crypto-PAn key in the config file it can be
	// overridden with a flag for testing purposes
	if *cryptoPanKey != "" {
		conf.CryptoPanKey = *cryptoPanKey
	}

	// Logger used for the different background workers, logged to stderr
	// so stdout only includes dnstap data if anything.
	logger := log.New(os.Stderr, "", log.LstdFlags)

	// Configure the selected output writer
	var dnstapOutput dnstap.Output

	switch *fileformat {
	case "fstrm":
		dnstapOutput, err = dnstap.NewFrameStreamOutputFromFilename(*outputFilename)
		if err != nil {
			log.Fatal(err)
		}
	case "json":
		dnstapOutput, err = dnstap.NewTextOutputFromFilename(*outputFilename, dnstap.JSONFormat, false)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("file-format must be 'fstrm' or 'json'")
	}

	// Enable logging for the selected output worker
	switch v := dnstapOutput.(type) {
	case *dnstap.FrameStreamOutput:
		v.SetLogger(logger)
	case *dnstap.TextOutput:
		v.SetLogger(logger)
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

	// Create an instance of the filter
	dtf, err := newDnstapFilter(logger, dnstapOutput, aesKey, *simpleRandomSamplingN, *debug)
	if err != nil {
		log.Fatal(err)
	}

	// Setup the unix socket dnstap.Input
	dti, err := dnstap.NewFrameStreamSockInputFromPath(*unixSocketPath)
	if err != nil {
		log.Fatal(err)
	}
	dti.SetTimeout(time.Second * 5)
	dti.SetLogger(logger)

	// Exit gracefully on SIGINT or SIGTERM
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
		<-sigs

		// We received a signal, tell runFilter() to stop
		close(dtf.stop)
	}()

	// Start filter
	go dtf.runFilter()

	// Start dnstap.Output
	go dnstapOutput.RunOutputLoop()

	// Start dnstap.Input
	go dti.ReadInto(dtf.inputChannel)

	// Wait here until runFilter() is done
	<-dtf.done
}

type dtaConfig struct {
	CryptoPanKey string `toml:"cryptopan-key"`
}

type dnstapFilter struct {
	inputChannel chan []byte          // the channel expected to be passed to dnstap ReadInto()
	dnstapOutput dnstap.Output        // the dnstap.Output we send modified dnstap messages to
	log          dnstap.Logger        // any information logging is sent here
	cryptopan    *cryptopan.Cryptopan // used for anonymizing IP addresses
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
func (dtf *dnstapFilter) runFilter() {
	dt := &dnstap.Dnstap{}
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

			if dtf.debug {
				dtf.log.Printf("dnstapFilter.runFilter: modifying dnstap message")
			}
			dtf.anonymizeDnstap(dt)

			b, err := proto.Marshal(dt)
			if err != nil {
				dtf.log.Printf("dnstapFilter.runFilter: proto.Marshal() failed: %s, returning", err)
				break filterLoop
			}
			dtf.dnstapOutput.GetOutputChannel() <- b
		case <-dtf.stop:
			break filterLoop
		}
	}
	// We close the dnstap.Output so it has a chance to flush out its messages
	dtf.dnstapOutput.Close()
	// Signal main() that we are done and ready to exit
	close(dtf.done)
}

// Anonymize IP address fields in a dnstap message
func (dtf *dnstapFilter) anonymizeDnstap(dt *dnstap.Dnstap) {
	dt.Message.QueryAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.QueryAddress))
	dt.Message.ResponseAddress = dtf.cryptopan.Anonymize(net.IP(dt.Message.ResponseAddress))
}
