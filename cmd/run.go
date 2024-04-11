package cmd

import (
	"log"

	"github.com/dnstapir/dtm/pkg/runner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run dtm in dnstap capture mode",
	Run: func(cmd *cobra.Command, args []string) {
		runner.Run()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	runCmd.Flags().Bool("debug", false, "print debug logging during operation")
	runCmd.Flags().Bool("disable-session-files", false, "do not write out session parquet files")

	runCmd.Flags().String("input-unix", "", "create unix socket for reading dnstap (e.g. /var/lib/unbound/dnstap.sock)")
	runCmd.Flags().String("input-tcp", "", "create TCP socket for reading dnstap (e.g. '127.0.0.1:53535')")
	runCmd.Flags().String("input-tls", "", "create TLS TCP socket for reading dnstap (e.g. '127.0.0.1:53535')")
	runCmd.MarkFlagsOneRequired("input-unix", "input-tcp", "input-tls")
	runCmd.MarkFlagsMutuallyExclusive("input-unix", "input-tcp", "input-tls")

	runCmd.Flags().String("input-tls-cert-file", "", "file containing cert used for TLS TCP socket")
	runCmd.Flags().String("input-tls-key-file", "", "file containing key used for TLS TCP socket")
	runCmd.MarkFlagsRequiredTogether("input-tls", "input-tls-cert-file", "input-tls-key-file")

	runCmd.Flags().String("input-tls-client-ca-file", "", "file containing CA used for client cert allowed to connect to TLS TCP socket")

	runCmd.Flags().String("cryptopan-key", "", "override the secret used for Crypto-PAn pseudonymization")

	runCmd.Flags().String("cryptopan-key-salt", "dtm-kdf-salt-val", "the salt used for key derivation")
	runCmd.Flags().String("well-known-domains", "well-known-domains.dawg", "the dawg file used for filtering well-known domains")
	runCmd.Flags().String("data-dir", "/var/lib/dtm", "directory where output data is written")
	runCmd.Flags().String("mqtt-signing-key-file", "dtm-mqtt-signer-key.pem", "ECSDSA key used for signing MQTT messages")
	runCmd.Flags().String("mqtt-client-key-file", "dtm-mqtt-client-key.pem", "ECSDSA client key used for authenticating to MQTT bus")
	runCmd.Flags().String("mqtt-client-cert-file", "dtm-mqtt-client.pem", "ECSDSA client cert used for authenticating to MQTT bus")
	runCmd.Flags().String("mqtt-server", "127.0.0.1:8883", "MQTT server we will publish events to")
	runCmd.Flags().String("mqtt-topic", "events/up/dtm/new_qname", "MQTT server we will publish events to")
	runCmd.Flags().String("mqtt-client-id", "dtm-pub", "MQTT client id used for publishing events")
	runCmd.Flags().String("mqtt-ca-file", "", "CA cert used for validating MQTT TLS connection, defaults to using OS CA certs")

	runCmd.Flags().Int("mqtt-keepalive", 30, "Keepalive interval for MQTT connection")
	//runCmd.Flags().Bool("mqtt-clean-start", true, "Control if a new MQTT session is created when connecting")
	runCmd.Flags().Int("qname-seen-entries", 10000000, "Number of 'seen' qnames stored in LRU cache, need to be changed based on RAM")
	runCmd.Flags().Int("cryptopan-address-entries", 10000000, "Number of cryptopan pseudonymised addresses stored in LRU cache, 0 disables the cache, need to be changed based on RAM")
	runCmd.Flags().Int("newqname-buffer", 1000, "Number of slots in new_qname publisher channel, if this is filled up we skip new_qname events")
	runCmd.Flags().String("http-ca-file", "", "CA cert used for validating aggregate-receiver connection, defaults to using OS CA certs")
	runCmd.Flags().String("http-signing-key-file", "dtm-http-signer-key.pem", "ECSDSA key used for signing HTTP messages to aggregate-receiver")
	runCmd.Flags().String("http-signing-key-id", "key1", "ID for the HTTP signing key")
	runCmd.Flags().String("http-client-key-file", "dtm-http-client-key.pem", "ECSDSA client key used for authenticating to aggregate-receiver")
	runCmd.Flags().String("http-client-cert-file", "dtm-http-client.pem", "ECSDSA client cert used for authenticating to aggregate-receiver")
	runCmd.Flags().String("http-url", "https://127.0.0.1:8443", "Service we will POST aggregates to")

	runCmd.Flags().String("debug-dnstap-filename", "", "File for dumping JSON-formatted dnstap packets we are about to process, for debugging")

	err := viper.BindPFlags(runCmd.Flags())
	if err != nil {
		log.Fatal(err)
	}
}
