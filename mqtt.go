package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func newAutoPahoClientConfig(dtm *dnstapMinimiser, caCertPool *x509.CertPool, server string, clientID string, clientCert tls.Certificate, mqttKeepAlive uint16) (autopaho.ClientConfig, error) {

	u, err := url.Parse(server)
	if err != nil {
		return autopaho.ClientConfig{}, fmt.Errorf("newAutoPahoClientConfig: unable to parse URL: %w", err)
	}

	cliCfg := autopaho.ClientConfig{
		BrokerUrls: []*url.URL{u},
		TlsCfg: &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{clientCert},
			MinVersion:   tls.VersionTLS13,
		},
		KeepAlive:      mqttKeepAlive,
		OnConnectionUp: func(*autopaho.ConnectionManager, *paho.Connack) { dtm.log.Info("mqtt connection up") },
		OnConnectError: func(err error) { dtm.log.Error("error whilst attempting connection", "error", err) },
		Debug:          paho.NOOPLogger{},
		ClientConfig: paho.ClientConfig{
			ClientID:      clientID,
			OnClientError: func(err error) { dtm.log.Error("server requested disconnect", "error", err) },
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					dtm.log.Error("server requested disconnect", "reason_string", d.Properties.ReasonString)
				} else {
					dtm.log.Error("server requested disconnect", "reason_code", d.ReasonCode)
				}
			},
		},
	}

	return cliCfg, nil

}

func runAutoPaho(ctx context.Context, wg *sync.WaitGroup, cm *autopaho.ConnectionManager, dtm *dnstapMinimiser, mqttPubCh chan []byte, topic string, mqttSigningKey *ecdsa.PrivateKey) {
	defer wg.Done()
	for {
		// AwaitConnection will return immediately if connection is up; adding this call stops publication whilst
		// connection is unavailable.
		err := cm.AwaitConnection(ctx)
		if err != nil { // Should only happen when context is cancelled
			dtm.log.Error("publisher done", "AwaitConnection", err)
			return
		}

		// Wait for a message to publish
		unsignedMsg := <-mqttPubCh
		if unsignedMsg == nil {
			// The channel has been closed
			return
		}

		signedMsg, err := jws.Sign(unsignedMsg, jws.WithJSON(), jws.WithKey(jwa.ES256, mqttSigningKey))
		if err != nil {
			dtm.log.Error("runAutoPaho: failed to created JWS message", "error", err)
		}

		// Publish will block so we run it in a goRoutine
		go func(msg []byte) {
			pr, err := cm.Publish(ctx, &paho.Publish{
				QoS:     0,
				Topic:   topic,
				Payload: msg,
			})
			if err != nil {
				dtm.log.Error("error publishing", "error", err)
			} else if pr != nil && pr.ReasonCode != 0 && pr.ReasonCode != 16 { // 16 = Server received message but there are no subscribers
				// pr is only non-nil for QoS 1 and up
				dtm.log.Info("reason code received", "reason_code", pr.ReasonCode)
			}
			dtm.log.Info("sent message", "content", string(msg))
		}(signedMsg)

		select {
		case <-time.After(time.Millisecond * 100):
		case <-ctx.Done():
			dtm.log.Info("publisher done")
			return
		}
	}
}
