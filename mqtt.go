package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/eclipse/paho.golang/paho"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type mqttPublisher struct {
	server     string
	topic      string
	clientID   string
	clientCert tls.Certificate
	signingKey *ecdsa.PrivateKey
	pahoClient *paho.Client
}

func newMQTTPublisher(caCertPool *x509.CertPool, server string, topic string, clientID string, clientCert tls.Certificate, signingKey *ecdsa.PrivateKey) (mqttPublisher, error) {
	conn, err := tls.Dial("tcp", server, &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return mqttPublisher{}, fmt.Errorf("newMQTTPublisher: unable to setup TLS dialer: %w", err)
	}

	c := paho.NewClient(paho.ClientConfig{
		Conn: conn,
	})

	return mqttPublisher{
		server:     server,
		topic:      topic,
		clientID:   clientID,
		clientCert: clientCert,
		signingKey: signingKey,
		pahoClient: c,
	}, nil
}

func (mq mqttPublisher) connect(keepAlive uint16, clientID string, cleanStart bool) error {
	cp := &paho.Connect{
		KeepAlive:  keepAlive,
		ClientID:   clientID,
		CleanStart: cleanStart,
	}
	ca, err := mq.pahoClient.Connect(context.Background(), cp)
	if err != nil {
		return fmt.Errorf("mqttPublisher.connect: unable to connect: %w", err)
	}
	if ca.ReasonCode != 0 {
		return fmt.Errorf("mqttPublisher.connect: failed to connect to %s : %d - %s", mq.server, ca.ReasonCode, ca.Properties.ReasonString)
	}

	fmt.Printf("Connected to %s\n", mq.server)

	return nil
}

func (mp mqttPublisher) publishMQTT(jsonBytes []byte) error {
	signedMessage, err := jws.Sign(jsonBytes, jws.WithJSON(), jws.WithKey(jwa.ES256, mp.signingKey))
	if err != nil {
		return fmt.Errorf("mqttPublisher.publishMQTT: failed to created JWS message: %w", err)
	}

	if _, err = mp.pahoClient.Publish(context.Background(), &paho.Publish{
		Topic:   mp.topic,
		Payload: signedMessage,
	}); err != nil {
		log.Println("error sending message:", err)
	}
	log.Printf("sent signed JWS: %s", string(signedMessage))

	return nil
}
