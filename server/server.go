package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/privacypass/challenge-bypass-server"
	"github.com/privacypass/challenge-bypass-server/crypto"
	"github.com/privacypass/challenge-bypass-server/metrics"
)

var (
	Version         = "dev"
	maxBackoffDelay = 1 * time.Second
	maxRequestSize  = int64(20 * 1024) // ~10kB is expected size for 100*base64([64]byte) + ~framing

	ErrEmptyKeyPath        = errors.New("key file path is empty")
	ErrNoSecretKey         = errors.New("server config does not contain a key")
	ErrRequestTooLarge     = errors.New("request too large to process")
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")
	// Commitments are embedded straight into the extension for now
	ErrEmptyCommPath = errors.New("no commitment file path specified")

	errLog *log.Logger = log.New(os.Stderr, "[btd] ", log.LstdFlags|log.Lshortfile)
)

type Server struct {
	BindAddress string
	ListenPort  int
	MetricsPort int
	MaxTokens   int

	signKey    []byte        // a big-endian marshaled big.Int representing an elliptic curve scalar for the current signing key
	redeemKeys [][]byte      // current signing key + all old keys
	g          *crypto.Point // elliptic curve point representation of generator G
	h          *crypto.Point // elliptic curve point representation of commitment H to signing key
	KeyVersion string        // the version of the key that is used

	// Guards signKey, redeemKeys, g, h.
	mutex sync.RWMutex
}

// return nil to exit without complaint, caller closes
func (c *Server) handle(conn *net.TCPConn) error {
	metrics.CounterConnections.Inc()

	// This is directly in the user's path, an overly slow connection should just fail
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Read the request but never more than a worst-case assumption
	var buf = new(bytes.Buffer)
	limitedConn := io.LimitReader(conn, maxRequestSize)
	_, err := io.Copy(buf, limitedConn)

	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "i/o timeout" && buf.Len() > 0 {
			// then probably we just hit the read deadline, so try to unwrap anyway
		} else {
			metrics.CounterConnErrors.Inc()
			return err
		}
	}

	var wrapped btd.BlindTokenRequestWrapper
	var request btd.BlindTokenRequest

	err = json.Unmarshal(buf.Bytes(), &wrapped)
	if err != nil {
		metrics.CounterJsonError.Inc()
		return err
	}
	err = json.Unmarshal(wrapped.Request, &request)
	if err != nil {
		metrics.CounterJsonError.Inc()
		return err
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	switch request.Type {
	case btd.ISSUE:
		metrics.CounterIssueTotal.Inc()
		err = btd.HandleIssue(conn, request, c.signKey, c.KeyVersion, c.g, c.h, c.MaxTokens)
		if err != nil {
			metrics.CounterIssueError.Inc()
			return err
		}
		return nil
	case btd.REDEEM:
		metrics.CounterRedeemTotal.Inc()
		err = btd.HandleRedeem(conn, request, wrapped.Host, wrapped.Path, c.redeemKeys)
		if err != nil {
			metrics.CounterRedeemError.Inc()
			conn.Write([]byte(err.Error())) // anything other than "success" counts as a VERIFY_ERROR
			return err
		}
		return nil
	default:
		errLog.Printf("unrecognized request type \"%s\"", request.Type)
		metrics.CounterUnknownRequestType.Inc()
		return ErrUnrecognizedRequest
	}
}

// LoadKeys loads a signing key and optionally loads a file containing old keys for redemption validation
func (c *Server) LoadKeys(
	signKeyFile string,
	commFile string,
	redeemKeysFile string, // optional
) error {
	if signKeyFile == "" {
		return ErrEmptyKeyPath
	} else if commFile == "" {
		return ErrEmptyCommPath
	}

	// Parse current signing key
	_, currkey, err := crypto.ParseKeyFile(signKeyFile, true)
	if err != nil {
		return err
	}
	var redeemKeys [][]byte
	signKey := currkey[0]
	redeemKeys = append(redeemKeys, signKey)

	// optionally parse old keys that are valid for redemption
	if redeemKeysFile != "" {
		errLog.Println("Adding extra keys for verifying token redemptions")
		_, oldKeys, err := crypto.ParseKeyFile(redeemKeysFile, false)
		if err != nil {
			return err
		}
		redeemKeys = append(redeemKeys, oldKeys...)
	}

	// Get bytes for public commitment to private key
	GBytes, HBytes, err := crypto.ParseCommitmentFile(commFile)
	if err != nil {
		return err
	}

	// Retrieve the actual elliptic curve points for the commitment
	// The commitment should match the current key that is being used for
	// signing
	//
	// We only support curve point commitments for P256-SHA256
	G, H, err := crypto.RetrieveCommPoints(GBytes, HBytes, signKey)
	if err != nil {
		return err
	}

	c.mutex.Lock()
	c.signKey = signKey
	c.redeemKeys = redeemKeys
	c.g = G
	c.h = H
	c.mutex.Unlock()

	return nil
}

func (c *Server) ListenAndServe() error {
	if len(c.signKey) == 0 {
		return ErrNoSecretKey
	}

	addr := fmt.Sprintf("%s:%d", c.BindAddress, c.ListenPort)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	errLog.Printf("blindsigmgmt starting, version: %v", Version)
	errLog.Printf("listening on %s", addr)

	// Initialize prometheus endpoint
	metricsAddr := fmt.Sprintf("%s:%d", c.BindAddress, c.MetricsPort)
	go func() {
		metrics.RegisterAndListen(metricsAddr, errLog)
	}()

	// Log errors without killing the entire server
	errorChannel := make(chan error)
	go func() {
		for err := range errorChannel {
			if err == nil {
				continue
			}
			errLog.Printf("%v", err)
		}
	}()

	// how long to wait for temporary net errors
	backoffDelay := 1 * time.Millisecond

	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if netErr.Temporary() {
					// let's wait
					if backoffDelay > maxBackoffDelay {
						backoffDelay = maxBackoffDelay
					}
					time.Sleep(backoffDelay)
					backoffDelay = 2 * backoffDelay
				}
			}
			metrics.CounterConnErrors.Inc()
			errorChannel <- err
			continue
		}

		backoffDelay = 1 * time.Millisecond
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(1 * time.Minute)

		go func() {
			errorChannel <- c.handle(tcpConn)
			tcpConn.Close()
		}()
	}
}
