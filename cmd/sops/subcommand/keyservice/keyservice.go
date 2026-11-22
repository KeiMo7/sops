package keyservice

import (
	"crypto/tls"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/logging"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("KEYSERVICE")
}

// Opts are the options the key service server can take
type Opts struct {
	Network string
	Address string
	Prompt  bool

	// TLS certificate material. The client CA enables caller authentication.
	TLSCertFile     string
	TLSKeyFile      string
	TLSClientCAFile string
	TLSMinVersion   string

	// AllowAnonymous explicitly admits unauthenticated callers. The
	// listener must be a loopback or unix socket.
	AllowAnonymous bool

	// PolicyPath is a YAML/JSON scope policy. Broken policy files fail at
	// startup.
	PolicyPath string

	// Verbose raises the server log level to Debug, including audit
	// records. Without it the server keeps audit records at Info, which is
	// the minimum needed for denials to be verifiable.
	Verbose bool

	// RequestTimeout bounds each backend operation. Queued requests are
	// bounded by QueueTimeout.
	RequestTimeout time.Duration
	QueueTimeout   time.Duration
	MaxConcurrent  int
	MaxQueued      int
	RateLimit      float64
	RateBurst      int
	MetricsPeriod  time.Duration
}

// validateConfig builds and validates the server configuration without
// opening a socket, so that misconfiguration fails at startup.
func validateConfig(opts Opts) (keyservice.ListenerConfig, *keyservice.Policy, *keyservice.ServerTLSConfig, error) {
	listener := keyservice.ListenerConfig{
		Network:        opts.Network,
		Address:        opts.Address,
		AllowAnonymous: opts.AllowAnonymous,
	}
	if opts.TLSCertFile != "" || opts.TLSKeyFile != "" || opts.TLSClientCAFile != "" {
		tlsCfg := &keyservice.ServerTLSConfig{
			CertFile:     opts.TLSCertFile,
			KeyFile:      opts.TLSKeyFile,
			ClientCAFile: opts.TLSClientCAFile,
		}
		minVersion, err := parseTLSVersion(opts.TLSMinVersion)
		if err != nil {
			return listener, nil, nil, err
		}
		tlsCfg.MinVersion = minVersion
		listener.TLS = tlsCfg
	}
	var policy *keyservice.Policy
	if opts.PolicyPath != "" {
		p, err := keyservice.LoadPolicy(opts.PolicyPath)
		if err != nil {
			return listener, nil, nil, err
		}
		policy = p
	}
	if err := listener.Validate(); err != nil {
		return listener, nil, nil, err
	}
	return listener, policy, listener.TLS, nil
}

func parseTLSVersion(version string) (uint16, error) {
	switch version {
	case "", "1.2", "tls1.2", "TLS1.2":
		return 0, nil
	case "1.3", "tls1.3", "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, &configError{msg: "invalid --tls-min-version " + version + " (want 1.2 or 1.3)"}
	}
}

type configError struct{ msg string }

func (e *configError) Error() string { return "keyservice: " + e.msg }

// Run runs a SOPS key service server
func Run(opts Opts) error {
	_, policy, tlsCfg, err := validateConfig(opts)
	if err != nil {
		return err
	}

	// Audit records are written at Info. The default logger level is Warn,
	// so raise it to Info for the server: without this, rejected and
	// failed requests would leave no auditable trace at all. --verbose
	// still selects Debug.
	if opts.Verbose {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}

	metrics := &keyservice.Metrics{}
	audit := keyservice.NewAuditLogger(log, metrics)
	limiter := keyservice.NewLimiter(opts.MaxConcurrent, opts.RateLimit, opts.RateBurst, opts.QueueTimeout, opts.MaxQueued, metrics)

	var transport grpc.ServerOption
	if tlsCfg != nil {
		tlsCfg.OnHandshakeFailure = audit.LogHandshakeFailure
		creds, err := tlsCfg.ServerCredentials()
		if err != nil {
			return err
		}
		transport = grpc.Creds(creds)
	}

	grpcOpts := []grpc.ServerOption{}
	if transport != nil {
		grpcOpts = append(grpcOpts, transport)
	}
	grpcServer := grpc.NewServer(grpcOpts...)
	keyservice.RegisterKeyServiceServer(grpcServer, keyservice.Server{
		Prompt:         opts.Prompt,
		Policy:         policy,
		AllowAnonymous: opts.AllowAnonymous,
		RequestTimeout: opts.RequestTimeout,
		Limiter:        limiter,
		Metrics:        metrics,
		Audit:          audit,
	})

	lis, err := net.Listen(opts.Network, opts.Address)
	if err != nil {
		return err
	}
	defer lis.Close()

	stopMetrics := make(chan struct{})
	if opts.MetricsPeriod > 0 {
		go func() {
			ticker := time.NewTicker(opts.MetricsPeriod)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					audit.LogMetrics()
				case <-stopMetrics:
					return
				}
			}
		}()
	}

	log.WithFields(logrus.Fields{
		"network":        opts.Network,
		"address":        opts.Address,
		"tls":            tlsCfg.Enabled(),
		"caller_auth":    tlsCfg.AuthenticatesCallers(),
		"anonymous":      opts.AllowAnonymous,
		"policy":         policy != nil,
		"max_concurrent": opts.MaxConcurrent,
		"rate_limit":     opts.RateLimit,
		"timeout":        opts.RequestTimeout.String(),
	}).Info("Listening")

	// Close socket if we get killed
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func(c chan os.Signal) {
		sig := <-c
		log.Infof("Caught signal %s: shutting down.", sig)
		close(stopMetrics)
		lis.Close()
		os.Exit(0)
	}(sigc)
	return grpcServer.Serve(lis)
}
