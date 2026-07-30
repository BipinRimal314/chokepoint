// Command chokepoint is a policy-enforcing proxy for Model Context Protocol
// tool servers.
//
// It runs an MCP server as a child process and sits between it and the agent,
// evaluating every tool call against a policy before forwarding it.
//
//	chokepoint --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv
//
// With no --policy it is a transparent proxy, which is the intended way to
// introduce it: put it in the path first, watch what the agent actually does,
// then write rules against observed behaviour.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/BipinRimal314/chokepoint/internal/detect"
	"github.com/BipinRimal314/chokepoint/internal/gateway"
	"github.com/BipinRimal314/chokepoint/internal/policy"
	"github.com/BipinRimal314/chokepoint/internal/proxy"
	"github.com/BipinRimal314/chokepoint/internal/telemetry"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type config struct {
	policyPath   string
	window       time.Duration
	maxCalls     int
	logLevel     string
	metricsAddr  string
	otlpEndpoint string
	showVersion  bool
	upstream     []string
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "chokepoint: %v\n\n", err)
		usage()
		os.Exit(2)
	}
	if cfg.showVersion {
		fmt.Printf("chokepoint %s\n", version)
		return
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "chokepoint: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: chokepoint [options] -- <mcp-server-command> [args...]

options:
  --policy PATH     policy file (YAML); omit for a transparent proxy
  --window DUR      behavioural window, e.g. 10m (default: whole session)
  --max-calls N     per-session call retention cap (default 10000)
  --metrics-addr A  serve Prometheus metrics on A, e.g. :9090 (default off)
  --otlp-endpoint E export OTLP/gRPC traces to E, e.g. localhost:4317 (default off)
  --log-level LEVEL debug, info, warn, error (default info)
  --version         print version and exit

example:
  chokepoint --policy policy.yaml --metrics-addr :9090 \
    -- npx -y @modelcontextprotocol/server-filesystem /srv
`)
}

func parseArgs(args []string) (config, error) {
	cfg := config{logLevel: "info", maxCalls: detect.DefaultMaxCalls}

	i := 0
	for ; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			i++
			break
		}
		// Everything before `--` is a chokepoint flag. Parsed by hand rather
		// than with the flag package because the upstream command routinely
		// carries its own flags, and flag would try to interpret them.
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}

		var err error
		switch arg {
		case "--policy":
			cfg.policyPath, err = next()
		case "--log-level":
			cfg.logLevel, err = next()
		case "--metrics-addr":
			cfg.metricsAddr, err = next()
		case "--otlp-endpoint":
			cfg.otlpEndpoint, err = next()
		case "--version", "-v":
			cfg.showVersion = true
		case "--help", "-h":
			usage()
			os.Exit(0)
		case "--window":
			var raw string
			if raw, err = next(); err == nil {
				cfg.window, err = time.ParseDuration(raw)
			}
		case "--max-calls":
			var raw string
			if raw, err = next(); err == nil {
				_, err = fmt.Sscanf(raw, "%d", &cfg.maxCalls)
			}
		default:
			return cfg, fmt.Errorf("unknown option %q", arg)
		}
		if err != nil {
			return cfg, err
		}
	}

	cfg.upstream = args[i:]
	if !cfg.showVersion && len(cfg.upstream) == 0 {
		return cfg, errors.New("no upstream command given; pass it after --")
	}
	return cfg, nil
}

func run(cfg config) error {
	logger := newLogger(cfg.logLevel)

	var pol *policy.Policy
	var scope detect.Scope
	if cfg.policyPath != "" {
		var err error
		pol, err = policy.Load(cfg.policyPath)
		if err != nil {
			// A policy that does not compile is a hard failure. Starting
			// anyway would run an agent with protection its operator believes
			// is in place.
			return fmt.Errorf("load policy: %w", err)
		}
		// Same reasoning for the working set: a boundary that cannot be parsed
		// would contain nothing, so every scope rule would report clean while
		// enforcing nothing.
		scope, err = detect.NewScope(pol.Workspace)
		if err != nil {
			return fmt.Errorf("load policy: workspace: %w", err)
		}
		logger.Info("policy loaded",
			"path", cfg.policyPath,
			"rules", len(pol.Rules),
			"default_effect", pol.DefaultEffect,
			"workspace", pol.Workspace)
		if !scope.Declared() {
			logger.Info("no workspace declared; scope rules will not fire")
		}
	} else {
		logger.Warn("no policy configured; running as a transparent proxy")
	}

	// Signals are handled by cancelling the context, which tears the session
	// down in order rather than leaving an orphaned child process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var observer gateway.Observer
	if cfg.metricsAddr != "" || cfg.otlpEndpoint != "" {
		tel, err := telemetry.New(ctx, telemetry.Options{
			ServiceName:  "chokepoint",
			Version:      version,
			MetricsAddr:  cfg.metricsAddr,
			OTLPEndpoint: cfg.otlpEndpoint,
			Logger:       logger,
		})
		if err != nil {
			// Refusing to start is deliberate. An operator who asked for
			// metrics and silently got none would believe they have
			// visibility they do not have, which is worse than a clear
			// failure at startup.
			return fmt.Errorf("telemetry: %w", err)
		}
		observer = tel
		defer func() {
			// A fresh context: the run context is already cancelled by the
			// time this runs, and an exporter given a dead context flushes
			// nothing — losing exactly the spans from the shutdown that is
			// most likely being investigated.
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := tel.Shutdown(flushCtx); err != nil {
				logger.Warn("telemetry shutdown", "error", err)
			}
		}()
	}

	cmd := exec.CommandContext(ctx, cfg.upstream[0], cfg.upstream[1:]...)
	// The child's stderr is passed through untouched: MCP servers log there,
	// and swallowing it would make debugging one impossible from behind the
	// proxy.
	cmd.Stderr = os.Stderr

	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("upstream stdout: %w", err)
	}
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("upstream stdin: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upstream %q: %w", cfg.upstream[0], err)
	}
	logger.Info("upstream started", "command", cfg.upstream[0], "pid", cmd.Process.Pid)

	gw := gateway.New(gateway.Options{
		Policy: pol,
		Detector: detect.NewSession(detect.Config{
			Window:   cfg.window,
			MaxCalls: cfg.maxCalls,
		}),
		Scope:    scope,
		Logger:   logger,
		Observer: observer,
	})

	session := proxy.NewSession(proxy.Streams{
		ClientIn:  os.Stdin,
		ClientOut: os.Stdout,
		ServerIn:  serverIn,
		ServerOut: serverOut,
	}, proxy.Options{
		Interceptor: gw,
		OnError: func(dir proxy.Direction, err error) {
			logger.Debug("proxy note", "direction", dir.String(), "error", err)
		},
	})

	runErr := session.Run(ctx)

	// Close the child's stdin so a well-behaved server exits on its own before
	// the context kills it.
	_ = serverIn.Close()
	waitErr := cmd.Wait()

	if runErr != nil {
		return runErr
	}
	// A child killed by our own shutdown is not a failure to report.
	if waitErr != nil && ctx.Err() == nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			logger.Info("upstream exited", "code", exitErr.ExitCode())
			return nil
		}
		return fmt.Errorf("upstream: %w", waitErr)
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	// Logs go to stderr without exception: stdout carries the MCP protocol
	// stream, and one stray log line there corrupts the session.
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
