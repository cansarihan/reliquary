package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/cansarihan/reliquary/internal/engine"
	"github.com/cansarihan/reliquary/internal/logging"
	"github.com/cansarihan/reliquary/internal/module"
	"github.com/cansarihan/reliquary/internal/osv"
	"github.com/cansarihan/reliquary/internal/report"
	"github.com/cansarihan/reliquary/internal/sbom"
	"github.com/cansarihan/reliquary/internal/server"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "reliquary: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return usage()
	}
	switch os.Args[1] {
	case "scan":
		return runScan(os.Args[2:])
	case "sbom":
		return runSBOM(os.Args[2:])
	case "serve":
		return runServe(os.Args[2:])
	case "version":
		fmt.Printf("reliquary %s (commit %s, built %s)\n", version, commit, date)
		return nil
	default:
		return usage()
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, "usage: reliquary <scan|sbom|serve|version> [flags] [dir]")
	fmt.Fprintln(os.Stderr, "  reliquary scan .")
	fmt.Fprintln(os.Stderr, "  reliquary sbom -o bom.json .")
	fmt.Fprintln(os.Stderr, "  reliquary serve -dir . -listen 127.0.0.1:8080")
	return errors.New("no command given")
}

func runScan(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	timeout := flags.Duration("t", 30*time.Second, "OSV query timeout")
	asJSON := flags.Bool("json", false, "print JSON instead of a table")
	if err := flags.Parse(args); err != nil {
		return err
	}

	project, err := module.Parse(dir(flags.Args()))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := osv.New(&http.Client{Timeout: *timeout})
	summary, err := engine.Run(ctx, project, client, nil)
	if err != nil {
		return err
	}

	if *asJSON {
		return report.JSON(os.Stdout, summary)
	}
	report.Table(os.Stdout, summary)
	return nil
}

func runSBOM(args []string) error {
	flags := flag.NewFlagSet("sbom", flag.ContinueOnError)
	out := flags.String("o", "", "write to a file instead of stdout")
	timeout := flags.Duration("t", 30*time.Second, "OSV query timeout")
	noScan := flags.Bool("no-scan", false, "list components without querying vulnerabilities")
	if err := flags.Parse(args); err != nil {
		return err
	}

	project, err := module.Parse(dir(flags.Args()))
	if err != nil {
		return err
	}

	var reports []engine.ModuleReport
	if !*noScan {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		client := osv.New(&http.Client{Timeout: *timeout})
		summary, err := engine.Run(ctx, project, client, nil)
		if err != nil {
			return err
		}
		reports = summary.Modules
	}

	document := sbom.Build(project, reports)
	writer := os.Stdout
	if *out != "" {
		file, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		writer = file
	}
	return sbom.Write(writer, document)
}

func dir(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "."
}

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8080", "listen address")
	root := flags.String("dir", ".", "project directory to scan")
	token := flags.String("token", os.Getenv("RELIQUARY_TOKEN"), "admin token")
	noUI := flags.Bool("no-ui", false, "disable the panel")
	timeout := flags.Duration("t", 30*time.Second, "OSV query timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}

	logger := logging.New("info", "text", os.Stderr)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	handler := server.New(server.Options{
		Dir:     *root,
		Token:   *token,
		UI:      !*noUI,
		Timeout: *timeout,
	}, server.BuildInfo{
		Version:   version,
		Commit:    commit,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}).Handler()

	httpServer := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		logger.Info("reliquary listening", "address", *listen, "dir", *root, "ui", !*noUI)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdown)
}
