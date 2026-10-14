package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Keviince/web-console/internal/app"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	checkHealth := flag.Bool("healthcheck", false, "check the local server and exit")
	generate := flag.Bool("generate-key", false, "print a new 256-bit encryption key and exit")
	testDevice := flag.String("test-device", "", "test a saved device by slug without starting the web server")
	flag.Parse()
	if *showVersion {
		fmt.Printf("web-console %s\n", version)
		return
	}
	if *checkHealth {
		if err := healthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *generate {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
		fmt.Println(hex.EncodeToString(key))
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := app.LoadConfig()
	if err != nil {
		log.Error("configuration error", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *testDevice != "" {
		if err := app.TestStoredDevice(ctx, cfg, *testDevice, log); err != nil {
			log.Error("device diagnostic failed", "reason", err.Error())
			os.Exit(1)
		}
		return
	}
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}
	defer a.Close()
	srv := &http.Server{Addr: cfg.Listen, Handler: a, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		a.RevokeAll()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("listening", "address", cfg.Listen, "portal", cfg.PortalURL)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func healthcheck() error {
	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid LISTEN address")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return fmt.Errorf("health check failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	return nil
}
