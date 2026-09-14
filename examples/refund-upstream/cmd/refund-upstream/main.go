// Command refund-upstream serves the authenticated Stripe test example.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	refund "github.com/cadrena/mcp-gateway/examples/refund-upstream"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "serve", "serve or validate; validate reads an existing test Charge")
	flag.Parse()
	adapter, err := refund.New(refund.Config{APIKey: os.Getenv("STRIPE_TEST_API_KEY")})
	if err != nil {
		return err
	}
	if *mode == "validate" {
		amount, err := strconv.ParseInt(os.Getenv("STRIPE_TEST_AMOUNT_MINOR"), 10, 64)
		if err != nil || amount <= 0 {
			return errors.New("STRIPE_TEST_AMOUNT_MINOR must be a positive integer")
		}
		args, err := json.Marshal(map[string]any{"customer": os.Getenv("STRIPE_TEST_CUSTOMER"), "payment": os.Getenv("STRIPE_TEST_CHARGE"), "amount_minor": amount})
		if err != nil {
			return errors.New("invalid test fixture")
		}
		if err := adapter.Validate(context.Background(), args); err != nil {
			return err
		}
		fmt.Println("Test Charge validation passed; no refund requested.")
		return nil
	}
	if *mode != "serve" {
		return errors.New("unsupported mode")
	}
	handler, err := refund.NewHandler(adapter, refund.HTTPConfig{GatewayBearer: os.Getenv("CADRENA_GATEWAY_BEARER"), AllowedHosts: list(os.Getenv("CADRENA_REFUND_HOSTS")), AllowedOrigins: list(os.Getenv("CADRENA_REFUND_ORIGINS"))})
	if err != nil {
		return err
	}
	listen := os.Getenv("CADRENA_REFUND_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8099"
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("refund server failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func list(value string) []string {
	if value == "" {
		return nil
	}
	items := strings.Split(value, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}
	return items
}
