// Command cctools serves customizable Clash configs aggregated from multiple
// subscription upstreams.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/frezcirno/cctools/internal/server"
)

const defaultListenAddr = "127.0.0.1:9000"

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           server.New(os.Getenv("TOKEN")).Handler(),
		ReadHeaderTimeout: 10 * time.Second, // primary Slowloris defense
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second, // generous: config generation fetches upstreams
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	idleClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
		close(idleClosed)
	}()

	log.Printf("Starting server on %s...\n", listenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-idleClosed
}
