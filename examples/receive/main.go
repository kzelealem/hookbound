package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/hookbound/hookbound"
	"github.com/hookbound/hookbound/standard"
)

type invoicePaid struct {
	Type string `json:"type"`
	Data struct {
		InvoiceID string `json:"invoice_id"`
	} `json:"data"`
}

func main() {
	keys, err := standard.StaticHMACKeys(os.Getenv("HOOKBOUND_SECRET"))
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := standard.NewHMACVerifier(keys)
	if err != nil {
		log.Fatal(err)
	}
	registry := hookbound.NewRegistry()
	if err := hookbound.HandleJSON(registry, "invoice.paid.v1", func(_ context.Context, message hookbound.Message[invoicePaid]) error {
		log.Printf("verified invoice %s from %s", message.Data.Data.InvoiceID, message.Source)
		return nil
	}); err != nil {
		log.Fatal(err)
	}
	receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier: verifier, Handler: registry, ReplayGuard: hookbound.NewMemoryReplayGuard(10_000, nil),
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /webhooks", receiver)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
