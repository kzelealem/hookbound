package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/hookbound/hookbound"
	"github.com/hookbound/hookbound/standard"
)

func main() {
	keys, err := standard.StaticHMACKeys(os.Getenv("HOOKBOUND_SECRET"))
	if err != nil {
		log.Fatal(err)
	}
	signer, err := standard.NewHMACSigner(keys)
	if err != nil {
		log.Fatal(err)
	}
	sender, err := hookbound.NewSender(hookbound.SenderConfig{Signer: signer})
	if err != nil {
		log.Fatal(err)
	}
	body, err := hookbound.JSONBody(map[string]any{
		"type": "invoice.paid.v1",
		"data": map[string]string{"invoice_id": "inv_123"},
	})
	if err != nil {
		log.Fatal(err)
	}
	result, err := sender.Send(context.Background(), hookbound.SendRequest{
		URL: "https://customer.example/webhooks", EventType: "invoice.paid.v1", Body: body,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("message=%s outcome=%s status=%d\n", result.MessageID, result.Outcome, result.StatusCode)
}
