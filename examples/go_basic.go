package main

// Offline publish/subscribe with Aster's Go application binding.

import (
	"fmt"
	"log"
	"os"

	aster "defenseunicorns.com/aster/mesh"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s PROVISIONING_BUNDLE DATABASE", os.Args[0])
	}

	// The authority-issued bundle gives this node its identity and permitted
	// scopes/topics. Applications pass it through as opaque bytes.
	bundle, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// The database holds publications, causal state, and subscription progress.
	// Close the native node even though the Go wrapper has a finalizer backstop.
	node, err := aster.Open(os.Args[2], bundle)
	if err != nil {
		log.Fatal(err)
	}
	defer node.Close()

	// Subscribe before publishing so the local commit uses the same durable,
	// at-least-once delivery path as an item received from another node.
	subscription, err := node.Subscribe(
		"position.current", "mission/team/alpha", nil, false,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Publish works with no peer or network. State uses LogicalKey to identify
	// the entity whose current value is being replaced.
	ttlMillis := uint64(60_000)
	receipt, err := node.Publish(
		aster.State,
		"position.current",
		"mission/team/alpha",
		[]byte(`{"lat":38.9,"lon":-77.0}`),
		aster.PublishOptions{
			LogicalKey: []byte("unit-7"),
			Priority:   aster.Immediate,
			TTLMillis:  &ttlMillis, // Expiry is independent of priority.
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	deliveries, err := subscription.Poll(1)
	if err != nil {
		log.Fatal(err)
	}
	if len(deliveries) == 0 {
		log.Fatal("the local publication was not delivered")
	}

	fmt.Printf("item=%x payload=%s\n", receipt.ItemID, deliveries[0].Item.Payload)

	// Acknowledge only after application processing succeeds. Until then Aster
	// may redeliver the item after a restart.
	if err := subscription.Acknowledge(deliveries[0].Item.ItemID); err != nil {
		log.Fatal(err)
	}
}
