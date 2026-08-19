package main

import (
	"fmt"
	"log"
	"os"

	aster "defenseunicorns.com/aster/mesh"
)

func main() {
	bundle, err := os.ReadFile("provisioning.bundle")
	if err != nil {
		log.Fatal(err)
	}
	node, err := aster.Open("aster-example.db", bundle)
	if err != nil {
		log.Fatal(err)
	}
	defer node.Close()
	subscription, err := node.Subscribe("position.current", "mission/team/alpha", nil, false)
	if err != nil {
		log.Fatal(err)
	}
	receipt, err := node.Publish(
		aster.State, "position.current", "mission/team/alpha",
		[]byte(`{"lat":38.9,"lon":-77.0}`),
		aster.PublishOptions{LogicalKey: []byte("unit-7"), Priority: aster.Immediate},
	)
	if err != nil {
		log.Fatal(err)
	}
	deliveries, err := subscription.Poll(1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x %s\n", receipt.ItemID, deliveries[0].Item.Payload)
	if err := subscription.Acknowledge(deliveries[0].Item.ItemID); err != nil {
		log.Fatal(err)
	}
}
