package main

import (
	"crypto/ed25519"
	"log"
	"math/rand"

	"go.sia.tech/core/types"
)

func main() {
	rng := rand.New(rand.NewSource(1))

	seed := make([]byte, ed25519.SeedSize)
	rng.Read(seed)
	pk := types.NewPrivateKeyFromSeed(seed)
	f := newFuzzer(rng, pk)

	for i := 0; i < 10000; i++ {
		if f.n.tip().Height > 1 && f.prob(0.3) {
			log.Println("Reverting:", f.n.tip().Height)

			b := f.n.tipBlock()
			f.revertBlock()
			f.applyBlock(b)
			f.revertBlock()
		} else {
			log.Println("Mining:", f.n.tip().Height)
			f.mineBlock()
		}
	}
}
