package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"log"
	"math"
	"math/rand"
	"os"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"lukechampine.com/flagg"
)

type block struct {
	Block    types.Block
	Reverted bool
}

type state struct {
	Genesis types.Block
	Network *consensus.Network

	Blocks []block
}

func stateHash(cs consensus.State) types.Hash256 {
	h := types.NewHasher()
	cs.EncodeTo(h.E)
	return h.Sum()
}

func fuzzCommand() {
	rng := rand.New(rand.NewSource(1))

	seed := make([]byte, ed25519.SeedSize)
	rng.Read(seed)
	pk := types.NewPrivateKeyFromSeed(seed)
	f := newFuzzer(rng, pk)

	s := state{
		Genesis: f.n.tipBlock(),
		Network: f.n.network,
	}
	defer func() {
		if err := recover(); err != nil {
			log.Println("Got crash:", err)
		}

		// write state to disk
		f, err := os.Create("crash.json")
		if err != nil {
			panic(err)
		}
		defer f.Close()

		if err := json.NewEncoder(f).Encode(s); err != nil {
			panic(err)
		}
	}()

	for i := 0; i < 1000; i++ {
		{
			b := f.mineBlock()
			log.Println("Mining:", f.n.tip().Height)
			log.Printf("Block ID: %v, current state: %v", b.ID(), stateHash(f.n.states[len(f.n.states)-1]))

			s.Blocks = append(s.Blocks, block{
				Block:    b,
				Reverted: false,
			})
			f.applyBlock(b)

			if f.n.tip().Height > 1 && f.prob(0.3) {
				log.Println("Reverting:", f.n.tip().Height)

				s.Blocks[len(s.Blocks)-1].Reverted = true
				f.revertBlock()
				f.applyBlock(b)
				f.revertBlock()
			}
		}
	}
}

func reproCommand(path string) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var s state
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		panic(err)
	}

	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), s.Network, s.Genesis, nil)
	if err != nil {
		panic(err)
	}

	blocks := []types.Block{s.Genesis}
	supplements := []consensus.V1BlockSupplement{{Transactions: make([]consensus.V1TransactionSupplement, len(s.Genesis.Transactions))}}
	states := []consensus.State{genesisState}

	apply := func(b types.Block) {
		cs := states[len(states)-1]
		bs := store.SupplementTipBlock(b)
		if cs.Index.Height != math.MaxUint64 {
			// don't validate genesis block
			if b.V2 != nil {
				log.Printf("Parent state: %v (%v), got commitment hash: %v", cs.Index, stateHash(cs), b.V2.Commitment)
				expected := cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())
				if b.V2.Commitment != expected {
					log.Fatalf("commitment hash mismatch: expected %v, got %v", expected, b.V2.Commitment)
				}
			}
			if err := consensus.ValidateBlock(cs, b, bs); err != nil {
				panic(err)
			}
		}

		cs, au := consensus.ApplyBlock(cs, b, bs, b.Timestamp)

		store.AddState(cs)
		store.AddBlock(b, &bs)
		store.ApplyBlock(cs, au)

		blocks = append(blocks, b)
		supplements = append(supplements, bs)
		states = append(states, cs)
	}

	revert := func() {
		b := blocks[len(blocks)-1]
		bs := supplements[len(supplements)-1]
		prevState := states[len(states)-2]

		ru := consensus.RevertBlock(prevState, b, bs)

		store.RevertBlock(prevState, ru)

		blocks = blocks[:len(blocks)-1]
		supplements = supplements[:len(supplements)-1]
		states = states[:len(states)-1]
	}

	for i, b := range s.Blocks {
		log.Println("Applying:", i)
		log.Printf("Block ID: %v, current state: %v", b.Block.ID(), stateHash(states[len(states)-1]))

		// apply block first
		apply(b.Block)
		if b.Reverted {
			log.Println("Reverting:", i)
			revert()
			apply(b.Block)
			revert()
		}
	}
}

func main() {
	// commands are just *flag.FlagSets
	var rootCmd *flag.FlagSet = flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, "Sia core fuzzer")

	fuzzCmd := flagg.New("fuzz", "Randomly generate blocks")
	reproCmd := flagg.New("repro", "Reproduce crash")

	// construct the command hierarchy
	tree := flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: fuzzCmd},
			{Cmd: reproCmd},
		},
	}

	cmd := flagg.Parse(tree)

	args := cmd.Args()
	switch cmd {
	case fuzzCmd:
		fuzzCommand()
	case reproCmd:
		for _, arg := range args {
			log.Println("Running:", arg)
			reproCommand(arg)
		}
	}

}
