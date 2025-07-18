package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"reflect"
	"sort"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"lukechampine.com/flagg"
)

type state struct {
	Genesis types.Block
	Network *consensus.Network

	Blocks []types.Block
}

func stateHash(cs consensus.State) types.Hash256 {
	h := types.NewHasher()
	cs.EncodeTo(h.E)
	return h.Sum()
}

func sortSupplement(bs *consensus.V1BlockSupplement) {
	sort.Slice(bs.ExpiringFileContracts, func(i, j int) bool {
		return bytes.Compare(bs.ExpiringFileContracts[i].ID[:], bs.ExpiringFileContracts[j].ID[:]) < 0
	})
}

func fuzzCommand(allowHeight, requireHeight, blocks uint64) error {
	rng := rand.New(rand.NewSource(1))

	seed := make([]byte, ed25519.SeedSize)
	rng.Read(seed)
	pk := types.NewPrivateKeyFromSeed(seed)
	f, err := newFuzzer(rng, pk, allowHeight, requireHeight)
	if err != nil {
		return err
	}
	defer f.Close()

	s := state{
		Genesis: f.n.blocks[0],
		Network: f.n.network,
		Blocks:  f.n.blocks[1:], // don't include genesis
	}

	defer func() {
		// write state to disk
		file, err := os.Create("repro.json")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		if err := json.NewEncoder(file).Encode(s); err != nil {
			panic(err)
		}

		if err := recover(); err != nil {
			panic(err)
		}
	}()

	for range blocks {
		{
			b := f.mineBlock()
			log.Println("Mining:", f.n.tip().Height)
			log.Printf("Block ID: %v, current state: %v", b.ID(), stateHash(f.n.tipState()))

			s.Blocks = append(s.Blocks, b)

			bs1 := f.n.store.SupplementTipBlock(types.Block{})
			if err := f.applyBlock(b); err != nil {
				return fmt.Errorf("failed to apply block: %w", err)
			}
			bs2 := f.n.store.SupplementTipBlock(types.Block{})
			f.revertBlock()
			bs3 := f.n.store.SupplementTipBlock(types.Block{})
			if err := f.applyBlock(b); err != nil {
				return fmt.Errorf("failed to re-apply block: %w", err)
			}
			bs4 := f.n.store.SupplementTipBlock(types.Block{})

			sortSupplement(&bs1)
			sortSupplement(&bs2)
			sortSupplement(&bs3)
			sortSupplement(&bs4)
			if !reflect.DeepEqual(bs1, bs3) || !reflect.DeepEqual(bs2, bs4) {
				return fmt.Errorf("mismatched block supplement, run `./fuzzer repro repro.json`")
			}
		}
	}

	// revert all blocks then reapply and see if we end up with same state
	state := f.n.tipState()
	for range len(s.Blocks) {
		log.Println("Reverting:", f.n.tip())
		f.revertBlock()
	}
	for _, b := range s.Blocks {
		if err := f.applyBlock(b); err != nil {
			return fmt.Errorf("failed to apply block after reverting all: %w", err)
		}
		log.Println("Re-applied:", f.n.tip())
	}

	newState := f.n.tipState()
	if state != newState {
		return fmt.Errorf("mismatched state hash after reverting all and reapplying, expected %v, got %v", state, newState)
	}

	return nil
}

func reproCommand(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var s state
	if err := json.NewDecoder(file).Decode(&s); err != nil {
		return err
	}

	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), s.Network, s.Genesis, nil)
	if err != nil {
		return err
	}

	blocks := []types.Block{s.Genesis}
	supplements := []consensus.V1BlockSupplement{{Transactions: make([]consensus.V1TransactionSupplement, len(s.Genesis.Transactions))}}
	states := []consensus.State{genesisState}

	apply := func(b types.Block) error {
		cs := states[len(states)-1]
		bs := store.SupplementTipBlock(b)
		if cs.Index.Height != math.MaxUint64 {
			// don't validate genesis block
			if err := consensus.ValidateBlock(cs, b, bs); err != nil {
				return err
			}
		}

		cs, au := consensus.ApplyBlock(cs, b, bs, b.Timestamp)

		store.AddState(cs)
		store.AddBlock(b, &bs)
		store.ApplyBlock(cs, au)

		blocks = append(blocks, b)
		supplements = append(supplements, bs)
		states = append(states, cs)

		return nil
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
		log.Printf("Block ID: %v, current state: %v", b.ID(), stateHash(states[len(states)-1]))

		bs1 := store.SupplementTipBlock(types.Block{})
		if err := apply(b); err != nil {
			return fmt.Errorf("failed to apply block: %w", err)
		}
		bs2 := store.SupplementTipBlock(types.Block{})
		revert()
		bs3 := store.SupplementTipBlock(types.Block{})
		if err := apply(b); err != nil {
			return fmt.Errorf("failed to apply block: %w", err)
		}
		bs4 := store.SupplementTipBlock(types.Block{})

		sortSupplement(&bs1)
		sortSupplement(&bs2)
		sortSupplement(&bs3)
		sortSupplement(&bs4)
		if !reflect.DeepEqual(bs1, bs3) || !reflect.DeepEqual(bs2, bs4) {
			file, err := os.Create("bs.json")
			if err != nil {
				return err
			}
			defer file.Close()

			if err := json.NewEncoder(file).Encode([]consensus.V1BlockSupplement{bs1, bs2, bs3, bs4}); err != nil {
				return err
			}
			return fmt.Errorf("repro: mismatched block supplement, wrote bs1, bs2, bs3, bs4 to bs.json")
		}
	}

	return nil
}

func main() {
	// commands are just *flag.FlagSets
	var rootCmd *flag.FlagSet = flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, "Sia core fuzzer")

	fuzzCmd := flagg.New("fuzz", "Randomly generate blocks")
	allowHeight := fuzzCmd.Uint64("allowHeight", 250, "v2 hardfork allow height")
	requireHeight := fuzzCmd.Uint64("requireHeight", 400, "v2 hardfork require height")
	blocks := fuzzCmd.Uint64("blocks", 500, "number of blocks to randomly generate")

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
		if err := fuzzCommand(*allowHeight, *requireHeight, *blocks); err != nil {
			panic(err)
		}
	case reproCmd:
		for _, arg := range args {
			log.Println("Running:", arg)
			if err := reproCommand(arg); err != nil {
				panic(err)
			}
		}
	}

}
