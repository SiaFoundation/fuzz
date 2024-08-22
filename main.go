package main

import (
	"encoding/json"
	"flag"
	"log"
	"math/rand"
	"os"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/fuzz/randgen"
	"lukechampine.com/flagg"
)

func testnet() (*consensus.Network, types.Block) {
	n := &consensus.Network{
		Name:            "testnet",
		InitialCoinbase: types.Siacoins(300000),
		MinimumCoinbase: types.Siacoins(300000),
		InitialTarget:   types.BlockID{0xFF},
	}
	n.HardforkDevAddr.Height = 10
	n.HardforkTax.Height = 20
	n.HardforkStorageProof.Height = 30
	n.HardforkOak.Height = 40
	n.HardforkOak.FixHeight = 50
	n.HardforkOak.GenesisTimestamp = time.Unix(1618033988, 0) // φ
	n.HardforkASIC.Height = 60
	n.HardforkASIC.OakTime = 10000 * time.Second
	n.HardforkASIC.OakTarget = n.InitialTarget
	n.HardforkFoundation.Height = 70
	n.HardforkFoundation.PrimaryAddress = types.AnyoneCanSpend().Address()
	n.HardforkFoundation.FailsafeAddress = types.VoidAddress
	n.HardforkV2.AllowHeight = 100
	n.HardforkV2.RequireHeight = 200
	b := types.Block{Timestamp: n.HardforkOak.GenesisTimestamp}
	return n, b
}

func main() {
	var rootCmd *flag.FlagSet = flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, `Usage: fuzz [command] [args]

If no command is specified the fuzzer will be run with the default parameters.

Commands:
	fuzz run
	fuzz test input.json
	fuzz min input.json
`)

	// construct the command hierarchy
	runCmd := flagg.New("run", `Usage:
	fuzz run
Run the fuzzer.
`)
	seed := runCmd.Int64("seed", 1, "random number generator seed")
	iterations := runCmd.Int("iterations", 1e7, "number of blocks to generate with fuzzer")
	numberPks := runCmd.Int("pks", 20, "Number of accounts to use in the fuzzer.  Higher number means more transactions per block.")
	testCmd := flagg.New("test", `Usage:
	fuzz test input.json
Test a JSON encoded crasher and see if it crashes.
`)
	minCmd := flagg.New("min", `Usage:
	fuzz min input.json
Minimize a JSON encoded crasher to find the simplest combination of transactions that panics.
`)

	tree := flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: runCmd},
			{Cmd: testCmd},
			{Cmd: minCmd},
		},
	}

	cmd := flagg.Parse(tree)
	args := cmd.Args()

	switch cmd {
	case rootCmd, runCmd:
		n, genesisBlock := testnet()

		n.HardforkTax.Height = 0
		n.HardforkFoundation.Height = 0
		n.InitialTarget = types.BlockID{0xFF}

		giftAmountSC := types.Siacoins(100)
		giftAmountSF := uint64(100)

		var pks []types.PrivateKey
		rng := rand.New(rand.NewSource(*seed))
		for i := 0; i < *numberPks; i++ {
			var b [32]byte
			rng.Read(b[:])
			pks = append(pks, types.NewPrivateKeyFromSeed(b[:]))
		}

		for _, pk := range pks {
			addr := types.StandardUnlockConditions(pk.PublicKey()).UnlockHash()
			genesisBlock.Transactions = append(genesisBlock.Transactions, types.Transaction{
				SiacoinOutputs: []types.SiacoinOutput{
					{Address: addr, Value: giftAmountSC},
				},
				SiafundOutputs: []types.SiafundOutput{
					{Address: addr, Value: giftAmountSF},
				},
			})
		}

		store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), n, genesisBlock)
		if err != nil {
			log.Fatal(err)
		}
		cm := chain.NewManager(store, genesisState)

		f := randgen.NewFuzzer(rng, n, genesisBlock, store, cm, pks)
		f.Run(*iterations)
		break
	case testCmd:
		if len(args) == 0 {
			testCmd.Usage()
			return
		}

		file, err := os.Open(args[0])
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		var c randgen.Crasher
		if err := json.NewDecoder(file).Decode(&c); err != nil {
			log.Fatal(err)
		}

		cm := c.MemChainManager()
		if err := cm.AddBlocks(c.Blocks[:c.CrashIndex]); err != nil {
			log.Fatal(err)
		}
		if err := cm.AddBlocks(c.Blocks[c.CrashIndex:]); err != nil {
			log.Fatal(err)
		}
		break
	case minCmd:
		if len(args) == 0 {
			testCmd.Usage()
			return
		}

		var c randgen.Crasher
		func() {
			file, err := os.Open(args[0])
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()

			if err := json.NewDecoder(file).Decode(&c); err != nil {
				log.Fatal(err)
			}
		}()

		beforeTxns := 0
		for _, c := range c.Blocks {
			beforeTxns += len(c.Transactions)
		}

		fn := func(c randgen.Crasher) {
			cm := c.MemChainManager()

			log.Println(len(c.Blocks))
			if err := cm.AddBlocks(c.Blocks[:c.CrashIndex]); err != nil {
				log.Println(err)
				return
			}
			if err := cm.AddBlocks(c.Blocks[c.CrashIndex:]); err != nil {
				log.Println(err)
				return
			}
		}
		randgen.Minimize(&c, fn)

		afterTxns := 0
		for _, c := range c.Blocks {
			afterTxns += len(c.Transactions)
		}

		func() {
			file, err := os.Create(args[0] + ".min")
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()

			if err := json.NewEncoder(file).Encode(c); err != nil {
				log.Fatal(err)
			}
			defer file.Close()
		}()

		log.Printf("Wrote minimized %s (%d -> %d transactions)\n", args[0], beforeTxns, afterTxns)
		break
	}
}
