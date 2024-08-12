package main

import (
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/fuzz/randgen"
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
	n.HardforkV2.AllowHeight = 100000
	n.HardforkV2.RequireHeight = 200000
	b := types.Block{Timestamp: n.HardforkOak.GenesisTimestamp}
	return n, b
}

func main() {
	n, genesisBlock := testnet()

	n.HardforkTax.Height = 0
	n.HardforkFoundation.Height = 0
	n.InitialTarget = types.BlockID{0xFF}

	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)

	var pks []types.PrivateKey
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
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

	dir, err := os.MkdirTemp(os.TempDir(), "randgen")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(dir, "consensus.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer bdb.Close()

	store, genesisState, err := chain.NewDBStore(bdb, n, genesisBlock)
	if err != nil {
		log.Fatal(err)
	}

	cm := chain.NewManager(store, genesisState)

	// file, err := os.Open("blocks.json")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer file.Close()

	// var blocks []types.Block
	// if err := json.NewDecoder(file).Decode(&blocks); err != nil {
	// 	log.Fatal(err)
	// }

	// if err := cm.AddBlocks(blocks[:2]); err != nil {
	// 	log.Fatal(err)
	// }
	// if err := cm.AddBlocks([]types.Block{blocks[2]}); err != nil {
	// 	// crash HERE
	// 	log.Fatal(err)
	// }

	f := randgen.NewFuzzer(rng, n, cm, pks)
	f.Run(1e7)
}
