package crashers

import (
	"encoding/json"
	"os"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

type Crasher struct {
	Network *consensus.Network `json:"network"`
	Genesis types.Block        `json:"genesis"`
	Blocks  []types.Block      `json:"blocks"`
}

func loadCrasher(t *testing.T, path string) (c Crasher) {
	js, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(js, &c); err != nil {
		t.Fatal(err)
	}
	return
}

func TestCoreutils_fee4ef5a(t *testing.T) {
	c := loadCrasher(t, "coreutils-fee4ef5a.json")

	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), c.Network, c.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, genesisState)
	if err := cm.AddBlocks(c.Blocks[:2]); err != nil {
		t.Fatal(err)
	}
	if err := cm.AddBlocks(c.Blocks[2:]); err != nil {
		t.Fatal(err)
	}
}
