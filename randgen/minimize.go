package randgen

import (
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

type Crasher struct {
	Network    *consensus.Network `json:"network"`
	CrashIndex int                `json:"crashIndex"`
	Genesis    types.Block        `json:"genesis"`
	Blocks     []types.Block      `json:"blocks"`
}

func (c Crasher) MemChainManager() *chain.Manager {
	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), c.Network, c.Genesis)
	if err != nil {
		panic(err)
	}
	return chain.NewManager(store, genesisState)
}

func Minimize(c *Crasher, fn func(Crasher)) {
	panics := func(bi, ti int) (panicked bool) {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()

		c := *c
		c.Blocks = append([]types.Block(nil), c.Blocks...)
		for i := range c.Blocks {
			c.Blocks[i].Transactions = append([]types.Transaction(nil), c.Blocks[i].Transactions...)
		}
		c.Blocks[bi].Transactions = append(c.Blocks[bi].Transactions[:ti], c.Blocks[bi].Transactions[ti+1:]...)

		// block data has changed, so we need to redo the PoW and fixup the parent IDs
		cm := c.MemChainManager()
		for i := range c.Blocks {
			c.Blocks[i].ParentID = cm.Tip().ID
			findBlockNonce(cm.TipState(), &c.Blocks[i])
			if err := cm.AddBlocks([]types.Block{c.Blocks[i]}); err != nil {
				return // not a panic, just invalid
			}
		}

		fn(c)
		return
	}

	for i := len(c.Blocks) - 1; i >= 0; i-- {
		for j := len(c.Blocks[i].Transactions) - 1; j >= 0; j-- {
			if panics(i, j) {
				c.Blocks[i].Transactions = append(c.Blocks[i].Transactions[:j], c.Blocks[i].Transactions[j+1:]...)
				j--
			}
		}
	}
}
