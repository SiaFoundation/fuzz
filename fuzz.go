package main

import (
	"math"
	"math/rand"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

type fuzzer struct {
	rng *rand.Rand
	n   *testChain

	pk     types.PrivateKey
	uc     types.UnlockConditions
	addr   types.Address
	policy types.SpendPolicy

	cies   []types.ChainIndexElement
	sces   map[types.SiacoinOutputID]types.SiacoinElement
	sfes   map[types.SiafundOutputID]types.SiafundElement
	fces   map[types.FileContractID]types.FileContractElement
	v2fces map[types.FileContractID]types.V2FileContractElement
}

func newFuzzer(rng *rand.Rand, pk types.PrivateKey, allowHeight, requireHeight uint64) (*fuzzer, error) {
	uc := types.StandardUnlockConditions(pk.PublicKey())
	addr := uc.UnlockHash()

	n, err := newTestChain(func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = allowHeight
		network.HardforkV2.RequireHeight = requireHeight
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr
	})
	if err != nil {
		return nil, err
	}

	f := &fuzzer{
		n: n,

		rng: rng,

		pk:     pk,
		uc:     uc,
		addr:   addr,
		policy: types.SpendPolicy(types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc)}),

		sces:   make(map[types.SiacoinOutputID]types.SiacoinElement),
		sfes:   make(map[types.SiafundOutputID]types.SiafundElement),
		fces:   make(map[types.FileContractID]types.FileContractElement),
		v2fces: make(map[types.FileContractID]types.V2FileContractElement),
	}

	for i := range f.n.blocks {
		cs := f.n.states[i]
		b := f.n.blocks[i]
		bs := f.n.supplements[i]

		if cs.Index.Height != math.MaxUint64 {
			// don't validate genesis block
			if err := consensus.ValidateBlock(cs, b, bs); err != nil {
				return nil, err
			}
		}
		_, au := consensus.ApplyBlock(cs, b, bs, b.Timestamp)
		f.processApplyUpdate(au)
	}

	return f, nil
}

func (f *fuzzer) Close() error {
	return f.n.Close()
}

func (f *fuzzer) applyBlock(b types.Block) error {
	au, err := f.n.applyBlock(b)
	if err != nil {
		return err
	}
	f.processApplyUpdate(au)
	return nil
}

func (f *fuzzer) revertBlock() {
	ru := f.n.revertBlock()
	f.processRevertUpdate(ru)
}

func (f *fuzzer) mineBlock() types.Block {
	var txns []types.Transaction
	if f.n.tip().Height < (f.n.network.HardforkV2.RequireHeight - 1) {
		for i := 0; i < f.rng.Intn(20); i++ {
			txns = append(txns, f.generateTransaction())
		}
	}

	var v2Txns []types.V2Transaction
	if f.n.tip().Height >= f.n.network.HardforkV2.AllowHeight {
		// we modify f.v2fces as we go and revise contracts but the Parent
		// field must be the parent at the start of the block for all revisions
		// in a block even if there are multiple
		originalParents := make(map[types.FileContractID]types.V2FileContractElement)
		for i := 0; i < f.rng.Intn(20); i++ {
			v2Txns = append(v2Txns, f.generateV2Transaction(originalParents))
		}
	}

	return mineBlock(f.n.tipState(), txns, v2Txns, types.VoidAddress)
}

func (f *fuzzer) processApplyUpdate(au consensus.ApplyUpdate) {
	for _, diff := range au.SiacoinElementDiffs() {
		if diff.SiacoinElement.SiacoinOutput.Address != f.addr {
			continue
		} else if diff.Created && diff.Spent {
			continue
		}

		id := diff.SiacoinElement.ID
		if diff.Spent {
			delete(f.sces, id)
		} else {
			f.sces[id] = diff.SiacoinElement.Copy()
		}
	}
	for _, diff := range au.SiafundElementDiffs() {
		if diff.SiafundElement.SiafundOutput.Address != f.addr {
			continue
		} else if diff.Created && diff.Spent {
			continue
		}

		id := diff.SiafundElement.ID
		if diff.Spent {
			delete(f.sfes, id)
		} else {
			f.sfes[id] = diff.SiafundElement.Copy()
		}
	}
	for _, diff := range au.FileContractElementDiffs() {
		id := diff.FileContractElement.ID
		if diff.Created {
			f.fces[id] = diff.FileContractElement.Copy()
		} else if diff.Revision != nil {
			diff.FileContractElement.FileContract = *diff.Revision
			f.fces[id] = diff.FileContractElement.Copy()
		} else if diff.Resolved {
			delete(f.fces, id)
		}
	}
	for _, diff := range au.V2FileContractElementDiffs() {
		id := diff.V2FileContractElement.ID
		if diff.Created {
			f.v2fces[id] = diff.V2FileContractElement.Copy()
		} else if diff.Revision != nil {
			diff.V2FileContractElement.V2FileContract = *diff.Revision
			f.v2fces[id] = diff.V2FileContractElement.Copy()
		} else if diff.Resolution != nil {
			delete(f.v2fces, id)
		}
	}
	f.cies = append(f.cies, au.ChainIndexElement().Copy())

	for id, sce := range f.sces {
		au.UpdateElementProof(&sce.StateElement)
		f.sces[id] = sce.Copy()
	}
	for id, sfe := range f.sfes {
		au.UpdateElementProof(&sfe.StateElement)
		f.sfes[id] = sfe.Copy()
	}
	for id, fce := range f.fces {
		au.UpdateElementProof(&fce.StateElement)
		f.fces[id] = fce.Copy()
	}
	for id, fce := range f.v2fces {
		au.UpdateElementProof(&fce.StateElement)
		f.v2fces[id] = fce.Copy()
	}
	for i, cie := range f.cies {
		au.UpdateElementProof(&cie.StateElement)
		f.cies[i] = cie.Copy()
	}
}

func (f *fuzzer) processRevertUpdate(ru consensus.RevertUpdate) {
	for _, diff := range ru.SiacoinElementDiffs() {
		if diff.SiacoinElement.SiacoinOutput.Address != f.addr {
			continue
		} else if diff.Created && diff.Spent {
			continue
		}

		id := diff.SiacoinElement.ID
		if diff.Spent {
			f.sces[id] = diff.SiacoinElement.Copy()
		} else {
			delete(f.sces, id)
		}
	}
	for _, diff := range ru.SiafundElementDiffs() {
		if diff.SiafundElement.SiafundOutput.Address != f.addr {
			continue
		} else if diff.Created && diff.Spent {
			continue
		}

		id := diff.SiafundElement.ID
		if diff.Spent {
			f.sfes[id] = diff.SiafundElement.Copy()
		} else {
			delete(f.sfes, id)
		}
	}
	for _, diff := range ru.FileContractElementDiffs() {
		id := diff.FileContractElement.ID
		if diff.Created {
			delete(f.fces, id)
		} else if diff.Revision != nil {
			f.fces[id] = diff.FileContractElement.Copy()
		} else if diff.Resolved {
			f.fces[id] = diff.FileContractElement.Copy()
		}
	}
	for _, diff := range ru.V2FileContractElementDiffs() {
		id := diff.V2FileContractElement.ID
		if diff.Created {
			delete(f.v2fces, id)
		} else if diff.Revision != nil {
			f.v2fces[id] = diff.V2FileContractElement.Copy()
		} else if diff.Resolution != nil {
			f.v2fces[id] = diff.V2FileContractElement.Copy()
		}
	}
	f.cies = f.cies[:len(f.cies)-1]

	for id, sce := range f.sces {
		ru.UpdateElementProof(&sce.StateElement)
		f.sces[id] = sce.Copy()
	}
	for id, sfe := range f.sfes {
		ru.UpdateElementProof(&sfe.StateElement)
		f.sfes[id] = sfe.Copy()
	}
	for id, fce := range f.fces {
		ru.UpdateElementProof(&fce.StateElement)
		f.fces[id] = fce.Copy()
	}
	for id, fce := range f.v2fces {
		ru.UpdateElementProof(&fce.StateElement)
		f.v2fces[id] = fce.Copy()
	}
	for i, cie := range f.cies {
		ru.UpdateElementProof(&cie.StateElement)
		f.cies[i] = cie.Copy()
	}
}
