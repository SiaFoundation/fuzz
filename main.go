package main

import (
	"crypto/ed25519"
	"log"
	"math/rand"
	"time"

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

	sces   map[types.SiacoinOutputID]types.SiacoinElement
	sfes   map[types.SiafundOutputID]types.SiafundElement
	v2fces map[types.FileContractID]types.V2FileContractElement
}

func newFuzzer(rng *rand.Rand, pk types.PrivateKey) *fuzzer {
	uc := types.StandardUnlockConditions(pk.PublicKey())
	addr := uc.UnlockHash()

	n := newTestChain(false, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 10000
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr
	})

	f := &fuzzer{
		n: n,

		rng: rng,

		pk:     pk,
		uc:     uc,
		addr:   addr,
		policy: types.SpendPolicy(types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc)}),

		sces:   make(map[types.SiacoinOutputID]types.SiacoinElement),
		sfes:   make(map[types.SiafundOutputID]types.SiafundElement),
		v2fces: make(map[types.FileContractID]types.V2FileContractElement),
	}

	bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(n.genesis().Transactions))}
	_, au := consensus.ApplyBlock(n.network.GenesisState(), n.genesis(), bs, time.Time{})
	f.processApplyUpdate(au)

	return f
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

	for id, sce := range f.sces {
		au.UpdateElementProof(&sce.StateElement)
		f.sces[id] = sce.Copy()
	}

	for id, sfe := range f.sfes {
		au.UpdateElementProof(&sfe.StateElement)
		f.sfes[id] = sfe.Copy()
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

	for id, sce := range f.sces {
		ru.UpdateElementProof(&sce.StateElement)
		f.sces[id] = sce.Copy()
	}
	for id, sfe := range f.sfes {
		ru.UpdateElementProof(&sfe.StateElement)
		f.sfes[id] = sfe.Copy()
	}
}

func (f *fuzzer) generateTransaction() (txn types.Transaction) {
	{
		var amount types.Currency
		for i := 0; i < f.rng.Intn(3); i++ {
			sco := types.SiacoinOutput{
				Address: f.addr,
				Value:   types.NewCurrency64(1),
			}

			amount = amount.Add(sco.Value)
			txn.SiacoinOutputs = append(txn.SiacoinOutputs, sco)
		}
		if amount.Cmp(types.ZeroCurrency) == 1 {
			var sum types.Currency
			for id, sce := range f.sces {
				sum = sum.Add(sce.SiacoinOutput.Value)
				txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
					ParentID:         id,
					UnlockConditions: f.uc,
				})
				delete(f.sces, id)

				if sum.Cmp(amount) >= 0 {
					break
				}
			}
			if sum.Cmp(amount) == 1 {
				txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
					Address: f.addr,
					Value:   sum.Sub(amount),
				})
			}
		}
	}
	{
		var amount uint64
		for i := 0; i < f.rng.Intn(3); i++ {
			sfo := types.SiafundOutput{
				Address: f.addr,
				Value:   1,
			}

			amount += sfo.Value
			txn.SiafundOutputs = append(txn.SiafundOutputs, sfo)
		}
		if amount > 0 {
			var sum uint64
			for id, sfe := range f.sfes {
				sum += sfe.SiafundOutput.Value
				txn.SiafundInputs = append(txn.SiafundInputs, types.SiafundInput{
					ParentID:         id,
					UnlockConditions: f.uc,
				})
				delete(f.sfes, id)

				if sum >= amount {
					break
				}
			}
			if sum > amount {
				txn.SiafundOutputs = append(txn.SiafundOutputs, types.SiafundOutput{
					Address: f.addr,
					Value:   sum - amount,
				})
			}
		}
	}
	signTransactionWithContracts(f.n.tipState(), f.pk, f.pk, f.pk, &txn)

	for i, sco := range txn.SiacoinOutputs {
		id := txn.SiacoinOutputID(i)
		f.sces[id] = types.SiacoinElement{
			ID: id,
			StateElement: types.StateElement{
				LeafIndex: types.UnassignedLeafIndex,
			},
			SiacoinOutput: sco,
		}
	}
	for i, sfo := range txn.SiafundOutputs {
		id := txn.SiafundOutputID(i)
		f.sfes[id] = types.SiafundElement{
			ID: id,
			StateElement: types.StateElement{
				LeafIndex: types.UnassignedLeafIndex,
			},
			SiafundOutput: sfo,
		}
	}
	return
}

func (f *fuzzer) generateV2Transaction() (txn types.V2Transaction) {
	{
		var amount types.Currency
		for i := 0; i < f.rng.Intn(3); i++ {
			sco := types.SiacoinOutput{
				Address: f.addr,
				Value:   types.NewCurrency64(1),
			}

			amount = amount.Add(sco.Value)
			txn.SiacoinOutputs = append(txn.SiacoinOutputs, sco)
		}
		if amount.Cmp(types.ZeroCurrency) == 1 {
			var sum types.Currency
			for id, sce := range f.sces {
				sum = sum.Add(sce.SiacoinOutput.Value)
				txn.SiacoinInputs = append(txn.SiacoinInputs, types.V2SiacoinInput{
					Parent:          sce,
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: f.policy},
				})
				delete(f.sces, id)

				if sum.Cmp(amount) >= 0 {
					break
				}
			}
			if sum.Cmp(amount) == 1 {
				txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
					Address: f.addr,
					Value:   sum.Sub(amount),
				})
			}
		}
	}
	{
		var amount uint64
		for i := 0; i < f.rng.Intn(3); i++ {
			sfo := types.SiafundOutput{
				Address: f.addr,
				Value:   1,
			}

			amount += sfo.Value
			txn.SiafundOutputs = append(txn.SiafundOutputs, sfo)
		}
		if amount > 0 {
			var sum uint64
			for id, sfe := range f.sfes {
				sum += sfe.SiafundOutput.Value
				txn.SiafundInputs = append(txn.SiafundInputs, types.V2SiafundInput{
					Parent:          sfe,
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: f.policy},
				})
				delete(f.sfes, id)

				if sum >= amount {
					break
				}
			}
			if sum > amount {
				txn.SiafundOutputs = append(txn.SiafundOutputs, types.SiafundOutput{
					Address: f.addr,
					Value:   sum - amount,
				})
			}
		}
	}
	// so we don't get "transactions cannot be empty"
	txn.ArbitraryData = []byte("1234")
	signV2TransactionWithContracts(f.n.tipState(), f.pk, f.pk, f.pk, &txn)

	for i := range txn.SiacoinOutputs {
		sce := txn.EphemeralSiacoinOutput(i)
		f.sces[sce.ID] = sce
	}
	for i := range txn.SiafundOutputs {
		sfe := txn.EphemeralSiafundOutput(i)
		f.sfes[sfe.ID] = sfe
	}
	return
}

func (f *fuzzer) mineBlock() {
	var txns []types.Transaction
	for i := 0; i < f.rng.Intn(10); i++ {
		txns = append(txns, f.generateTransaction())
	}
	var v2Txns []types.V2Transaction
	for i := 0; i < f.rng.Intn(10); i++ {
		v2Txns = append(v2Txns, f.generateV2Transaction())
	}

	b := mineBlock(f.n.tipState(), txns, v2Txns, types.VoidAddress)
	au := f.n.applyBlock(b)
	f.processApplyUpdate(au)
}

func (f *fuzzer) revertBlock() {
	ru := f.n.revertBlock()
	f.processRevertUpdate(ru)
}

func main() {
	rng := rand.New(rand.NewSource(1))

	seed := make([]byte, ed25519.SeedSize)
	rng.Read(seed)
	pk := types.NewPrivateKeyFromSeed(seed)
	f := newFuzzer(rng, pk)

	for i := 0; i < 500; i++ {
		log.Println("Mining:", i)
		f.mineBlock()

		if rng.Float64() < 0.2 {
			log.Println("Reverting:", i)
			f.revertBlock()
		}
	}
}
