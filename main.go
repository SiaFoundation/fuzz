package main

import (
	"log"
	"math/rand"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

type fuzzer struct {
	rng *rand.Rand
	n   *testChain

	pk   types.PrivateKey
	uc   types.UnlockConditions
	addr types.Address

	sces map[types.SiacoinOutputID]types.SiacoinElement
	sfes map[types.SiafundOutputID]types.SiafundElement
	fces map[types.FileContractID]types.FileContractElement
}

func newFuzzer(rng *rand.Rand, pk types.PrivateKey) *fuzzer {
	uc := types.StandardUnlockConditions(pk.PublicKey())
	addr := uc.UnlockHash()

	n := newTestChain(false, func(network *consensus.Network, genesisBlock types.Block) {
		genesisBlock.Transactions[0].SiacoinOutputs[0].Address = addr
		genesisBlock.Transactions[0].SiafundOutputs[0].Address = addr
	})

	f := &fuzzer{
		n: n,

		rng: rng,

		pk:   pk,
		uc:   uc,
		addr: addr,

		sces: make(map[types.SiacoinOutputID]types.SiacoinElement),
		sfes: make(map[types.SiafundOutputID]types.SiafundElement),
		fces: make(map[types.FileContractID]types.FileContractElement),
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
		}

		id := diff.SiacoinElement.ID
		if diff.Spent {
			delete(f.sces, id)
		} else {
			f.sces[id] = diff.SiacoinElement
		}
	}
	for _, diff := range au.SiafundElementDiffs() {
		if diff.SiafundElement.SiafundOutput.Address != f.addr {
			continue
		}

		id := diff.SiafundElement.ID
		if diff.Spent {
			delete(f.sfes, id)
		} else {
			f.sfes[id] = diff.SiafundElement
		}
	}
}

func (f *fuzzer) processRevertUpdate(ru consensus.RevertUpdate) {
	for _, diff := range ru.SiacoinElementDiffs() {
		if diff.SiacoinElement.SiacoinOutput.Address != f.addr {
			continue
		}

		id := diff.SiacoinElement.ID
		if diff.Spent {
			f.sces[id] = diff.SiacoinElement
		} else {
			delete(f.sces, id)
		}
	}
	for _, diff := range ru.SiafundElementDiffs() {
		if diff.SiafundElement.SiafundOutput.Address != f.addr {
			continue
		}

		id := diff.SiafundElement.ID
		if diff.Spent {
			f.sfes[id] = diff.SiafundElement
		} else {
			delete(f.sfes, id)
		}
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

func (f *fuzzer) mineBlock() {
	var txns []types.Transaction
	for i := 0; i < f.rng.Intn(10); i++ {
		txns = append(txns, f.generateTransaction())
	}

	b := mineBlock(f.n.tipState(), txns, nil, types.VoidAddress)
	au := f.n.applyBlock(b)
	f.processApplyUpdate(au)
}

func (f *fuzzer) revertBlock() {
	ru := f.n.revertBlock()
	f.processRevertUpdate(ru)
}

func main() {
	f := newFuzzer(rand.New(rand.NewSource(1)), types.GeneratePrivateKey())

	for i := 0; i < 100; i++ {
		log.Println(i)
		f.mineBlock()
	}
}
