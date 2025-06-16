package main

import (
	"crypto/ed25519"
	"log"
	"math/rand"
	"time"

	proto2 "go.sia.tech/core/rhp/v2"
	proto4 "go.sia.tech/core/rhp/v4"

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

func newFuzzer(rng *rand.Rand, pk types.PrivateKey) *fuzzer {
	uc := types.StandardUnlockConditions(pk.PublicKey())
	addr := uc.UnlockHash()

	n := newTestChain(false, func(network *consensus.Network, genesisBlock types.Block) {
		network.HardforkV2.AllowHeight = 100
		network.HardforkV2.RequireHeight = 500
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
		fces:   make(map[types.FileContractID]types.FileContractElement),
		v2fces: make(map[types.FileContractID]types.V2FileContractElement),
	}

	bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(n.genesis().Transactions))}
	_, au := consensus.ApplyBlock(n.network.GenesisState(), n.genesis(), bs, time.Time{})
	f.processApplyUpdate(au)

	return f
}

func (f *fuzzer) prob(p float64) bool {
	return f.rng.Float64() < p
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
	f.cies = append(f.cies, au.ChainIndexElement())

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
		f.cies[i] = cie
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
		f.cies[i] = cie
	}
}

func prepareContract(addr types.Address, endHeight uint64) types.FileContract {
	rk := types.GeneratePrivateKey().PublicKey()
	rAddr := types.StandardUnlockHash(rk)
	hk := types.GeneratePrivateKey().PublicKey()
	hs := proto2.HostSettings{
		WindowSize: 1,
		Address:    types.StandardUnlockHash(hk),
	}
	sc := types.Siacoins(1)
	fc := proto2.PrepareContractFormation(rk, hk, sc.Mul64(2), sc.Mul64(2), endHeight, hs, rAddr)
	fc.UnlockHash = addr
	return fc
}

func (f *fuzzer) generateTransaction() (txn types.Transaction) {
	// {
	// 	count := f.rng.Intn(2)
	// 	for _, fce := range f.fces {
	// 		if len(txn.StorageProofs) >= count {
	// 			break
	// 		}

	// 		fc := fce.FileContract
	// 		height := f.n.tip().Height
	// 		if height < fc.WindowStart {
	// 			continue
	// 		}
	// 		txn.StorageProofs = append(txn.StorageProofs, types.StorageProof{
	// 			ParentID: fce.ID,
	// 		})
	// 		delete(f.fces, fce.ID)
	// 	}
	// 	if len(txn.StorageProofs) > 0 {
	// 		// can't have storage proofs and outputs in one transaction
	// 		return
	// 	}
	// }
	// var amount types.Currency
	// {
	// 	for i, count := 0, f.rng.Intn(3); i < count; i++ {
	// 		fc := prepareContract(f.addr, f.n.tip().Height+10)
	// 		txn.FileContracts = append(txn.FileContracts, fc)
	// 		amount = amount.Add(fc.Payout)
	// 	}
	// }
	// {
	// 	i := 0
	// 	count := f.rng.Intn(3)
	// 	for _, fce := range f.fces {
	// 		if i > count {
	// 			break
	// 		}

	// 		fc := fce.FileContract
	// 		height := f.n.tip().Height
	// 		if fc.WindowStart >= height {
	// 			continue
	// 		}
	// 		fc.RevisionNumber++
	// 		// fc.WindowStart = height + 1
	// 		// fc.WindowEnd = fc.WindowStart + 10
	// 		txn.FileContractRevisions = append(txn.FileContractRevisions, types.FileContractRevision{
	// 			ParentID:         fce.ID,
	// 			UnlockConditions: f.uc,
	// 			FileContract:     fc,
	// 		})
	// 		f.fces[fce.ID] = types.FileContractElement{
	// 			ID:           fce.ID,
	// 			StateElement: fce.StateElement,
	// 			FileContract: fc,
	// 		}

	// 		i++
	// 	}
	// }
	// {
	// 	for i, count := 0, f.rng.Intn(3); i < count; i++ {
	// 		sco := types.SiacoinOutput{
	// 			Address: f.addr,
	// 			Value:   types.NewCurrency64(1),
	// 		}

	// 		amount = amount.Add(sco.Value)
	// 		txn.SiacoinOutputs = append(txn.SiacoinOutputs, sco)
	// 	}
	// 	if amount.Cmp(types.ZeroCurrency) == 1 {
	// 		var sum types.Currency
	// 		for id, sce := range f.sces {
	// 			sum = sum.Add(sce.SiacoinOutput.Value)
	// 			txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
	// 				ParentID:         id,
	// 				UnlockConditions: f.uc,
	// 			})
	// 			delete(f.sces, id)

	// 			if sum.Cmp(amount) >= 0 {
	// 				break
	// 			}
	// 		}
	// 		if sum.Cmp(amount) == 1 {
	// 			txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
	// 				Address: f.addr,
	// 				Value:   sum.Sub(amount),
	// 			})
	// 		}
	// 	}
	// }
	// {
	// 	var amount uint64
	// 	for i, count := 0, f.rng.Intn(3); i < count; i++ {
	// 		sfo := types.SiafundOutput{
	// 			Address: f.addr,
	// 			Value:   1,
	// 		}

	// 		amount += sfo.Value
	// 		txn.SiafundOutputs = append(txn.SiafundOutputs, sfo)
	// 	}
	// 	if amount > 0 {
	// 		var sum uint64
	// 		for id, sfe := range f.sfes {
	// 			sum += sfe.SiafundOutput.Value
	// 			txn.SiafundInputs = append(txn.SiafundInputs, types.SiafundInput{
	// 				ParentID:         id,
	// 				UnlockConditions: f.uc,
	// 			})
	// 			delete(f.sfes, id)

	// 			if sum >= amount {
	// 				break
	// 			}
	// 		}
	// 		if sum > amount {
	// 			txn.SiafundOutputs = append(txn.SiafundOutputs, types.SiafundOutput{
	// 				Address: f.addr,
	// 				Value:   sum - amount,
	// 			})
	// 		}
	// 	}
	// }
	// signTransactionWithContracts(f.n.tipState(), f.pk, &txn)

	// for i, sco := range txn.SiacoinOutputs {
	// 	id := txn.SiacoinOutputID(i)
	// 	f.sces[id] = types.SiacoinElement{
	// 		ID: id,
	// 		StateElement: types.StateElement{
	// 			LeafIndex: types.UnassignedLeafIndex,
	// 		},
	// 		SiacoinOutput: sco,
	// 	}
	// }
	// for i, sfo := range txn.SiafundOutputs {
	// 	id := txn.SiafundOutputID(i)
	// 	f.sfes[id] = types.SiafundElement{
	// 		ID: id,
	// 		StateElement: types.StateElement{
	// 			LeafIndex: types.UnassignedLeafIndex,
	// 		},
	// 		SiafundOutput: sfo,
	// 	}
	// }
	// for i, fc := range txn.FileContracts {
	// 	id := txn.FileContractID(i)
	// 	f.fces[id] = types.FileContractElement{
	// 		ID: id,
	// 		StateElement: types.StateElement{
	// 			LeafIndex: types.UnassignedLeafIndex,
	// 		},
	// 		FileContract: fc,
	// 	}
	// }
	return
}

func payoutV2(fc types.V2FileContract) types.Currency {
	return fc.RenterOutput.Value.Add(fc.HostOutput.Value).Add(consensus.State{}.V2FileContractTax(fc))
}

func prepareV2Contract(renterPK, hostPK types.PrivateKey, proofHeight uint64) (types.V2FileContract, types.Currency) {
	fc, _ := proto4.NewContract(proto4.HostPrices{}, proto4.RPCFormContractParams{
		ProofHeight:     proofHeight,
		Allowance:       types.Siacoins(1),
		RenterAddress:   types.StandardUnlockConditions(renterPK.PublicKey()).UnlockHash(),
		Collateral:      types.Siacoins(1),
		RenterPublicKey: renterPK.PublicKey(),
	}, hostPK.PublicKey(), types.StandardUnlockConditions(hostPK.PublicKey()).UnlockHash())
	fc.ExpirationHeight = fc.ProofHeight + 1
	fc.RenterOutput.Address = types.VoidAddress
	fc.HostOutput.Address = types.VoidAddress

	return fc, payoutV2(fc)
}

func (f *fuzzer) generateV2Transaction(originalParents map[types.FileContractID]types.V2FileContractElement) (txn types.V2Transaction) {
	var amount types.Currency
	{
		for i, count := 0, f.rng.Intn(3); i < count; i++ {
			fc, payout := prepareV2Contract(f.pk, f.pk, f.n.tip().Height+10)

			amount = amount.Add(payout)
			txn.FileContracts = append(txn.FileContracts, fc)
		}
	}
	{
		i := 0
		count := f.rng.Intn(3)
		for id, fce := range f.v2fces {
			if i > count {
				break
			}

			fc := fce.V2FileContract
			height := f.n.tip().Height
			if height >= fc.ProofHeight {
				continue
			}
			fc.RevisionNumber++

			parent := fce
			if v, ok := originalParents[id]; ok {
				parent = v
			} else {
				originalParents[id] = parent
			}

			txn.FileContractRevisions = append(txn.FileContractRevisions, types.V2FileContractRevision{
				Parent:   parent,
				Revision: fc,
			})

			f.v2fces[id] = types.V2FileContractElement{
				ID:             id,
				StateElement:   fce.StateElement,
				V2FileContract: fc,
			}

			i++
		}
	}
	{
		i := 0
		count := f.rng.Intn(3)
		for id, fce := range f.v2fces {
			if i > count {
				break
			}

			fc := fce.V2FileContract
			height := f.n.tip().Height
			if height < fc.ProofHeight {
				continue
			}
			fc.RevisionNumber++

			parent := fce
			if v, ok := originalParents[id]; ok {
				parent = v
			} else {
				originalParents[id] = parent
			}

			txn.FileContractResolutions = append(txn.FileContractResolutions, types.V2FileContractResolution{
				Parent: parent,
				Resolution: &types.V2StorageProof{
					ProofIndex: f.cies[fc.ProofHeight],
				},
			})
			delete(f.v2fces, id)

			i++
		}
	}
	// {
	// 	i := 0
	// 	count := f.rng.Intn(3)
	// 	for id, fce := range f.v2fces {
	// 		if i > count {
	// 			break
	// 		}

	// 		fc := fce.V2FileContract
	// 		height := f.n.tip().Height
	// 		if height < fc.ProofHeight {
	// 			continue
	// 		}
	// 		fc.RevisionNumber++

	// 		parent := fce
	// 		if v, ok := originalParents[id]; ok {
	// 			parent = v
	// 		} else {
	// 			originalParents[id] = parent
	// 		}

	// 		newContract := fc
	// 		newContract.ProofHeight = height + 10
	// 		newContract.ExpirationHeight = newContract.ProofHeight + 1
	// 		renewal := &types.V2FileContractRenewal{
	// 			FinalRenterOutput: fc.RenterOutput,
	// 			FinalHostOutput:   fc.HostOutput,
	// 			RenterRollover:    types.ZeroCurrency,
	// 			HostRollover:      types.ZeroCurrency,
	// 			NewContract:       newContract,
	// 		}
	// 		txn.FileContractResolutions = append(txn.FileContractResolutions, types.V2FileContractResolution{
	// 			Parent:     parent,
	// 			Resolution: renewal,
	// 		})
	// 		amount = amount.Add(payoutV2(fc))
	// 		delete(f.v2fces, id)

	// 		i++
	// 	}
	// }
	// {
	// 	i := 0
	// 	count := f.rng.Intn(3)
	// 	for id, fce := range f.v2fces {
	// 		if i > count {
	// 			break
	// 		}

	// 		fc := fce.V2FileContract
	// 		height := f.n.tip().Height
	// 		if height < fc.ExpirationHeight {
	// 			continue
	// 		}
	// 		fc.RevisionNumber++

	// 		parent := fce.Copy()
	// 		if v, ok := originalParents[id]; ok {
	// 			parent = v
	// 		} else {
	// 			originalParents[id] = parent
	// 		}

	// 		txn.FileContractResolutions = append(txn.FileContractResolutions, types.V2FileContractResolution{
	// 			Parent:     parent,
	// 			Resolution: &types.V2FileContractExpiration{},
	// 		})
	// 		delete(f.v2fces, id)

	// 		i++
	// 	}
	// }
	{
		// for i, count := 0, f.rng.Intn(3); i < count; i++ {
		// 	sco := types.SiacoinOutput{
		// 		Address: f.addr,
		// 		Value:   types.NewCurrency64(1),
		// 	}

		// 	amount = amount.Add(sco.Value)
		// 	txn.SiacoinOutputs = append(txn.SiacoinOutputs, sco)
		// }
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
	// {
	// 	var amount uint64
	// 	for i, count := 0, f.rng.Intn(3); i < count; i++ {
	// 		sfo := types.SiafundOutput{
	// 			Address: f.addr,
	// 			Value:   1,
	// 		}

	// 		amount += sfo.Value
	// 		txn.SiafundOutputs = append(txn.SiafundOutputs, sfo)
	// 	}
	// 	if amount > 0 {
	// 		var sum uint64
	// 		for id, sfe := range f.sfes {
	// 			sum += sfe.SiafundOutput.Value
	// 			txn.SiafundInputs = append(txn.SiafundInputs, types.V2SiafundInput{
	// 				Parent:          sfe,
	// 				SatisfiedPolicy: types.SatisfiedPolicy{Policy: f.policy},
	// 			})
	// 			delete(f.sfes, id)

	// 			if sum >= amount {
	// 				break
	// 			}
	// 		}
	// 		if sum > amount {
	// 			txn.SiafundOutputs = append(txn.SiafundOutputs, types.SiafundOutput{
	// 				Address: f.addr,
	// 				Value:   sum - amount,
	// 			})
	// 		}
	// 	}
	// }
	// so we don't get "transactions cannot be empty"
	txn.ArbitraryData = []byte("1234")
	signV2TransactionWithContracts(f.n.tipState(), f.pk, &txn)

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

func (f *fuzzer) applyBlock(b types.Block) {
	au := f.n.applyBlock(b)
	f.processApplyUpdate(au)
}

func (f *fuzzer) revertBlock() {
	ru := f.n.revertBlock()
	f.processRevertUpdate(ru)
}

func (f *fuzzer) mineBlock() {
	var txns []types.Transaction
	if f.n.tip().Height < (f.n.network.HardforkV2.RequireHeight - 1) {
		for i := 0; i < f.rng.Intn(20); i++ {
			txns = append(txns, f.generateTransaction())
		}
	}

	var v2Txns []types.V2Transaction
	if f.n.tip().Height >= f.n.network.HardforkV2.AllowHeight {
		originalParents := make(map[types.FileContractID]types.V2FileContractElement)
		for i := 0; i < f.rng.Intn(20); i++ {
			v2Txns = append(v2Txns, f.generateV2Transaction(originalParents))
		}
	}

	b := mineBlock(f.n.tipState(), txns, v2Txns, types.VoidAddress)
	f.applyBlock(b)
}

func main() {
	rng := rand.New(rand.NewSource(1))

	seed := make([]byte, ed25519.SeedSize)
	rng.Read(seed)
	pk := types.NewPrivateKeyFromSeed(seed)
	f := newFuzzer(rng, pk)

	for i := 0; i < 10000; i++ {
		if f.n.tip().Height > 0 && f.prob(0.3) {
			log.Println("Reverting:", i)

			b := f.n.tipBlock()
			f.revertBlock()
			f.applyBlock(b)
			f.revertBlock()

		} else {
			log.Println("Mining:", i)
			f.mineBlock()
		}
	}
}
