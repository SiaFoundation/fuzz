package main

import (
	"crypto/ed25519"

	proto2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
)

func (f *fuzzer) prepareContract(endHeight uint64) types.FileContract {
	seed := make([]byte, ed25519.SeedSize)
	f.rng.Read(seed)
	pk := types.NewPrivateKeyFromSeed(seed)
	publicKey := pk.PublicKey()

	hs := proto2.HostSettings{
		WindowSize: 1,
		Address:    types.StandardUnlockHash(publicKey),
	}
	sc := types.Siacoins(1)
	fc := proto2.PrepareContractFormation(publicKey, publicKey, sc.Mul64(2), sc.Mul64(2), endHeight, hs, hs.Address)
	fc.UnlockHash = f.addr
	return fc
}

func (f *fuzzer) generateTransaction() (txn types.Transaction) {
	{
		count := f.rng.Intn(2)
		for _, fce := range mapValues(f.fces) {
			if len(txn.StorageProofs) >= count {
				break
			}

			id := fce.ID
			fc := fce.FileContract
			height := f.n.tip().Height
			if height < fc.WindowStart {
				continue
			}
			txn.StorageProofs = append(txn.StorageProofs, types.StorageProof{
				ParentID: id,
			})
			delete(f.fces, id)
		}
		if len(txn.StorageProofs) > 0 {
			// can't have storage proofs and outputs in one transaction
			return
		}
	}
	var amount types.Currency
	{
		for i, count := 0, f.rng.Intn(10); i < count; i++ {
			fc := f.prepareContract(f.n.tip().Height + 10)
			txn.FileContracts = append(txn.FileContracts, fc)
			amount = amount.Add(fc.Payout)
		}
	}
	{
		i := 0
		count := f.rng.Intn(3)
		for _, fce := range mapValues(f.fces) {
			if i > count {
				break
			}

			fc := fce.FileContract
			height := f.n.tip().Height
			if fc.WindowStart >= height {
				continue
			}
			fc.RevisionNumber++
			// fc.WindowStart = height + 1
			// fc.WindowEnd = fc.WindowStart + 10
			txn.FileContractRevisions = append(txn.FileContractRevisions, types.FileContractRevision{
				ParentID:         fce.ID,
				UnlockConditions: f.uc,
				FileContract:     fc,
			})
			f.fces[fce.ID] = types.FileContractElement{
				ID:           fce.ID,
				StateElement: fce.StateElement,
				FileContract: fc,
			}

			i++
		}
	}
	{
		for i, count := 0, f.rng.Intn(3); i < count; i++ {
			sco := types.SiacoinOutput{
				Address: f.addr,
				Value:   types.NewCurrency64(1),
			}

			amount = amount.Add(sco.Value)
			txn.SiacoinOutputs = append(txn.SiacoinOutputs, sco)
		}
		if amount.Cmp(types.ZeroCurrency) == 1 {
			var sum types.Currency
			for _, sce := range mapValues(f.sces) {
				id := sce.ID
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
		for i, count := 0, f.rng.Intn(3); i < count; i++ {
			sfo := types.SiafundOutput{
				Address: f.addr,
				Value:   1,
			}

			amount += sfo.Value
			txn.SiafundOutputs = append(txn.SiafundOutputs, sfo)
		}
		if amount > 0 {
			var sum uint64
			for _, sfe := range mapValues(f.sfes) {
				id := sfe.ID
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
	signTransactionWithContracts(f.n.tipState(), f.pk, &txn)

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
	for i, fc := range txn.FileContracts {
		id := txn.FileContractID(i)
		f.fces[id] = types.FileContractElement{
			ID: id,
			StateElement: types.StateElement{
				LeafIndex: types.UnassignedLeafIndex,
			},
			FileContract: fc,
		}
	}
	return
}
