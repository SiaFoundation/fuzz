package main

import (
	"go.sia.tech/core/consensus"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
)

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
			fc, payout := prepareV2Contract(f.pk, f.pk, f.n.tip().Height+1)

			amount = amount.Add(payout)
			txn.FileContracts = append(txn.FileContracts, fc)
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
	// 		if height >= fc.ProofHeight {
	// 			continue
	// 		}
	// 		fc.RevisionNumber++

	// 		parent := fce
	// 		if v, ok := originalParents[id]; ok {
	// 			parent = v
	// 		} else {
	// 			originalParents[id] = parent
	// 		}

	// 		txn.FileContractRevisions = append(txn.FileContractRevisions, types.V2FileContractRevision{
	// 			Parent:   parent,
	// 			Revision: fc,
	// 		})

	// 		f.v2fces[id] = types.V2FileContractElement{
	// 			ID:             id,
	// 			StateElement:   fce.StateElement,
	// 			V2FileContract: fc,
	// 		}

	// 		i++
	// 	}
	// }
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
