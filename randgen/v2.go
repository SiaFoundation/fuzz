package randgen

import (
	"sort"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func (f *Fuzzer) addV2Outputs(acc Account, txn *types.V2Transaction) {
	// random outputs
	balanceSC, balanceSF := acc.Balance()
	for i, m := 0, f.rng.Intn(maxOutputs); i < m; i++ {
		rSC := f.randSC()
		if f.prob(probSC) && balanceSC.Cmp(rSC) >= 0 {
			balanceSC = balanceSC.Sub(rSC)
			txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{Value: rSC, Address: f.randAddr(acc.Address)})
		}
		rSF := f.randSF()
		if f.prob(probSF) && balanceSF >= rSF {
			balanceSF = balanceSF - rSF
			txn.SiafundOutputs = append(txn.SiafundOutputs, types.SiafundOutput{Value: rSF, Address: f.randAddr(acc.Address)})
		}
	}
}

func (f *Fuzzer) addV2MinerFee(acc Account, txn *types.V2Transaction) {
	if f.prob(probMinerFee) {
		txn.MinerFee = f.randSC()
	}
}

func (f *Fuzzer) fundV2Transaction(cs consensus.State, acc Account, height uint64, txn *types.V2Transaction) bool {
	var scUtxos []types.SiacoinElement
	for _, sce := range acc.SCUtxos {
		scUtxos = append(scUtxos, sce)
	}
	sort.Slice(scUtxos, func(i, j int) bool {
		return scUtxos[i].ID.String() > scUtxos[j].ID.String()
	})

	var sfUtxos []types.SiafundElement
	for _, sfe := range acc.SFUtxos {
		sfUtxos = append(sfUtxos, sfe)
	}
	sort.Slice(sfUtxos, func(i, j int) bool {
		return sfUtxos[i].ID.String() > sfUtxos[j].ID.String()
	})

	sc, sf := totalOutputsV2(cs, *txn)

	if sc.Cmp(types.ZeroCurrency) == 1 {
		var runningSC types.Currency
		for _, sce := range scUtxos {
			if sce.MaturityHeight > height {
				continue
			}
			runningSC = runningSC.Add(sce.SiacoinOutput.Value)

			txn.SiacoinInputs = append(txn.SiacoinInputs, types.V2SiacoinInput{
				Parent: sce,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{types.PolicyTypeUnlockConditions(acc.UC)},
				},
			})
			delete(acc.SCUtxos, types.SiacoinOutputID(sce.ID))

			if runningSC.Cmp(sc) >= 0 {
				if change := runningSC.Sub(sc); change.Cmp(types.ZeroCurrency) == 1 {
					txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
						Address: acc.Address,
						Value:   change,
					})
				}
				break
			}
		}
		if runningSC.Cmp(sc) < 0 {
			// log.Println("failed to fund siacoin outputs")
			return false
		}
	}

	if sf > 0 {
		runningSF := uint64(0)
		for _, sfe := range sfUtxos {
			runningSF += sfe.SiafundOutput.Value

			txn.SiafundInputs = append(txn.SiafundInputs, types.V2SiafundInput{
				Parent: sfe,
				SatisfiedPolicy: types.SatisfiedPolicy{
					Policy: types.SpendPolicy{types.PolicyTypeUnlockConditions(acc.UC)},
				},
			})
			delete(acc.SFUtxos, types.SiafundOutputID(sfe.ID))

			if runningSF >= sf {
				if change := runningSF - sf; change > 0 {
					txn.SiafundOutputs = append(txn.SiafundOutputs, types.SiafundOutput{
						Address: acc.Address,
						Value:   change,
					})
				}
				break
			}
		}
		if runningSF < sf {
			// log.Println("failed to fund siafund outputs")
			return false
		}
	}

	return true
}

func (f *Fuzzer) randV2Txn(cs consensus.State, height uint64, addr types.Address) (types.V2Transaction, bool) {
	var txn types.V2Transaction
	acc := f.accs[addr]

	f.addV2Outputs(acc, &txn)
	f.addV2MinerFee(acc, &txn)

	// renter := f.accs[f.randAddr(types.VoidAddress)]
	// host := f.accs[f.randAddr(types.VoidAddress)]
	// f.addFileContract(acc, renter, host, &txn)
	// f.addFileContractRevision(acc, height, &txn)
	if ok := f.fundV2Transaction(cs, acc, height, &txn); !ok {
		return types.V2Transaction{}, ok
	}

	// {
	// 	for i := range txn.FileContracts {
	// 		f.contractAddresses[txn.FileContractID(i)] = ContractAddresses{
	// 			Renter: renter.Address,
	// 			Host:   host.Address,
	// 		}
	// 	}
	// }

	return txn, true
}

func (f *Fuzzer) randV2Txns(cs consensus.State) (txns []types.V2Transaction) {
	height := cs.Index.Height
	if height >= f.network.HardforkV2.AllowHeight {
		cs := f.cm.TipState()
		for _, addr := range f.accAddrs {
			if f.prob(probTransaction) {
				txn, ok := f.randV2Txn(cs, height, addr)
				if !ok {
					continue
				}
				f.signV2Txn(f.accs[addr].PK, cs, &txn)
				txns = append(txns, txn)
			}
		}
	}
	return
}
