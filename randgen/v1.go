package randgen

import (
	"sort"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func (f *Fuzzer) addOutputs(acc Account, txn *types.Transaction) {
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

func (f *Fuzzer) addMinerFee(acc Account, txn *types.Transaction) {
	if f.prob(probMinerFee) {
		txn.MinerFees = []types.Currency{f.randSC()}
	}
}

func (f *Fuzzer) addFileContract(acc, renter, host Account, txn *types.Transaction) {
	if f.prob(probFC) {
		windowStart := f.cm.Tip().Height + 1 + uint64(f.rng.Intn(maxContractExpire))
		windowEnd := windowStart + 1 + uint64(f.rng.Intn(maxContractExpire))
		fc := prepareContractFormation(renter.PK.PublicKey(), host.PK.PublicKey(), f.randSC(), f.randSC(), windowStart, windowEnd, acc.Address)
		txn.FileContracts = append(txn.FileContracts, fc)
	}
}

func (f *Fuzzer) addFileContractRevision(acc Account, height uint64, txn *types.Transaction) {
	if f.prob(probReviseFC) {
		var fces []types.FileContractElement
		for _, fce := range f.contracts {
			// we can't revise after proof window has opened
			if height >= fce.FileContract.WindowStart {
				continue
			}
			fces = append(fces, fce)
		}
		sort.Slice(fces, func(i, j int) bool {
			return fces[i].ID.String() > fces[j].ID.String()
		})
		if len(fces) > 0 {
			fc := fces[f.rng.Intn(len(fces))]
			fc.FileContract.RevisionNumber++
			fc.FileContract.WindowStart = height + 1 + uint64(f.rng.Intn(maxContractExpire))
			fc.FileContract.WindowEnd = fc.FileContract.WindowStart + 1 + uint64(f.rng.Intn(maxContractExpire))

			addrs := f.contractAddresses[types.FileContractID(fc.ID)]
			renterPubKey := f.accs[addrs.Renter].PK.PublicKey()
			hostPubKey := f.accs[addrs.Host].PK.PublicKey()

			uc := types.UnlockConditions{
				PublicKeys: []types.UnlockKey{
					{Algorithm: types.SpecifierEd25519, Key: renterPubKey[:]},
					{Algorithm: types.SpecifierEd25519, Key: hostPubKey[:]},
				},
				SignaturesRequired: 2,
			}
			txn.FileContractRevisions = append(txn.FileContractRevisions, types.FileContractRevision{
				ParentID:         types.FileContractID(fc.ID),
				UnlockConditions: uc,
				FileContract:     fc.FileContract,
			})

			// don't revise again in same block
			delete(f.contracts, types.FileContractID(fc.ID))
		}
	}
}

func (f *Fuzzer) fundTransaction(acc Account, height uint64, txn *types.Transaction) bool {
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

	sc, sf := totalOutputs(*txn)

	if sc.Cmp(types.ZeroCurrency) == 1 {
		var runningSC types.Currency
		for _, sce := range scUtxos {
			if sce.MaturityHeight > height {
				continue
			}
			runningSC = runningSC.Add(sce.SiacoinOutput.Value)

			txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
				ParentID:         types.SiacoinOutputID(sce.ID),
				UnlockConditions: acc.UC,
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

			txn.SiafundInputs = append(txn.SiafundInputs, types.SiafundInput{
				ParentID:         types.SiafundOutputID(sfe.ID),
				UnlockConditions: acc.UC,
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

func (f *Fuzzer) randTxn(height uint64, addr types.Address) (types.Transaction, bool) {
	var txn types.Transaction
	acc := f.accs[addr]

	f.addOutputs(acc, &txn)
	f.addMinerFee(acc, &txn)

	renter := f.accs[f.randAddr(types.VoidAddress)]
	host := f.accs[f.randAddr(types.VoidAddress)]
	f.addFileContract(acc, renter, host, &txn)
	f.addFileContractRevision(acc, height, &txn)
	if ok := f.fundTransaction(acc, height, &txn); !ok {
		return types.Transaction{}, ok
	}

	{
		for i := range txn.FileContracts {
			f.contractAddresses[txn.FileContractID(i)] = ContractAddresses{
				Renter: renter.Address,
				Host:   host.Address,
			}
		}
	}

	return txn, true
}

func (f *Fuzzer) randTxns(cs consensus.State) (txns []types.Transaction) {
	height := cs.Index.Height
	if height < f.network.HardforkV2.RequireHeight-1 {
		for _, addr := range f.accAddrs {
			if f.prob(probTransaction) {
				txn, ok := f.randTxn(height, addr)
				if !ok {
					continue
				}
				f.signTxn(f.accs[addr].PK, cs, &txn)
				txns = append(txns, txn)
			}
		}
	}
	return
}
