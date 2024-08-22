package randgen

import (
	"log"
	"math"
	"math/rand"
	"sort"

	"github.com/brunoga/deep"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

const (
	probReorg       = 0.5
	probTransaction = 0.5

	probSC       = 0.3
	probSF       = 0.3
	probFC       = 0.3
	probReviseFC = 0.3
	probMinerFee = 0.3
)

const (
	maxOutputs        = 3
	maxAccounts       = 10
	maxContractExpire = 20

	maxSC = 3 // H
	maxSF = 3 // SF

	maxBatchBlocks = 3
	maxReorgSize   = 10
)

type Account struct {
	Address types.Address
	PK      types.PrivateKey
	UC      types.UnlockConditions

	SCUtxos map[types.SiacoinOutputID]types.SiacoinElement
	SFUtxos map[types.SiafundOutputID]types.SiafundElement
}

func (a *Account) Balance() (sc types.Currency, sf uint64) {
	for _, sce := range a.SCUtxos {
		sc = sc.Add(sce.SiacoinOutput.Value)
	}
	for _, sfe := range a.SFUtxos {
		sf += sfe.SiafundOutput.Value
	}
	return
}

type prevState struct {
	State     consensus.State
	Accs      map[types.Address]Account
	Contracts map[types.FileContractID]types.FileContractElement
}

type ContractAddresses struct {
	Renter, Host types.Address
}

type Fuzzer struct {
	network *consensus.Network
	genesis types.Block

	accs     map[types.Address]Account
	accAddrs []types.Address

	prevs             []prevState
	contracts         map[types.FileContractID]types.FileContractElement
	contractAddresses map[types.FileContractID]ContractAddresses

	rng *rand.Rand

	s  chain.Store
	cm *chain.Manager

	appliedBlocks []types.Block
}

func (f *Fuzzer) Account(addr types.Address) (Account, bool) {
	acc, ok := f.accs[addr]
	return acc, ok
}

func (f *Fuzzer) Addresses() []types.Address {
	return f.accAddrs
}

func (f *Fuzzer) prob(p float64) bool {
	return f.rng.Float64() < p
}

func (f *Fuzzer) randAddr(self types.Address) types.Address {
	for addr := range f.accs {
		if addr != self {
			return addr
		}
	}
	return types.VoidAddress
}

func (f *Fuzzer) randSC() types.Currency {
	return types.NewCurrency64(f.rng.Uint64()%maxSC + 1)
}

func (f *Fuzzer) randSF() uint64 {
	return f.rng.Uint64()%maxSF + 1
}

func (f *Fuzzer) applyUpdates(crus []chain.RevertUpdate, caus []chain.ApplyUpdate) {
	for _, cru := range crus {
		// log.Println("Reorg update")
		cru.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
			if acc, ok := f.accs[sce.SiacoinOutput.Address]; !ok {
				return
			} else if spent {
				acc.SCUtxos[types.SiacoinOutputID(sce.ID)] = sce
			} else {
				delete(acc.SCUtxos, types.SiacoinOutputID(sce.ID))
			}
		})
		cru.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
			if acc, ok := f.accs[sfe.SiafundOutput.Address]; !ok {
				return
			} else if spent {
				acc.SFUtxos[types.SiafundOutputID(sfe.ID)] = sfe
			} else {
				delete(acc.SFUtxos, types.SiafundOutputID(sfe.ID))
			}
		})
		cru.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
			id := types.FileContractID(fce.StateElement.ID)

			if created {
				delete(f.contracts, id)
			} else if rev != nil {
				f.contracts[id] = fce
			} else if resolved {
				f.contracts[id] = fce
			}
		})
	}
	for _, cau := range caus {
		cau.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
			if acc, ok := f.accs[sce.SiacoinOutput.Address]; !ok {
				return
			} else if spent {
				delete(acc.SCUtxos, types.SiacoinOutputID(sce.ID))
			} else {
				acc.SCUtxos[types.SiacoinOutputID(sce.ID)] = sce
			}
		})
		cau.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
			if acc, ok := f.accs[sfe.SiafundOutput.Address]; !ok {
				return
			} else if spent {
				delete(acc.SFUtxos, types.SiafundOutputID(sfe.ID))
			} else {
				acc.SFUtxos[types.SiafundOutputID(sfe.ID)] = sfe
			}
		})
		cau.ForEachFileContractElement(func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool) {
			id := types.FileContractID(fce.StateElement.ID)

			if created {
				f.contracts[id] = fce
			} else if rev != nil {
				f.contracts[id] = *rev
			} else if resolved {
				delete(f.contracts, id)
			}
		})
	}
}

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

func (f *Fuzzer) randV2Txn(height uint64, addr types.Address) (types.V2Transaction, bool) {
	var txn types.V2Transaction
	// acc := f.accs[addr]

	// f.addOutputs(acc, &txn)
	// f.addMinerFee(acc, &txn)

	// renter := f.accs[f.randAddr(types.VoidAddress)]
	// host := f.accs[f.randAddr(types.VoidAddress)]
	// f.addFileContract(acc, renter, host, &txn)
	// f.addFileContractRevision(acc, height, &txn)
	// if ok := f.fundTransaction(acc, height, &txn); !ok {
	// 	return types.Transaction{}, ok
	// }

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
				txn, ok := f.randV2Txn(height, addr)
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

func NewFuzzer(rng *rand.Rand, network *consensus.Network, genesisBlock types.Block, s chain.Store, cm *chain.Manager, pks []types.PrivateKey) Fuzzer {
	f := Fuzzer{
		network: network,
		genesis: genesisBlock,

		accs:              make(map[types.Address]Account),
		contracts:         make(map[types.FileContractID]types.FileContractElement),
		contractAddresses: make(map[types.FileContractID]ContractAddresses),
		rng:               rng,

		s:  s,
		cm: cm,
	}

	for _, pk := range pks {
		uc := types.StandardUnlockConditions(pk.PublicKey())
		addr := uc.UnlockHash()

		f.accAddrs = append(f.accAddrs, addr)
		f.accs[addr] = Account{
			Address: addr,
			PK:      pk,
			UC:      uc,
			SCUtxos: make(map[types.SiacoinOutputID]types.SiacoinElement),
			SFUtxos: make(map[types.SiafundOutputID]types.SiafundElement),
		}
	}

	return f
}

func (f *Fuzzer) Run(iterations int) {
	// apply genesis
	crus, caus, err := f.cm.UpdatesSince(types.ChainIndex{}, math.MaxInt64)
	if err != nil {
		panic(err)
	}
	f.applyUpdates(crus, caus)

	for i := 0; i < iterations; i++ {
		if len(f.prevs) > 0 && f.prob(probReorg) {
			cpy, err := deep.Copy(f.prevs[f.rng.Intn(len(f.prevs))])
			if err != nil {
				panic(err)
			}
			state := cpy.State
			f.accs = cpy.Accs
			f.contracts = cpy.Contracts

			var blocks []types.Block
			extra := f.cm.Tip().Height - state.Index.Height + 1
			for i := uint64(0); i < extra; i++ {
				block := f.mineBlock(state, f.randAddr(types.VoidAddress), f.randTxns(state), f.randV2Txns(state))
				blocks = append(blocks, block)

				state.Index.Height += 1
				state.Index.ID = block.ID()
			}

			log.Println("REORG!")
			// log.Println("BEFORE:", f.cm.Tip())
			f.applyBlocks(blocks)
			// log.Println("AFTER:", f.cm.Tip())
		} else {
			cpy, err := deep.Copy(prevState{f.cm.TipState(), f.accs, f.contracts})
			if err != nil {
				panic(err)
			}
			f.prevs = append(f.prevs, cpy)

			cs := f.cm.TipState()
			f.applyBlocks([]types.Block{f.mineBlock(cs, f.randAddr(types.VoidAddress), f.randTxns(cs), f.randV2Txns(cs))})
		}
		log.Println(f.cm.Tip())
	}
}
