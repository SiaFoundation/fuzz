package randgen

import (
	"log"
	"math"
	"math/rand"
	"time"

	"github.com/brunoga/deep"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

const (
	probReorg       = 0.0
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

	store chain.Store
	cm    *chain.Manager

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
	// if we have no other addresses to choose from
	if len(f.accAddrs) == 1 && f.accAddrs[0] == self {
		return types.VoidAddress
	}

	// otherwise, pick a random address
	result := f.accAddrs[f.rng.Intn(len(f.accAddrs))]
	if result == self {
		return f.randAddr(self)
	}
	return result
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

func NewFuzzer(rng *rand.Rand, network *consensus.Network, genesisBlock types.Block, store chain.Store, cm *chain.Manager, pks []types.PrivateKey) Fuzzer {
	f := Fuzzer{
		network: network,
		genesis: genesisBlock,

		accs:              make(map[types.Address]Account),
		contracts:         make(map[types.FileContractID]types.FileContractElement),
		contractAddresses: make(map[types.FileContractID]ContractAddresses),
		rng:               rng,

		store: store,
		cm:    cm,
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

type chainUpdate interface {
	UpdateElementProof(e *types.StateElement)
}

func (f *Fuzzer) updateProofs(update chainUpdate) {
	for fcid := range f.contracts {
		e := f.contracts[fcid]
		update.UpdateElementProof(&e.StateElement)
		f.contracts[fcid] = e
	}
	for _, acc := range f.accs {
		for scid := range acc.SCUtxos {
			e := acc.SCUtxos[scid]
			update.UpdateElementProof(&e.StateElement)
			acc.SCUtxos[scid] = e
		}
		for sfid := range acc.SFUtxos {
			e := acc.SFUtxos[sfid]
			update.UpdateElementProof(&e.StateElement)
			acc.SFUtxos[sfid] = e
		}
	}
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

			txns := f.randTxns(cs)
			if _, err := f.cm.AddV2PoolTransactions(cs.Index, f.randV2Txns(cs)); err != nil {
				panic(err)
			}
			block := f.mineBlock(cs, f.randAddr(types.VoidAddress), txns, f.cm.V2PoolTransactions())

			_, au := consensus.ApplyBlock(cs, block, f.store.SupplementTipBlock(block), time.Time{})
			f.updateProofs(au)

			f.applyBlocks([]types.Block{block})
		}
		log.Println(f.cm.Tip())
	}
}
