package main

import (
	"log"
	"math"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/testutil"
)

func mineBlock(state consensus.State, txns []types.Transaction, v2Txns []types.V2Transaction, minerAddr types.Address) types.Block {
	reward := state.BlockReward()
	for _, txn := range txns {
		for _, fee := range txn.MinerFees {
			reward = reward.Add(fee)
		}
	}
	for _, txn := range v2Txns {
		reward = reward.Add(txn.MinerFee)
	}

	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    time.Date(2025, time.January, 0, 0, 0, 0, 0, time.UTC),
		Transactions: txns,
		MinerPayouts: []types.SiacoinOutput{{Address: minerAddr, Value: reward}},
	}
	if len(v2Txns) > 0 {
		b.V2 = &types.V2BlockData{
			Transactions: v2Txns,
			Height:       state.Index.Height + 1,
		}
		b.V2.Commitment = state.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())
		for b.ID().CmpWork(state.ChildTarget) < 0 {
			b.Nonce += state.NonceFactor()
		}
	}
	return b
}

type testChain struct {
	store *chain.DBStore

	network     *consensus.Network
	blocks      []types.Block
	supplements []consensus.V1BlockSupplement
	states      []consensus.State
}

func newTestChain(v2 bool, modifyGenesis func(*consensus.Network, types.Block)) *testChain {
	var network *consensus.Network
	var genesisBlock types.Block
	if v2 {
		network, genesisBlock = testutil.V2Network()
	} else {
		network, genesisBlock = testutil.Network()
	}
	if v2 {
		network.HardforkV2.AllowHeight = 1
		network.HardforkV2.RequireHeight = 2
	}
	if modifyGenesis != nil {
		modifyGenesis(network, genesisBlock)
	}

	store, genesisState, err := chain.NewDBStore(chain.NewMemDB(), network, genesisBlock, nil)
	if err != nil {
		panic(err)
	}
	bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(genesisBlock.Transactions))}

	return &testChain{
		store: store,

		network:     network,
		blocks:      []types.Block{genesisBlock},
		supplements: []consensus.V1BlockSupplement{bs},
		states:      []consensus.State{genesisState},
	}
}

func (n *testChain) genesis() types.Block {
	return n.blocks[0]
}

func (n *testChain) tipBlock() types.Block {
	return n.blocks[len(n.blocks)-1]
}

func (n *testChain) tipState() consensus.State {
	return n.states[len(n.states)-1]
}

func (n *testChain) tip() types.ChainIndex {
	return n.states[len(n.states)-1].Index
}

func (n *testChain) applyBlock(b types.Block) consensus.ApplyUpdate {
	cs := n.tipState()
	bs := n.store.SupplementTipBlock(b)
	if cs.Index.Height != math.MaxUint64 {
		// don't validate genesis block
		if err := consensus.ValidateBlock(cs, b, bs); err != nil {
			panic(err)
		}
		if b.V2 != nil {
			log.Printf("Parent state: %v, got commitment hash: %v", cs.Index, b.V2.Commitment)
		}
	}

	cs, au := consensus.ApplyBlock(cs, b, bs, b.Timestamp)

	n.store.AddState(cs)
	n.store.AddBlock(b, &bs)
	n.store.ApplyBlock(cs, au)

	n.blocks = append(n.blocks, b)
	n.supplements = append(n.supplements, bs)
	n.states = append(n.states, cs)

	return au
}

func (n *testChain) revertBlock() consensus.RevertUpdate {
	b := n.blocks[len(n.blocks)-1]
	bs := n.supplements[len(n.supplements)-1]
	prevState := n.states[len(n.states)-2]

	ru := consensus.RevertBlock(prevState, b, bs)

	n.store.RevertBlock(prevState, ru)

	n.blocks = n.blocks[:len(n.blocks)-1]
	n.supplements = n.supplements[:len(n.supplements)-1]
	n.states = n.states[:len(n.states)-1]

	return ru
}

func (n *testChain) mineTransactions(txns []types.Transaction, v2Txns []types.V2Transaction) {
	b := mineBlock(n.tipState(), txns, v2Txns, types.VoidAddress)
	n.applyBlock(b)
}

// signTransactionWithContracts signs a transaction using the specified private
// keys, including contract revisions.
func signTransactionWithContracts(cs consensus.State, pk types.PrivateKey, txn *types.Transaction) {
	appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
		sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:       parentID,
			CoveredFields:  types.CoveredFields{WholeTransaction: true},
			PublicKeyIndex: pubkeyIndex,
			Signature:      sig[:],
		})
	}
	for i := range txn.SiacoinInputs {
		appendSig(pk, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
	}
	for i := range txn.SiafundInputs {
		appendSig(pk, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
	}
	for i := range txn.FileContractRevisions {
		appendSig(pk, 0, types.Hash256(txn.FileContractRevisions[i].ParentID))
	}
}

// signV2TransactionWithContracts signs a transaction using the specified
// private keys, including contracts and revisions.
func signV2TransactionWithContracts(cs consensus.State, pk types.PrivateKey, txn *types.V2Transaction) {
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cs.InputSigHash(*txn))}
	}
	for i := range txn.SiafundInputs {
		txn.SiafundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{pk.SignHash(cs.InputSigHash(*txn))}
	}
	for i := range txn.FileContracts {
		txn.FileContracts[i].RenterSignature = pk.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
		txn.FileContracts[i].HostSignature = pk.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
	}
	for i := range txn.FileContractRevisions {
		txn.FileContractRevisions[i].Revision.RenterSignature = pk.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
		txn.FileContractRevisions[i].Revision.HostSignature = pk.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
	}
	for i := range txn.FileContractResolutions {
		if r, ok := txn.FileContractResolutions[i].Resolution.(*types.V2FileContractRenewal); ok {
			r.RenterSignature = pk.SignHash(cs.RenewalSigHash(*r))
			r.HostSignature = pk.SignHash(cs.RenewalSigHash(*r))
			r.NewContract.RenterSignature = pk.SignHash(cs.ContractSigHash(r.NewContract))
			r.NewContract.HostSignature = pk.SignHash(cs.ContractSigHash(r.NewContract))
		}
	}
}
