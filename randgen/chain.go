package randgen

import (
	"encoding/json"
	"log"
	"math/bits"
	"os"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
)

// copied from rhp/v2 to avoid import cycle
func prepareContractFormation(renterPubKey types.PublicKey, hostPubKey types.PublicKey, renterPayout, hostCollateral types.Currency, endHeight uint64, windowSize uint64, refundAddr types.Address) types.FileContract {
	taxAdjustedPayout := func(target types.Currency) types.Currency {
		guess := target.Mul64(1000).Div64(961)
		mod64 := func(c types.Currency, v uint64) types.Currency {
			var r uint64
			if c.Hi < v {
				_, r = bits.Div64(c.Hi, c.Lo, v)
			} else {
				_, r = bits.Div64(0, c.Hi, v)
				_, r = bits.Div64(r, c.Lo, v)
			}
			return types.NewCurrency64(r)
		}
		sfc := (consensus.State{}).SiafundCount()
		tm := mod64(target, sfc)
		gm := mod64(guess, sfc)
		if gm.Cmp(tm) < 0 {
			guess = guess.Sub(types.NewCurrency64(sfc))
		}
		return guess.Add(tm).Sub(gm)
	}
	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			{Algorithm: types.SpecifierEd25519, Key: renterPubKey[:]},
			{Algorithm: types.SpecifierEd25519, Key: hostPubKey[:]},
		},
		SignaturesRequired: 2,
	}
	// uc := types.StandardUnlockConditions(renterPubKey)
	hostPayout := hostCollateral
	payout := taxAdjustedPayout(renterPayout.Add(hostPayout))
	return types.FileContract{
		Filesize:       0,
		FileMerkleRoot: types.Hash256{},
		WindowStart:    endHeight,
		WindowEnd:      endHeight + windowSize,
		Payout:         payout,
		UnlockHash:     types.Hash256(uc.UnlockHash()),
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
			{Value: types.ZeroCurrency, Address: types.VoidAddress},
		},
	}
}

func totalOutputs(txn types.Transaction) (sc types.Currency, sf uint64) {
	for _, out := range txn.SiacoinOutputs {
		sc = sc.Add(out.Value)
	}
	for _, fc := range txn.FileContracts {
		sc = sc.Add(fc.Payout)
	}
	for _, fee := range txn.MinerFees {
		sc = sc.Add(fee)
	}
	for _, out := range txn.SiafundOutputs {
		sf += out.Value
	}
	return
}

func totalOutputsV2(cs consensus.State, txn types.V2Transaction) (sc types.Currency, sf uint64) {
	for _, out := range txn.SiacoinOutputs {
		sc = sc.Add(out.Value)
	}
	for _, fc := range txn.FileContracts {
		sc = sc.Add(fc.RenterOutput.Value).Add(fc.HostOutput.Value).Add(cs.V2FileContractTax(fc))
	}
	for _, fcr := range txn.FileContractResolutions {
		if r, ok := fcr.Resolution.(*types.V2FileContractRenewal); ok {
			// a renewal creates a new contract, optionally "rolling over" funds
			// from the old contract
			rev := r.NewContract
			sc = sc.Add(rev.RenterOutput.Value).Add(rev.HostOutput.Value).Add(cs.V2FileContractTax(rev))
		}
	}
	sc = sc.Add(txn.MinerFee)
	for _, out := range txn.SiafundOutputs {
		sf += out.Value
	}
	return
}

func (f *Fuzzer) signTxn(priv types.PrivateKey, cs consensus.State, txn *types.Transaction) {
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
		appendSig(priv, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
	}
	for i := range txn.SiafundInputs {
		appendSig(priv, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
	}
	for _, fcr := range txn.FileContractRevisions {
		addrs := f.contractAddresses[fcr.ParentID]
		renterKey, hostKey := f.accs[addrs.Renter].PK, f.accs[addrs.Host].PK
		appendSig(renterKey, 0, types.Hash256(fcr.ParentID))
		appendSig(hostKey, 1, types.Hash256(fcr.ParentID))
	}
}

func (f *Fuzzer) signV2Txn(priv types.PrivateKey, cs consensus.State, txn *types.V2Transaction) {
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].SatisfiedPolicy.Signatures = []types.Signature{priv.SignHash(cs.InputSigHash(*txn))}
	}
	for i := range txn.SiafundInputs {
		txn.SiafundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{priv.SignHash(cs.InputSigHash(*txn))}
	}
	txnID := txn.ID()
	for i := range txn.FileContracts {
		addrs := f.contractAddresses[txn.V2FileContractID(txnID, i)]
		renterPrivateKey, hostPrivateKey := f.accs[addrs.Renter].PK, f.accs[addrs.Host].PK
		txn.FileContracts[i].RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
		txn.FileContracts[i].HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
	}
	for i := range txn.FileContractRevisions {
		addrs := f.contractAddresses[types.FileContractID(txn.FileContractRevisions[i].Parent.ID)]
		renterPrivateKey, hostPrivateKey := f.accs[addrs.Renter].PK, f.accs[addrs.Host].PK

		txn.FileContractRevisions[i].Revision.RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
		txn.FileContractRevisions[i].Revision.HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
	}
	for i := range txn.FileContractResolutions {
		addrs := f.contractAddresses[types.FileContractID(txn.FileContractResolutions[i].Parent.ID)]
		renterPrivateKey, hostPrivateKey := f.accs[addrs.Renter].PK, f.accs[addrs.Host].PK

		switch r := txn.FileContractResolutions[i].Resolution.(type) {
		case *types.V2FileContractRenewal:
			r.RenterSignature = renterPrivateKey.SignHash(cs.RenewalSigHash(*r))
			r.HostSignature = hostPrivateKey.SignHash(cs.RenewalSigHash(*r))
		case *types.V2FileContractFinalization:
			r.RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(types.V2FileContract(*r)))
			r.HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(types.V2FileContract(*r)))
		}
	}
}

func (f *Fuzzer) addBlocks(b []types.Block) {
	defer func() {
		if err := recover(); err != nil {
			file, err := os.Create("crasher.json")
			if err != nil {
				panic(err)
			}
			defer file.Close()
			if err := json.NewEncoder(file).Encode(Crasher{
				Network:    f.network,
				Genesis:    f.genesis,
				Blocks:     append(f.appliedBlocks, b...),
				CrashIndex: len(f.appliedBlocks),
			}); err != nil {
				panic(err)
			}
			log.Println("Wrote crasher.json")
			panic(nil)
		}
	}()

	// prev := f.cm.Tip()
	if err := f.cm.AddBlocks(b); err != nil {
		panic(err)
	}
	// crus, caus, err := f.cm.UpdatesSince(prev, math.MaxInt64)
	// if err != nil {
	// 	panic(err)
	// }
	// f.applyUpdates(crus, caus)

	f.appliedBlocks = append(f.appliedBlocks, b...)
}

func (f *Fuzzer) mineBlock(cs consensus.State, rewardAddr types.Address, txns []types.Transaction, v2Txns []types.V2Transaction) types.Block {
	b := types.Block{
		ParentID:  cs.Index.ID,
		Timestamp: types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{
			Value:   cs.BlockReward(),
			Address: rewardAddr,
		}},
	}

	childHeight := cs.Index.Height + 1
	if childHeight >= cs.Network.HardforkV2.AllowHeight {
		b.V2 = &types.V2BlockData{
			Height: childHeight,
		}
	}

	var weight uint64
	for _, txn := range txns {
		if weight += cs.TransactionWeight(txn); weight > cs.MaxBlockWeight() {
			break
		}
		b.Transactions = append(b.Transactions, txn)
		b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(txn.TotalFees())
	}
	if b.V2 != nil {
		for _, txn := range v2Txns {
			if weight += cs.V2TransactionWeight(txn); weight > cs.MaxBlockWeight() {
				break
			}
			b.V2.Transactions = append(b.V2.Transactions, txn)
			b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(txn.MinerFee)
		}

		b.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(b.Transactions, b.V2Transactions()), rewardAddr)
	}

	if !coreutils.FindBlockNonce(cs, &b, 5*time.Second) {
		panic("mining too slow")
	}
	return b
}
