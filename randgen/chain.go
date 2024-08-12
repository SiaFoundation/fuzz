package randgen

import (
	"encoding/json"
	"math"
	"math/bits"
	"os"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func findBlockNonce(cs consensus.State, b *types.Block) {
	// ensure nonce meets factor requirement
	for b.Nonce%cs.NonceFactor() != 0 {
		b.Nonce++
	}
	for b.ID().CmpWork(cs.ChildTarget) < 0 {
		b.Nonce += cs.NonceFactor()
	}
}

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

func (f *Fuzzer) signTxn(priv types.PrivateKey, txn *types.Transaction) {
	appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
		sig := key.SignHash(f.cm.TipState().WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
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

func (f *Fuzzer) applyBlocks(b []types.Block) {
	f.appliedBlocks = append(f.appliedBlocks, b...)
	{
		file, err := os.Create("blocks.json")
		if err != nil {
			panic(err)
		}
		defer file.Close()
		if err := json.NewEncoder(file).Encode(f.appliedBlocks); err != nil {
			panic(err)
		}
	}

	prev := f.cm.Tip()
	if err := f.cm.AddBlocks(b); err != nil {
		panic(err)
	}
	crus, caus, err := f.cm.UpdatesSince(prev, math.MaxInt64)
	if err != nil {
		panic(err)
	}
	f.applyUpdates(crus, caus)
}

func (f *Fuzzer) mineBlock(state consensus.State, minerAddr types.Address, txns []types.Transaction) types.Block {
	var fees types.Currency
	for _, txn := range txns {
		for _, fee := range txn.MinerFees {
			fees = fees.Add(fee)
		}
	}
	b := types.Block{
		ParentID:  state.Index.ID,
		Timestamp: f.cm.TipState().Network.HardforkOak.GenesisTimestamp.Add(time.Second * time.Duration(1+f.cm.TipState().Index.Height)),
		MinerPayouts: []types.SiacoinOutput{
			{Address: minerAddr, Value: state.BlockReward().Add(fees)},
		},
		Transactions: txns,
	}
	findBlockNonce(state, &b)
	return b
}
