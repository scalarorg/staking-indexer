package indexer

import (
	"github.com/babylonchain/babylon/btcstaking"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TODO_SCALAR: implement the scalar staking tx quick check
func IsPossibleV0StakingTx(tx *wire.MsgTx, expectedMagicBytes []byte) bool {
	return btcstaking.IsPossibleV0StakingTx(tx, expectedMagicBytes)
}

// TODO_SCALAR: implement the scalar staking tx parsing
func ParseV0StakingTx(tx *wire.MsgTx, expectedMagicBytes []byte, covenantKeys []*secp256k1.PublicKey, covenantQuorum uint32, net *chaincfg.Params) (*btcstaking.ParsedV0StakingTx, error) {
	return btcstaking.ParseV0StakingTx(tx, expectedMagicBytes, covenantKeys, covenantQuorum, net)
}
