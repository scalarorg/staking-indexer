/** Extended config for btcd

// https://github.com/btcsuite/btcd/commit/1362124a16b4560f2e23ab1c54ca1238812cfb1f

**/

package config

import (
	"math"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
var genesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
				0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x45, /* |.......E| */
				0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, /* |The Time| */
				0x73, 0x20, 0x30, 0x33, 0x2f, 0x4a, 0x61, 0x6e, /* |s 03/Jan| */
				0x2f, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43, 0x68, /* |/2009 Ch| */
				0x61, 0x6e, 0x63, 0x65, 0x6c, 0x6c, 0x6f, 0x72, /* |ancellor| */
				0x20, 0x6f, 0x6e, 0x20, 0x62, 0x72, 0x69, 0x6e, /* | on brin| */
				0x6b, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x63, /* |k of sec|*/
				0x6f, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x69, 0x6c, /* |ond bail| */
				0x6f, 0x75, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, /* |out for |*/
				0x62, 0x61, 0x6e, 0x6b, 0x73, /* |banks| */
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value: 0x12a05f200,
			PkScript: []byte{
				0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, /* |A.g....U| */
				0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, /* |H'.g..q0| */
				0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, /* |..\..(.9| */
				0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, /* |..yb...a| */
				0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, /* |..I..?L.| */
				0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, /* |8..U....| */
				0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, /* |..\8M...| */
				0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, /* |.W.Lp+k.| */
				0x1d, 0x5f, 0xac, /* |._.| */
			},
		},
	},
	LockTime: 0,
}

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the testnet4 network.
var testNet4GenesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x7b, 0x67, 0x66, 0xe6, 0x7e, 0x57, 0xd5, 0xcd,
	0x0c, 0x40, 0xe4, 0x7e, 0x07, 0x80, 0xb8, 0xcb,
	0x4c, 0x14, 0x41, 0x34, 0x23, 0x22, 0xe2, 0x1e,
	0xe1, 0xae, 0x7a, 0xa7, 0x0a, 0xa0, 0xaa, 0x7a,
})

// testNet4GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet4GenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},          // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNet4GenesisMerkleRoot, // 7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e
		Timestamp:  time.Unix(1714777860, 0),  // ???
		Bits:       0x1d00ffff,                // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x17780CBB,                // 393743547
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx}, // FIXME: tx is different
}

// testNet4GenesisHash is the hash of the first block in the block chain for the
// test network (version 4).

// 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043


var testNet4GenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
	0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
	0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
	0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
})

const TestNet4 wire.BitcoinNet = 0x283f161c

var (
	bigOne = big.NewInt(1)
	// testNet3PowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet4PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)
)

var TestNet4Params = chaincfg.Params{
	Name:        "testnet4",
	Net:         TestNet4,
	DefaultPort: "48333",
	DNSSeeds: []chaincfg.DNSSeed{
		{"seed.testnet4.bitcoin.sprovoost.nl.", true},
		{"seed.testnet4.wiz.biz.", true},
	},
	// Chain parameters
	GenesisBlock:             &testNet4GenesisBlock,
	GenesisHash:              &testNet4GenesisHash,
	PowLimit:                 testNet4PowLimit,
	PowLimitBits:             0x1d00ffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        false,
	// Checkpoints ordered from oldest to newest.
	Checkpoints: []chaincfg.Checkpoint{},
	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1512, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016,
	Deployments: [chaincfg.DefinedDeployments]chaincfg.ConsensusDeployment{
		chaincfg.DeploymentTestDummy: {
			BitNumber:         28,
			DeploymentStarter: chaincfg.NewMedianTimeDeploymentStarter(time.Unix(math.MaxInt64, 0)), // Never active
			DeploymentEnder:   &chaincfg.MedianTimeDeploymentEnder{},
		},
		chaincfg.DeploymentTaproot: {
			BitNumber:         2,
			DeploymentStarter: &chaincfg.MedianTimeDeploymentStarter{}, // Always active
			DeploymentEnder:   &chaincfg.MedianTimeDeploymentEnder{},
		},
	},
	// Mempool parameters
	RelayNonStdTxs: true,
	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tb", // always tb for test net
	// Address encoding magics
	PubKeyHashAddrID:        0x6f, // starts with m or n
	ScriptHashAddrID:        0xc4, // starts with 2
	WitnessPubKeyHashAddrID: 0x03, // starts with QW
	WitnessScriptHashAddrID: 0x28, // starts with T7n
	PrivateKeyID:            0xef, // starts with 9 (uncompressed) or c (compressed)
	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub
	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}
