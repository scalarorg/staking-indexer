package datagen

import (
	"math/rand"
	"testing"

	bbndatagen "github.com/babylonchain/babylon/testutil/datagen"
	"github.com/babylonchain/networks/parameters/parser"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"

	// "github.com/babylonchain/staking-indexer/indexerstore"

	"github.com/scalarorg/btc-vault/btcvault"
)

const (
	burningPathInfoType           int = 0
	slashingOrLostKeyPathInfoType int = 1
	burnWithoutDAppPathInfoType   int = 2
)

type TestVaultData struct {
	StakerKey                   *btcec.PublicKey
	FinalityProviderKey         *btcec.PublicKey
	StakingAmount               btcutil.Amount
	ChainID                     []byte
	ChainIdUserAddress          []byte
	ChainIdSmartContractAddress []byte
	MintingAmount               []byte
}

func GenerateTestVaultData(
	t *testing.T,
	r *rand.Rand,
	params *parser.ParsedVersionedGlobalParams,
) *TestVaultData {
	stakerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	fpPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	stakingAmount := btcutil.Amount(r.Int63n(int64(params.MaxStakingAmount-params.MinStakingAmount)) + int64(params.MinStakingAmount) + 1)

	chainID := bbndatagen.GenRandomByteArray(r, 8)
	chainIdUserAddress := bbndatagen.GenRandomByteArray(r, 20)
	chainIdSmartContractAddress := bbndatagen.GenRandomByteArray(r, 20)
	mintingAmount := bbndatagen.GenRandomByteArray(r, 8)

	return &TestVaultData{
		StakerKey:                   stakerPrivKey.PubKey(),
		FinalityProviderKey:         fpPrivKey.PubKey(),
		StakingAmount:               stakingAmount,
		ChainID:                     chainID,
		ChainIdUserAddress:          chainIdUserAddress,
		ChainIdSmartContractAddress: chainIdSmartContractAddress,
		MintingAmount:               mintingAmount,
	}
}

func GenerateVaultTxFromTestData(t *testing.T, r *rand.Rand, params *parser.ParsedVersionedGlobalParams, vaultData *TestVaultData) (*btcvault.IdentifiableVaultInfo, *btcutil.Tx) {
	stakingInfo, tx, err := btcvault.BuildV0IdentifiableVaultOutputsAndTx(
		params.Tag,
		vaultData.StakerKey,
		vaultData.FinalityProviderKey,
		params.CovenantPks,
		params.CovenantQuorum,
		vaultData.StakingAmount,
		vaultData.ChainID,
		vaultData.ChainIdUserAddress,
		vaultData.ChainIdSmartContractAddress,
		vaultData.MintingAmount,
		&chaincfg.SigNetParams,
	)
	require.NoError(t, err)

	// an input is needed because btcd serialization does not work well if tx does not have inputs
	txIn := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.HashH(bbndatagen.GenRandomByteArray(r, 10)),
			Index: r.Uint32(),
		},
		SignatureScript: bbndatagen.GenRandomByteArray(r, 10),
		Sequence:        r.Uint32(),
	}
	tx.AddTxIn(txIn)

	return stakingInfo, btcutil.NewTx(tx)
}

func GenerateBurningTxFromVault(t *testing.T, r *rand.Rand, params *parser.ParsedVersionedGlobalParams, vaultData *TestVaultData, stakingTxHash *chainhash.Hash, stakingOutputIdx uint32) *btcutil.Tx {
	vaultInfo, err := btcvault.BuildV0IdentifiableVaultOutputs(
		params.Tag,
		vaultData.StakerKey,
		vaultData.FinalityProviderKey,
		params.CovenantPks,
		params.CovenantQuorum,
		vaultData.StakingAmount,
		vaultData.ChainID,
		vaultData.ChainIdUserAddress,
		vaultData.ChainIdSmartContractAddress,
		vaultData.MintingAmount,
		&chaincfg.SigNetParams,
	)
	require.NoError(t, err)

	burningSpendInfo, err := vaultInfo.BurnPathSpendInfo()
	require.NoError(t, err)

	burningInfo, err := btcvault.BuildSpendingInfo(
		burningPathInfoType,
		vaultData.StakerKey,
		[]*btcec.PublicKey{vaultData.FinalityProviderKey},
		params.CovenantPks,
		params.CovenantQuorum,
		vaultData.StakingAmount-params.UnbondingFee,
		&chaincfg.SigNetParams,
	)
	require.NoError(t, err)

	burningTx := wire.NewMsgTx(2)
	witness, err := btcvault.CreateWitness(burningSpendInfo, [][]byte{})
	require.NoError(t, err)
	burningTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(stakingTxHash, stakingOutputIdx), nil, witness))
	burningTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum
	burningTx.AddTxOut(burningInfo.Output)

	return btcutil.NewTx(burningTx)
}

func GenerateSlashingOrLostKeyTxFromVault(t *testing.T, r *rand.Rand, params *parser.ParsedVersionedGlobalParams, vaultData *TestVaultData, vaultTxHash *chainhash.Hash, vaultOutputIdx uint32) *btcutil.Tx {
	vaultInfo, err := btcvault.BuildV0IdentifiableVaultOutputs(
		params.Tag,
		vaultData.StakerKey,
		vaultData.FinalityProviderKey,
		params.CovenantPks,
		params.CovenantQuorum,
		vaultData.StakingAmount,
		vaultData.ChainID,
		vaultData.ChainIdUserAddress,
		vaultData.ChainIdSmartContractAddress,
		vaultData.MintingAmount,
		&chaincfg.SigNetParams,
	)
	require.NoError(t, err)

	slashingOrLostKeySpendInfo, err := vaultInfo.SlashingOrLostKeyPathSpendInfo()
	require.NoError(t, err)

	slashingOrLostKeyInfo, err := btcvault.BuildSpendingInfo(
		slashingOrLostKeyPathInfoType,
		vaultData.StakerKey,
		[]*btcec.PublicKey{vaultData.FinalityProviderKey},
		params.CovenantPks,
		params.CovenantQuorum,
		vaultData.StakingAmount-params.UnbondingFee,
		&chaincfg.SigNetParams,
	)
	require.NoError(t, err)

	slashingOrLostKeyTx := wire.NewMsgTx(2)
	witness, err := btcvault.CreateWitness(slashingOrLostKeySpendInfo, [][]byte{})
	require.NoError(t, err)
	slashingOrLostKeyTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(vaultTxHash, vaultOutputIdx), nil, witness))
	slashingOrLostKeyTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum
	slashingOrLostKeyTx.AddTxOut(slashingOrLostKeyInfo.Output)

	return btcutil.NewTx(slashingOrLostKeyTx)
}

func GenerateBurnWithoutDAppTxFromVault(t *testing.T, r *rand.Rand, params *parser.ParsedVersionedGlobalParams, vaultData *TestVaultData, vaultTxHash *chainhash.Hash, vaultOutputIdx uint32) *btcutil.Tx {
	vaultInfo, err := btcvault.BuildV0IdentifiableVaultOutputs(
		params.Tag,
		vaultData.StakerKey,
		vaultData.FinalityProviderKey,
		params.CovenantPks,
		params.CovenantQuorum,
		vaultData.StakingAmount,
		vaultData.ChainID,
		vaultData.ChainIdUserAddress,
		vaultData.ChainIdSmartContractAddress,
		vaultData.MintingAmount,
		&chaincfg.SigNetParams,
	)
	require.NoError(t, err)

	burnwithoutDAppSpendInfo, err := vaultInfo.BurnWithoutDAppPathSpendInfo()
	require.NoError(t, err)

	burnwithoutDAppTx := wire.NewMsgTx(2)
	witness, err := btcvault.CreateWitness(burnwithoutDAppSpendInfo, [][]byte{})
	require.NoError(t, err)

	burnwithoutDAppTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(vaultTxHash, vaultOutputIdx), nil, witness))
	// add a dump input
	randomOutput := &wire.OutPoint{
		Hash:  chainhash.HashH(bbndatagen.GenRandomByteArray(r, 10)),
		Index: r.Uint32(),
	}
	burnwithoutDAppTx.AddTxIn(wire.NewTxIn(randomOutput, bbndatagen.GenRandomByteArray(r, 10), nil))

	return btcutil.NewTx(burnwithoutDAppTx)
}
