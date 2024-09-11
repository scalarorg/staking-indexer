package indexer_test

import (
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	bbndatagen "github.com/babylonchain/babylon/testutil/datagen"
	"github.com/babylonchain/networks/parameters/parser"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/scalarorg/btc-vault/btcvault"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	// "github.com/babylonchain/staking-indexer/btcscanner"
	// "github.com/babylonchain/staking-indexer/config"
	// "github.com/babylonchain/staking-indexer/indexer"
	// "github.com/babylonchain/staking-indexer/testutils"
	// "github.com/babylonchain/staking-indexer/testutils/datagen"
	// "github.com/babylonchain/staking-indexer/types"
	"github.com/scalarorg/staking-indexer/btcscanner"
	"github.com/scalarorg/staking-indexer/config"
	"github.com/scalarorg/staking-indexer/indexer"
	"github.com/scalarorg/staking-indexer/testutils"
	"github.com/scalarorg/staking-indexer/testutils/datagen"
	"github.com/scalarorg/staking-indexer/types"
)

type VaultTxData struct {
	VaultTx   *btcutil.Tx
	VaultData *datagen.TestVaultData
}

type VaultEvent struct {
	VaultTx     *btcutil.Tx
	VaultTxData *datagen.TestVaultData
	Height      int32
	IsOverflow  bool
}

type TestScenarioVault struct {
	VersionedParams *parser.ParsedGlobalParams
	VaultEvents     []*VaultEvent
	Blocks          []*types.IndexedBlock
	TvlToHeight     map[int32]btcutil.Amount
	Tvl             btcutil.Amount
}

func NewTestScenarioVault(r *rand.Rand, t *testing.T, versionedParams *parser.ParsedGlobalParams, vaultChance int, numEvents int, checkOverflow bool) *TestScenarioVault {
	startHeight := r.Int31n(1000) + 1 + int32(versionedParams.Versions[0].ActivationHeight)
	lastEventHeight := startHeight
	vaultEvents := make([]*VaultEvent, 0)
	tvl := btcutil.Amount(0)
	txsPerHeight := make(map[int32][]*btcutil.Tx)
	tvlToHeight := make(map[int32]btcutil.Amount)

	// create numEvents events
	for i := 0; i < numEvents; i++ {
		// randomly select a height at which the event should be happening
		height := lastEventHeight + r.Int31n(3)
		p := versionedParams.GetVersionedGlobalParamsByHeight(uint64(height))
		require.NotNil(t, p)
		txs, ok := txsPerHeight[height]
		if !ok {
			// new height
			txs = make([]*btcutil.Tx, 0)
		}

		// stakingChance/100 chance to be a staking event, or there are
		// no active staking events created, otherwise, to be an unbonding event
		if r.Intn(100) < vaultChance {
			vaultEvent := buildVaultEvent(r, t, height, p)
			if checkOverflow && isOverflow(uint64(height), tvl, p) {
				vaultEvent.IsOverflow = true
			} else {
				tvl += vaultEvent.VaultTxData.StakingAmount
			}
			vaultEvents = append(vaultEvents, vaultEvent)
			txs = append(txs, vaultEvent.VaultTx)
		} else {
			require.True(t, tvl >= 0)
		}

		txsPerHeight[height] = txs
		tvlToHeight[height] = tvl
		lastEventHeight = height
	}

	blocks := make([]*types.IndexedBlock, 0)
	for h := startHeight; h <= lastEventHeight; h++ {
		block := &types.IndexedBlock{
			Height: h,
			Header: &wire.BlockHeader{Timestamp: time.Now()},
			Txs:    txsPerHeight[h],
		}
		blocks = append(blocks, block)
		_, ok := tvlToHeight[h]
		if !ok {
			tvlToHeight[h] = tvlToHeight[h-1]
		}
	}

	return &TestScenarioVault{
		VersionedParams: versionedParams,
		VaultEvents:     vaultEvents,
		Blocks:          blocks,
		TvlToHeight:     tvlToHeight,
		Tvl:             tvl,
	}
}

func buildVaultEvent(r *rand.Rand, t *testing.T, height int32, p *parser.ParsedVersionedGlobalParams) *VaultEvent {
	vaultData := datagen.GenerateTestVaultData(t, r, p)
	_, vaultTx := datagen.GenerateVaultTxFromTestData(t, r, p, vaultData)

	return &VaultEvent{
		VaultTx:     vaultTx,
		VaultTxData: vaultData,
		Height:      height,
	}
}

func FuzzBlockHandlerScalar(f *testing.F) {
	// Note: before committing, it should be tested with large seed
	// to avoid flaky
	// small seed for ci because db open/close is slow
	bbndatagen.AddRandomSeedsToFuzzer(f, 50)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))

		homePath := filepath.Join(t.TempDir(), "indexer")
		cfg := config.DefaultConfigWithHome(homePath)

		n := r.Intn(100) + 1
		sysParamsVersions := datagen.GenerateGlobalParamsVersions(r, t)
		testScenario := NewTestScenarioVault(r, t, sysParamsVersions, 80, n, true)

		db, err := cfg.DatabaseConfig.GetDbBackend()
		require.NoError(t, err)
		chainUpdateInfoChan := make(chan *btcscanner.ChainUpdateInfo)
		mockBtcScanner := NewMockedBtcScanner(t, chainUpdateInfoChan)
		stakingIndexer, err := indexer.NewStakingIndexer(cfg, zap.NewNop(), NewMockedConsumer(t), db, sysParamsVersions, mockBtcScanner)
		require.NoError(t, err)

		defer func() {
			err = db.Close()
			require.NoError(t, err)
		}()

		for _, b := range testScenario.Blocks {
			err := stakingIndexer.HandleConfirmedBlockScalar(b)
			require.NoError(t, err)
			tvl, err := stakingIndexer.GetConfirmedTvl()
			require.NoError(t, err)
			require.Equal(t, uint64(testScenario.TvlToHeight[b.Height]), tvl)
		}
		tvl, err := stakingIndexer.GetConfirmedTvl()
		require.NoError(t, err)
		require.Equal(t, uint64(testScenario.Tvl), tvl)

		for _, vaultEv := range testScenario.VaultEvents {
			storedTx, err := stakingIndexer.GetVaultTxByHash(vaultEv.VaultTx.Hash())
			require.NoError(t, err)
			require.NotNil(t, storedTx)
			require.Equal(t, vaultEv.VaultTx.Hash().String(), storedTx.Tx.TxHash().String())
			require.True(t, testutils.PubKeysEqual(vaultEv.VaultTxData.StakerKey, storedTx.StakerPk))
			require.True(t, testutils.PubKeysEqual(vaultEv.VaultTxData.FinalityProviderKey, storedTx.DAppPk))
			require.Equal(t, vaultEv.IsOverflow, storedTx.IsOverflow)
		}

		// replay the blocks and the result should be the same
		for _, b := range testScenario.Blocks {
			err := stakingIndexer.HandleConfirmedBlockScalar(b)
			require.NoError(t, err)
		}
		tvl, err = stakingIndexer.GetConfirmedTvl()
		require.NoError(t, err)
		require.Equal(t, uint64(testScenario.Tvl), tvl)

		for _, vaultEv := range testScenario.VaultEvents {
			storedTx, err := stakingIndexer.GetVaultTxByHash(vaultEv.VaultTx.Hash())
			require.NoError(t, err)
			require.NotNil(t, storedTx)
			require.Equal(t, vaultEv.VaultTx.Hash().String(), storedTx.Tx.TxHash().String())
			require.True(t, testutils.PubKeysEqual(vaultEv.VaultTxData.StakerKey, storedTx.StakerPk))
			require.True(t, testutils.PubKeysEqual(vaultEv.VaultTxData.FinalityProviderKey, storedTx.DAppPk))
			require.Equal(t, vaultEv.IsOverflow, storedTx.IsOverflow)
		}

		// calculate unconfirmed tvl
		testUnconfirmedScenario := NewTestScenarioVault(r, t, sysParamsVersions, 80, n, false)
		unconfirmedTvl, err := stakingIndexer.CalculateTvlInUnconfirmedBlocksScalar(testUnconfirmedScenario.Blocks)
		require.NoError(t, err)
		require.Equal(t, testUnconfirmedScenario.Tvl, unconfirmedTvl)
	})
}

func FuzzValidateSpendingTxFromVault(f *testing.F) {
	bbndatagen.AddRandomSeedsToFuzzer(f, 10)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))

		homePath := filepath.Join(t.TempDir(), "indexer")
		cfg := config.DefaultConfigWithHome(homePath)

		sysParamsVersions := datagen.GenerateGlobalParamsVersions(r, t)

		db, err := cfg.DatabaseConfig.GetDbBackend()
		require.NoError(t, err)
		chainUpdateInfoChan := make(chan *btcscanner.ChainUpdateInfo)
		mockBtcScanner := NewMockedBtcScanner(t, chainUpdateInfoChan)
		stakingIndexer, err := indexer.NewStakingIndexer(cfg, zap.NewNop(), NewMockedConsumer(t), db, sysParamsVersions, mockBtcScanner)
		require.NoError(t, err)
		defer func() {
			err = db.Close()
			require.NoError(t, err)
		}()

		// Select the first params versions to play with
		params := sysParamsVersions.Versions[0]
		// 1. generate and add a valid staking tx to the indexer
		vaultData := datagen.GenerateTestVaultData(t, r, params)
		_, vaultTx := datagen.GenerateVaultTxFromTestData(t, r, params, vaultData)
		// For a valid tx, its btc height is always larger than the activation height
		mockedHeight := uint64(params.ActivationHeight) + 1
		err = stakingIndexer.ProcessVaultTx(
			vaultTx.MsgTx(),
			getParsedVaultData(vaultData, vaultTx.MsgTx(), params),
			mockedHeight, time.Now(), params)
		require.NoError(t, err)
		storedVaultTx, err := stakingIndexer.GetVaultTxByHash(vaultTx.Hash())
		require.NoError(t, err)
		require.NotNil(t, storedVaultTx)

		// 2.1. test ValidateBurningTxFromVault with valid burning tx
		burningTxFromVault := datagen.GenerateBurningTxFromVault(t, r, params, vaultData, vaultTx.Hash(), 0)
		_, err = stakingIndexer.ValidateSpendingTxFromVault(burningTxFromVault.MsgTx(), storedVaultTx, 0, params)
		require.NoError(t, err)

		// 3.1. test Validate BuringTxFromVault with invalid spending input index, expect panic
		require.Panics(t, func() {
			_, _ = stakingIndexer.ValidateSpendingTxFromVault(burningTxFromVault.MsgTx(), storedVaultTx, 1, params)
		})

		// 2.2. test ValidateSlashingOrLostKeyTxFromVault with valid slashing tx
		slashingTxFromVault := datagen.GenerateSlashingOrLostKeyTxFromVault(t, r, params, vaultData, vaultTx.Hash(), 0)
		_, err = stakingIndexer.ValidateSpendingTxFromVault(slashingTxFromVault.MsgTx(), storedVaultTx, 0, params)
		require.NoError(t, err)

		// 3.2. test ValidateSlashingOrLostKeyTxFromVault with invalid spending input index, expect panic
		require.Panics(t, func() {
			_, _ = stakingIndexer.ValidateSpendingTxFromVault(slashingTxFromVault.MsgTx(), storedVaultTx, 1, params)
		})

		// 2.3. test BurnWithoutDAppTxFromVault with valid burning tx
		burnWithoutDAppTxFromVault := datagen.GenerateBurnWithoutDAppTxFromVault(t, r, params, vaultData, vaultTx.Hash(), 0)
		_, err = stakingIndexer.ValidateSpendingTxFromVault(burnWithoutDAppTxFromVault.MsgTx(), storedVaultTx, 0, params)
		require.NoError(t, err)

		// 3.3. test BurnWithoutDAppTxFromVault with invalid spending input index, expect panic
		require.Panics(t, func() {
			_, _ = stakingIndexer.ValidateSpendingTxFromVault(burnWithoutDAppTxFromVault.MsgTx(), storedVaultTx, 1, params)
		})

	})
}

func getParsedVaultData(data *datagen.TestVaultData, tx *wire.MsgTx, params *parser.ParsedVersionedGlobalParams) *btcvault.ParsedV0VaultTx {
	return &btcvault.ParsedV0VaultTx{
		VaultOutput:       tx.TxOut[0],
		VaultOutputIdx:    0,
		OpReturnOutput:    tx.TxOut[1],
		OpReturnOutputIdx: 1,
		OpReturnData: &btcvault.V0OpReturnData{
			Tag:                       params.Tag,
			Version:                   0,
			StakerPublicKey:           &btcvault.XonlyPubKey{PubKey: data.StakerKey},
			FinalityProviderPublicKey: &btcvault.XonlyPubKey{PubKey: data.FinalityProviderKey},
		},
		PayloadOutput:    tx.TxOut[2],
		PayloadOutputIdx: 2,
		PayloadOpReturnData: &btcvault.PayloadOpReturnData{
			ChainID:                     data.ChainID,
			ChainIdUserAddress:          data.ChainIdUserAddress,
			ChainIdSmartContractAddress: data.ChainIdSmartContractAddress,
			Amount:                      data.MintingAmount,
		},
	}
}
