package indexer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/babylonchain/babylon/btcstaking"
	"github.com/babylonchain/networks/parameters/parser"

	// "github.com/babylonchain/staking-indexer/indexerstore"
	// "github.com/babylonchain/staking-indexer/types"
	// queuecli "github.com/babylonchain/staking-queue-client/client"
	"github.com/scalarorg/staking-indexer/indexerstore"
	"github.com/scalarorg/staking-indexer/types"
	queuecli "github.com/scalarorg/staking-queue-client/client"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/scalarorg/btc-vault/btcvault"

	"go.uber.org/zap"
)

const (
	burningPathInfoType           int = 0
	slashingOrLostKeyPathInfoType int = 1
	burnWithoutDAppPathInfoType   int = 2
)

func (si *StakingIndexer) blocksScalarEventLoop() {
	defer si.wg.Done()

	for {
		select {
		case update := <-si.btcScanner.ChainUpdateInfoChan():
			confirmedBlocks := update.ConfirmedBlocks
			for _, block := range confirmedBlocks {
				si.logger.Info("received confirmed block",
					zap.Int32("height", block.Height))

				if err := si.HandleConfirmedBlockScalar(block); err != nil {
					// this indicates systematic failure
					si.logger.Fatal("failed to handle block",
						zap.Int32("height", block.Height),
						zap.Error(err))
				}
			}

			if err := si.processUnconfirmedInfoScalar(update.UnconfirmedBlocks); err != nil {
				si.logger.Error("failed to process unconfirmed blocks",
					zap.Error(err))

				failedProcessingUnconfirmedBlockCounter.Inc()
			}

		case <-si.quit:
			si.logger.Info("closing the confirmed blocks loop")
			return
		}
	}
}

// based on indexer.go - compatible with the scalar vault
// processUnconfirmedInfoScalar processes information from given unconfirmed blocks
// It follows the steps below:
// 1. iterate all txs of each unconfirmed block to identify vault and ? transactions,
// and calculate total unconfirmed tvl
// 2. get the current confirmed tvl
// 3. push unconfirmed info event to the queue
// 4. record metrics
// This method will not make any change to the system state.
func (si *StakingIndexer) processUnconfirmedInfoScalar(unconfirmedBlocks []*types.IndexedBlock) error {
	if len(unconfirmedBlocks) == 0 {
		si.logger.Info("no unconfirmed blocks, skip processing unconfirmed info")
		return nil
	}

	si.logger.Info("processing unconfirmed blocks",
		zap.Int32("start_height", unconfirmedBlocks[0].Height),
		zap.Int32("end_height", unconfirmedBlocks[len(unconfirmedBlocks)-1].Height))

	tipBlockCache := unconfirmedBlocks[len(unconfirmedBlocks)-1]

	tvlInUnconfirmedBlocks, err := si.CalculateTvlInUnconfirmedBlocksScalar(unconfirmedBlocks)
	if err != nil {
		return fmt.Errorf("failed to calculate unconfirmed tvl: %w", err)
	}

	confirmedTvl, err := si.GetConfirmedTvl()
	if err != nil {
		return fmt.Errorf("failed to get the confirmed TVL: %w", err)
	}

	unconfirmedTvl := btcutil.Amount(confirmedTvl) + tvlInUnconfirmedBlocks
	if unconfirmedTvl < 0 {
		return fmt.Errorf("total tvl %d is negative", unconfirmedTvl)
	}

	si.logger.Info("successfully calculated unconfirmed TVL",
		zap.Int32("tip_height", tipBlockCache.Height),
		zap.Uint64("confirmed_tvl", confirmedTvl),
		zap.Int64("tvl_in_unconfirmed_blocks", int64(tvlInUnconfirmedBlocks)),
		zap.Int64("unconfirmed_tvl", int64(unconfirmedTvl)))

	btcInfoEvent := queuecli.NewBtcInfoEvent(uint64(tipBlockCache.Height), confirmedTvl, uint64(unconfirmedTvl))
	if err := si.consumer.PushBtcInfoEvent(&btcInfoEvent); err != nil {
		return fmt.Errorf("failed to push the unconfirmed event: %w", err)
	}

	// record metrics
	lastCalculatedTvl.Set(float64(unconfirmedTvl))

	return nil
}

func (si *StakingIndexer) CalculateTvlInUnconfirmedBlocksScalar(unconfirmedBlocks []*types.IndexedBlock) (btcutil.Amount, error) {
	tvl := btcutil.Amount(0)
	unconfirmedVaultTxs := make(map[chainhash.Hash]*indexerstore.StoredVaultTransaction)
	for _, b := range unconfirmedBlocks {
		params, err := si.getVersionedParams(uint64(b.Height))
		if err != nil {
			return 0, err
		}

		for _, tx := range b.Txs {
			msgTx := tx.MsgTx()
			if len(msgTx.TxOut) < 4 {
				// Vault tx must have at least 4 outputs
				continue
			}
			// 1. try to parse vault tx
			vaultData, err := si.tryParseVaultTx(msgTx, params)
			if err == nil {
				// this is a new vault tx, validate it against vault requirement
				if err := si.validateVaultTx(params, vaultData); err != nil {
					// Note: the metrics and logs will be repeated when the tx is confirmed
					invalidTransactionsCounter.WithLabelValues("unconfirmed_vault_transaction").Inc()
					si.logger.Warn("found an invalid vault tx",
						zap.String("tx_hash", msgTx.TxHash().String()),
						zap.Int32("height", b.Height),
						zap.Bool("is_confirmed", false),
						zap.Error(err),
					)

					// invalid vault tx will not be counted for TVL
					continue
				}

				tvl += btcutil.Amount(vaultData.VaultOutput.Value)
				// save the vault tx in memory for later identifying spending tx
				vaultValue := uint64(vaultData.VaultOutput.Value)
				unconfirmedVaultTxs[msgTx.TxHash()] = &indexerstore.StoredVaultTransaction{
					Tx:                          msgTx,
					StakingOutputIdx:            uint32(vaultData.VaultOutputIdx),
					InclusionHeight:             uint64(b.Height),
					StakerPk:                    vaultData.OpReturnData.StakerPublicKey.PubKey,
					StakingValue:                vaultValue,
					DAppPk:                      vaultData.OpReturnData.FinalityProviderPublicKey.PubKey,
					ChainID:                     vaultData.PayloadOpReturnData.ChainID,
					ChainIdUserAddress:          vaultData.PayloadOpReturnData.ChainIdUserAddress,
					ChainIdSmartContractAddress: vaultData.PayloadOpReturnData.ChainIdSmartContractAddress,
					MintingAmount:               vaultData.PayloadOpReturnData.Amount,
				}

				si.logger.Info("found an unconfirmed vault tx",
					zap.String("tx_hash", msgTx.TxHash().String()),
					zap.Uint64("value", vaultValue),
					zap.Int32("height", b.Height))

				continue
			}

			// 2. not a vault tx, check whether it spends a stored vault tx
			vaultTxs, _ := si.getSpentVaultTxs(msgTx)
			if len(vaultTxs) == 0 {
				// it does not spend a stored vault tx, check whether it spends
				// an unconfirmed vault tx
				// check it by compare the outpoint of previous tx with the tx hash of the unconfirmed vault tx
				vaultTxs, _ = getSpentFromVaultTxs(msgTx, unconfirmedVaultTxs)
			}
			for _, vaultTx := range vaultTxs {
				// 3. is a spending tx, check whether it is a valid spending tx
				paramsFromVaultTxHeight, err := si.getVersionedParams(vaultTx.InclusionHeight)
				if err != nil {
					return 0, err
				}
				isBurning, _ := si.IsValidSpendingTx(burningPathInfoType, msgTx, vaultTx, paramsFromVaultTxHeight)
				isSlashingOrLostKey, _ := si.IsValidSpendingTx(slashingOrLostKeyPathInfoType, msgTx, vaultTx, paramsFromVaultTxHeight)
				isBurnWithoutDApp, _ := si.IsValidSpendingTx(burnWithoutDAppPathInfoType, msgTx, vaultTx, paramsFromVaultTxHeight)

				if !isBurning && !isSlashingOrLostKey && !isBurnWithoutDApp {
					invalidTransactionsCounter.WithLabelValues("unconfirmed_unknown_transaction").Inc()
				} else {
					si.logger.Warn("found a tx that spends the vault tx",
						zap.String("tx_hash", msgTx.TxHash().String()),
						zap.String("vault_tx_hash", vaultTx.Tx.TxHash().String()))
					if !vaultTx.IsOverflow {
						tvl -= btcutil.Amount(vaultTx.StakingValue)
					}
				}
			}
		}
	}

	return tvl, nil
}

// HandleConfirmedBlockScalar iterates through the tx set of a confirmed block and
// parse the vault, burning, slashingOrLostKey and burnignWithoutDApp txs if there are any.
func (si *StakingIndexer) HandleConfirmedBlockScalar(b *types.IndexedBlock) error {
	params, err := si.getVersionedParams(uint64(b.Height))
	if err != nil {
		return err
	}
	for _, tx := range b.Txs {
		msgTx := tx.MsgTx()
		// 1. try to parse vault tx
		vaultData, err := si.tryParseVaultTx(msgTx, params)
		if err == nil {
			si.logger.Info("[handleConfirmedBlock] found a vault tx", zap.Any("vaultData", vaultData))

			if err := si.ProcessVaultTx(
				msgTx, vaultData, uint64(b.Height), b.Header.Timestamp, params,
			); err != nil {
				// record metrics
				failedProcessingVaultTxsCounter.Inc()
				return fmt.Errorf("failed to process the vault tx: %w", err)
			}
			// should not use *continue* here as a special case is
			// the tx could be a vault tx as well as a withdrawal
			// tx that spends the previous vault tx

		} else {
			si.logger.Warn("No vault tx founded", zap.Error(err))
		}

		// 2. not a vault tx, check whether it is a spending tx from a previous
		// vault tx, and handle it if so
		vaultTxs, spendVaultInputIndexes := si.getSpentVaultTxs(msgTx)
		if len(vaultTxs) > 0 {
			si.logger.Info("[handleConfirmedBlock] found a spending tx from vault", zap.Any("vaultTxs", vaultTxs), zap.Any("spendVaultInputIndexes", spendVaultInputIndexes))
		}
		for i, vaultTx := range vaultTxs {
			// this is a spending tx from a previous vault tx, further process it
			// by checking whether it is unbonding or withdrawal
			si.logger.Info("found a spending tx from vault", zap.Any("vaultTx", vaultTx), zap.Any("spendVaultInputIndexes", spendVaultInputIndexes))
			if err := si.handleSpendingVaultTransaction(
				msgTx, vaultTx, spendVaultInputIndexes[i],
				uint64(b.Height)); err != nil {
				return err
			}
		}
	}
	if err := si.is.SaveLastProcessedHeight(uint64(b.Height)); err != nil {
		return fmt.Errorf("failed to save the last processed height: %w", err)
	}

	// record metrics
	lastProcessedBtcHeight.Set(float64(b.Height))
	return nil
}

func (si *StakingIndexer) handleSpendingVaultTransaction(
	tx *wire.MsgTx,
	vaultTx *indexerstore.StoredVaultTransaction,
	spendingInputIndex int,
	height uint64,
) error {
	vaultTxHash := vaultTx.Tx.TxHash()
	paramsFromVaultTxHeight, err := si.getVersionedParams(vaultTx.InclusionHeight)
	if err != nil {
		return err
	}

	typeOfSpend, err := si.ValidateSpendingTxFromVault(tx, vaultTx, spendingInputIndex, paramsFromVaultTxHeight)

	if err != nil {
		if errors.Is(err, ErrInvalidSpendingTx) {
			invalidTransactionsCounter.WithLabelValues("confirmed_spending_vault_transactions").Inc()
			si.logger.Warn("found an invalid spending tx from vault",
				zap.String("tx_hash", tx.TxHash().String()),
				zap.Uint64("height", height),
				zap.Bool("is_confirmed", true),
				zap.Error(err),
			)

			return nil
		}
		failedProcessingSpendingTxsFromVaultCounter.Inc()
		return err
	}

	if err := si.processSpendingVaultTx(typeOfSpend, tx, &vaultTxHash, height); err != nil {
		// record metrics
		if typeOfSpend == burningPathInfoType {
			failedProcessingBurningTxsFromVaultCounter.Inc()
		} else if typeOfSpend == slashingOrLostKeyPathInfoType {
			failedProcessingSlashingOrLostKeyTxsFromVaultCounter.Inc()
		} else if typeOfSpend == burnWithoutDAppPathInfoType {
			failedProcessingBurnWithoutDAppTxsFromVaultCounter.Inc()
		}

		return err
	}

	return nil
}

func (si *StakingIndexer) ValidateSpendingTxFromVault(
	tx *wire.MsgTx,
	vaultTx *indexerstore.StoredVaultTransaction,
	spendingInputIdx int,
	params *parser.ParsedVersionedGlobalParams,
) (int, error) {
	// re-build the time-lock path script and check whether the script from
	// the witness matches
	vaultInfo, err := btcvault.BuildVaultInfo(
		vaultTx.StakerPk,
		[]*btcec.PublicKey{vaultTx.DAppPk},
		params.CovenantPks,
		params.CovenantQuorum,
		btcutil.Amount(vaultTx.StakingValue),
		&si.cfg.BTCNetParams,
	)
	if err != nil {
		return -1, fmt.Errorf("failed to rebuid the vault info: %w", err)
	}

	burningPathInfo, err := vaultInfo.BurnPathSpendInfo()
	if err != nil {
		return -1, fmt.Errorf("failed to get the burning path spend info: %w", err)
	}

	slashingOrLostKeyPathInfo, err := vaultInfo.SlashingOrLostKeyPathSpendInfo()
	if err != nil {
		return -1, fmt.Errorf("failed to get the slashing or lost key path spend info: %w", err)
	}

	burnWithoutDAppPathInfo, err := vaultInfo.BurnWithoutDAppPathSpendInfo()
	if err != nil {
		return -1, fmt.Errorf("failed to get the burn without dapp path spend info: %w", err)
	}

	witness := tx.TxIn[spendingInputIdx].Witness
	if len(witness) < 2 {
		panic(fmt.Errorf("spending tx should have at least 2 elements in witness, got %d", len(witness)))
	}

	scriptFromWitness := tx.TxIn[spendingInputIdx].Witness[len(tx.TxIn[spendingInputIdx].Witness)-2]

	checkBurningPath := bytes.Equal(burningPathInfo.GetPkScriptPath(), scriptFromWitness)
	checkSlashingOrLostKeyPath := bytes.Equal(slashingOrLostKeyPathInfo.GetPkScriptPath(), scriptFromWitness)
	checkBurnWithoutDAppPath := bytes.Equal(burnWithoutDAppPathInfo.GetPkScriptPath(), scriptFromWitness)

	if !checkSlashingOrLostKeyPath && !checkBurnWithoutDAppPath && !checkBurningPath {
		return -1, fmt.Errorf("%w: the tx does not unlock any spending path", ErrInvalidSpendingTx)
	}

	// we sure that the tx spends the correct vault output
	var typeOfSpend int
	if checkBurningPath {
		typeOfSpend = burningPathInfoType
	} else if checkSlashingOrLostKeyPath {
		typeOfSpend = slashingOrLostKeyPathInfoType
	} else if checkBurnWithoutDAppPath {
		typeOfSpend = burnWithoutDAppPathInfoType
	}

	return typeOfSpend, nil
}

// getSpentVaultTxs find all the stored vault txs spent by the given tx.
// It returns the found vault txs and the spending input index of the given tx
func (si *StakingIndexer) getSpentVaultTxs(tx *wire.MsgTx) ([]*indexerstore.StoredVaultTransaction, []int) {
	storedVaultTxs := make([]*indexerstore.StoredVaultTransaction, 0)
	spendingInputIndexes := make([]int, 0)
	for i, txIn := range tx.TxIn {
		maybeStakingTxHash := txIn.PreviousOutPoint.Hash
		vaultTx, err := si.GetVaultTxByHash(&maybeStakingTxHash)
		if err != nil || vaultTx == nil {
			continue
		}

		// this ensures the spending tx spends the correct vault output
		if txIn.PreviousOutPoint.Index != vaultTx.StakingOutputIdx {
			continue
		}

		storedVaultTxs = append(storedVaultTxs, vaultTx)
		spendingInputIndexes = append(spendingInputIndexes, i)
	}

	return storedVaultTxs, spendingInputIndexes
}

// getSpentVaultTxs find all the vault txs from the given ones spent by the given tx.
// It returns the found vault txs and the spending input index of the given tx
func getSpentFromVaultTxs(
	tx *wire.MsgTx,
	stakingTxs map[chainhash.Hash]*indexerstore.StoredVaultTransaction,
) ([]*indexerstore.StoredVaultTransaction, []int) {
	storedVaultTxs := make([]*indexerstore.StoredVaultTransaction, 0)
	spendingInputIndexes := make([]int, 0)
	for i, txIn := range tx.TxIn {
		maybeVaultTxHash := txIn.PreviousOutPoint.Hash
		stakingTx, exists := stakingTxs[maybeVaultTxHash]
		if !exists {
			continue
		}

		// this ensures the spending tx spends the correct vault output
		if txIn.PreviousOutPoint.Index != stakingTx.StakingOutputIdx {
			continue
		}

		storedVaultTxs = append(storedVaultTxs, stakingTx)
		spendingInputIndexes = append(spendingInputIndexes, i)
	}

	return storedVaultTxs, spendingInputIndexes
}

// IsValidSpendingTx tries to identify a tx is a valid spending tx
// It returns error when (1) it fails to verify the spending tx due
// to invalid parameters, and (2) the tx spends the spending path
// but is invalid
func (si *StakingIndexer) IsValidSpendingTx(typeOfSpend int, tx *wire.MsgTx, vaultTx *indexerstore.StoredVaultTransaction, params *parser.ParsedVersionedGlobalParams) (bool, error) {
	// 1. an spending tx must be a transfer tx
	if err := btcstaking.IsTransferTx(tx); err != nil {
		return false, nil
	}

	// 2. an spending tx must spend the vault output
	vaultTxHash := vaultTx.Tx.TxHash()
	if !tx.TxIn[0].PreviousOutPoint.Hash.IsEqual(&vaultTxHash) {
		return false, nil
	}
	if tx.TxIn[0].PreviousOutPoint.Index != vaultTx.StakingOutputIdx {
		return false, nil
	}

	// 3. re-build the spending path script and check whether the script from
	// the witness matches
	// We have 3 path :
	// + burning
	// + slashingOrLostKey
	// + burnWithoutDApp
	vaultInfo, err := btcvault.BuildVaultInfo(
		vaultTx.StakerPk,
		[]*btcec.PublicKey{vaultTx.DAppPk},
		params.CovenantPks,
		params.CovenantQuorum,
		btcutil.Amount(vaultTx.StakingValue),
		&si.cfg.BTCNetParams,
	)
	if err != nil {
		return false, fmt.Errorf("failed to rebuid the vault info: %w", err)
	}

	witness := tx.TxIn[0].Witness
	if len(witness) < 2 {
		panic(fmt.Errorf("spending tx should have at least 2 elements in witness, got %d", len(witness)))
	}

	scriptFromWitness := tx.TxIn[0].Witness[len(tx.TxIn[0].Witness)-2]

	var spendingPathInfo *btcvault.SpendInfo
	if typeOfSpend == burningPathInfoType {
		spendingPathInfo, err = vaultInfo.BurnPathSpendInfo()
		if err != nil {
			return false, fmt.Errorf("failed to get the burning path spend info: %w", err)
		}
	} else if typeOfSpend == slashingOrLostKeyPathInfoType {
		spendingPathInfo, err = vaultInfo.SlashingOrLostKeyPathSpendInfo()
		if err != nil {
			return false, fmt.Errorf("failed to get the slashing or lost key path spend info: %w", err)
		}
	} else if typeOfSpend == burnWithoutDAppPathInfoType {
		spendingPathInfo, err = vaultInfo.BurnWithoutDAppPathSpendInfo()
		if err != nil {
			return false, fmt.Errorf("failed to get the burn without dapp path spend info: %w", err)
		}
	}

	if !bytes.Equal(spendingPathInfo.GetPkScriptPath(), scriptFromWitness) {
		// not burning tx as it does not unlock the burning path
		return false, nil
	}

	return true, nil
}

func (si *StakingIndexer) ProcessVaultTx(
	tx *wire.MsgTx,
	vaultData *btcvault.ParsedV0VaultTx,
	height uint64, timestamp time.Time,
	params *parser.ParsedVersionedGlobalParams,
) error {
	var (
		// whether the vault tx is overflow
		isOverflow bool
	)

	si.logger.Info("found a vault tx",
		zap.Uint64("height", height),
		zap.String("tx_hash", tx.TxHash().String()),
		zap.Int64("value", vaultData.VaultOutput.Value),
	)

	// check whether the vault tx already exists in db
	// if so, get the isOverflow from the data in db
	// otherwise, check it if the current tvl already reaches
	// the cap
	txHash := tx.TxHash()
	storedVaultTx, err := si.is.GetVaultTransaction(&txHash)
	if err != nil {
		return err
	}
	if storedVaultTx != nil {
		isOverflow = storedVaultTx.IsOverflow
	} else {
		// this is a new vault tx, validate it against vault requirement
		if err := si.validateVaultTx(params, vaultData); err != nil {
			invalidTransactionsCounter.WithLabelValues("confirmed_vault_transaction").Inc()
			si.logger.Warn("found an invalid vault tx",
				zap.String("tx_hash", tx.TxHash().String()),
				zap.Uint64("height", height),
				zap.Bool("is_confirmed", true),
				zap.Error(err),
			)
			// TODO handle invalid vault tx (storing and pushing events)
			return nil
		}

		// check if the vault tvl is overflow with this vault tx
		vaultOverflow, err := si.isOverflow(height, params)
		if err != nil {
			return fmt.Errorf("failed to check the overflow of vault tx: %w", err)
		}

		isOverflow = vaultOverflow
	}

	if isOverflow {
		si.logger.Info("the vault tx is overflow",
			zap.String("tx_hash", tx.TxHash().String()))
	}

	// add the vault transaction to the system state
	if err := si.addVaultTransaction(
		height, timestamp, tx,
		vaultData.OpReturnData.StakerPublicKey.PubKey,
		vaultData.OpReturnData.FinalityProviderPublicKey.PubKey,
		uint64(vaultData.VaultOutput.Value),
		uint32(vaultData.VaultOutputIdx),
		vaultData.PayloadOpReturnData.ChainID,
		vaultData.PayloadOpReturnData.ChainIdUserAddress,
		vaultData.PayloadOpReturnData.ChainIdSmartContractAddress,
		vaultData.PayloadOpReturnData.Amount,
		isOverflow,
	); err != nil {
		return err
	}
	return nil
}

// addVaultTransaction pushes the vault event, saves it to the database
// and records metrics
func (si *StakingIndexer) addVaultTransaction(
	height uint64,
	timestamp time.Time,
	tx *wire.MsgTx,
	stakerPk *btcec.PublicKey,
	dAppPk *btcec.PublicKey,
	stakingValue uint64,
	stakingOutputIndex uint32,
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	amountMinting []byte,
	isOverflow bool,
) error {
	txHex, err := getTxHex(tx)
	if err != nil {
		return err
	}

	vaultEvent := queuecli.NewActiveVaultEvent(
		tx.TxHash().String(),
		txHex,
		hex.EncodeToString(schnorr.SerializePubKey(stakerPk)),
		hex.EncodeToString(schnorr.SerializePubKey(dAppPk)),
		stakingValue,
		height,
		timestamp.Unix(),
		uint64(stakingOutputIndex),
		chainID,
		chainIdUserAddress,
		chainIdSmartContractAddress,
		amountMinting,
		isOverflow,
	)

	// push the events first then save the tx due to the assumption
	// that the consumer can handle duplicate events
	if err := si.consumer.PushVaultEvent(&vaultEvent); err != nil {
		return fmt.Errorf("failed to push the vault event to the queue: %w", err)
	}

	si.logger.Info("saving the vault transaction",
		zap.String("tx_hash", tx.TxHash().String()),
	)
	// save the vault tx in the db
	if err := si.is.AddVaultTransaction(
		tx, stakingOutputIndex, height,
		stakerPk, dAppPk,
		stakingValue, chainID, chainIdUserAddress, chainIdSmartContractAddress, amountMinting, isOverflow,
	); err != nil && !errors.Is(err, indexerstore.ErrDuplicateTransaction) {
		return fmt.Errorf("failed to add the vault tx to store: %w", err)
	}

	si.logger.Info("successfully saved the vault transaction",
		zap.String("tx_hash", tx.TxHash().String()),
	)

	// record metrics
	if isOverflow {
		totalVaultTxs.WithLabelValues("overflow").Inc()
	} else {
		totalVaultTxs.WithLabelValues("active").Inc()
	}
	lastFoundVaultTxHeight.Set(float64(height))
	return nil
}

func (si *StakingIndexer) processSpendingVaultTx(typeOfSpend int, tx *wire.MsgTx, vaultTxHash *chainhash.Hash, height uint64) error {
	txHashHex := tx.TxHash().String()
	if typeOfSpend == burningPathInfoType {
		si.logger.Info("found a spending tx from vault",
			zap.String("tx_hash", txHashHex),
			zap.String("vault_tx_hash", vaultTxHash.String()),
		)
		burningEvent := queuecli.NewBurningVaultEvent(vaultTxHash.String())
		if err := si.consumer.PushBurningEvent(&burningEvent); err != nil {
			return fmt.Errorf("failed to push the burning event to the consumer: %w", err)
		}
		// record metrics
		totalBurningTxsFromVault.Inc()
		lastFoundBurningTxFromVaultHeight.Set(float64(height))

	} else if typeOfSpend == slashingOrLostKeyPathInfoType {
		si.logger.Info("found a slashing or lost key tx from vault",
			zap.String("tx_hash", txHashHex),
			zap.String("vault_tx_hash", vaultTxHash.String()),
		)
		slashingOrLostKeyEvent := queuecli.NewSlashingOrLostKeyVaultEvent(vaultTxHash.String())
		if err := si.consumer.PushSlashingOrLostKeyEvent(&slashingOrLostKeyEvent); err != nil {
			return fmt.Errorf("failed to push the slashing or lost key event to the consumer: %w", err)
		}

		// record metrics
		totalSlashingOrLostKeyTxsFromVault.Inc()
		lastFoundSlashingOrLostKeyTxFromVaultHeight.Set(float64(height))

	} else if typeOfSpend == burnWithoutDAppPathInfoType {
		si.logger.Info("found a burn without dapp tx from vault",
			zap.String("tx_hash", txHashHex),
			zap.String("vault_tx_hash", vaultTxHash.String()),
		)
		burnWithoutDAppEvent := queuecli.NewBurnWithoutDAppVaultEvent(vaultTxHash.String())
		if err := si.consumer.PushBurnWithoutDAppEvent(&burnWithoutDAppEvent); err != nil {
			return fmt.Errorf("failed to push the burn without dapp event to the consumer: %w", err)
		}
		// record metrics
		totalBurnWithoutDAppTxsFromVault.Inc()
		lastFoundBurnWithoutDAppTxFromVaultHeight.Set(float64(height))
	}

	return nil
}

func (si *StakingIndexer) tryParseVaultTx(tx *wire.MsgTx, params *parser.ParsedVersionedGlobalParams) (*btcvault.ParsedV0VaultTx, error) {
	if len(tx.TxOut) > 2 {
		si.logger.Debug("TxOuput",
			zap.Int("First output len", len(tx.TxOut[1].PkScript)),
			zap.Int("Second output len", len(tx.TxOut[2].PkScript)))
	}
	possible := btcvault.IsPossibleV0VaultTx(tx, params.Tag)
	if !possible {
		return nil, fmt.Errorf("validate vault tx failed")
	}
	// opReturnData, opReturnOutputIdx, err := tryToGetOpReturnDataFromOutputs(tx.TxOut)
	opReturnData, err := btcvault.NewV0OpReturnDataFromTxOutput(tx.TxOut[1])
	if err != nil {
		return nil, fmt.Errorf("cannot parse v0 op return staking transaction: %w", err)
	}
	if opReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected v0 op return output")
	}
	// payloadOpReturnData, err := btcvault.NewPayloadOpReturnDataFromTxOutput(tx.TxOut[2])
	// if err != nil {
	// 	return nil, fmt.Errorf("cannot parse payload op return data: %w", err)
	// }
	vaultInfo, err := btcvault.BuildVaultInfo(
		opReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{opReturnData.FinalityProviderPublicKey.PubKey},
		params.CovenantPks,
		params.CovenantQuorum,
		// we can pass 0 here, as staking amount is not used when creating taproot address
		0,
		&si.cfg.BTCNetParams,
	)
	// vaultHex := hex.EncodeToString(vaultInfo.VaultOutput.PkScript)
	// firstOutHex := hex.EncodeToString(tx.TxOut[0].PkScript)
	si.logger.Debug("VaultInfo", zap.Binary("VaultOutput", vaultInfo.VaultOutput.PkScript), zap.Binary("FirstOutput", tx.TxOut[0].PkScript))
	parsedData, err := btcvault.ParseV0VaultTx(
		tx,
		params.Tag,
		params.CovenantPks,
		params.CovenantQuorum,
		&si.cfg.BTCNetParams)
	if err != nil {
		return nil, err
	}
	return parsedData, nil
}

func (si *StakingIndexer) GetVaultTxByHash(hash *chainhash.Hash) (*indexerstore.StoredVaultTransaction, error) {
	return si.is.GetVaultTransaction(hash)
}

func (si *StakingIndexer) GetBurningTxByHash(hash *chainhash.Hash) (*indexerstore.StoredBurningTransaction, error) {
	return si.is.GetBurningTransaction(hash)
}

func (si *StakingIndexer) validateVaultTx(params *parser.ParsedVersionedGlobalParams, vaultData *btcvault.ParsedV0VaultTx) error {
	value := btcutil.Amount(vaultData.VaultOutput.Value)
	// Minimum staking amount check
	if value < params.MinStakingAmount {
		return fmt.Errorf("%w: staking amount is too low, expected: %v, got: %v",
			ErrInvalidStakingTx, params.MinStakingAmount, value)
	}

	// Maximum staking amount check
	if value > params.MaxStakingAmount {
		return fmt.Errorf("%w: staking amount is too high, expected: %v, got: %v",
			ErrInvalidStakingTx, params.MaxStakingAmount, value)
	}
	return nil
}
