package indexer

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Based on github.com/babylonchain/staking-indexer/indexer/metrics.go
var (
	lastFoundVaultTxHeight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "si_last_found_vault_tx_height",
			Help: "The inclusion height of the last found vault transaction",
		},
	)

	lastFoundBurningTxFromVaultHeight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "si_last_found_burning_from_vault_height",
			Help: "The inclusion height of the last found burning transaction spending a previous vault transaction ",
		},
	)

	lastFoundSlashingOrLostKeyTxFromVaultHeight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "si_last_found_slashing_or_lost_key_from_vault_height",
			Help: "The inclusion height of the last found slashing or lost key transaction spending a previous vault transaction",
		},
	)

	lastFoundBurnWithoutDAppTxFromVaultHeight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "si_last_found_burn_without_dapp_from_vault_height",
			Help: "The inclusion height of the last found burn without dApp transaction spending a previous vault transaction",
		},
	)

	totalVaultTxs = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "si_total_vault_txs",
			Help: "Total number of vault transactions",
		},
		[]string{
			"tx_type",
		},
	)

	totalBurningTxsFromVault = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_total_burning_txs",
			Help: "Total number of burning transactions",
		},
	)

	totalSlashingOrLostKeyTxsFromVault = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_total_slashing_or_lost_key_txs",
			Help: "Total number of slashing or lost key transactions",
		},
	)

	totalBurnWithoutDAppTxsFromVault = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_total_burn_without_dapp_txs",
			Help: "Total number of burn without dApp transactions",
		},
	)

	/* alerts */

	failedProcessingVaultTxsCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_failed_processing_vault_txs_counter",
			Help: "Total number of failures when processing valid vault transactions",
		},
	)

	failedProcessingSpendingTxsFromVaultCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_failed_processing_spending_txs_from_vault_counter",
			Help: "Total number of failures when processing valid spending transactions from vault ",
		},
	)

	failedProcessingBurningTxsFromVaultCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_failed_processing_burning_txs_counter",
			Help: "Total number of failures when processing valid burning transactions",
		},
	)

	failedProcessingSlashingOrLostKeyTxsFromVaultCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_failed_processing_slashing_or_lost_key_txs_counter",
			Help: "Total number of failures when processing valid slashing or lost key transactions",
		},
	)

	failedProcessingBurnWithoutDAppTxsFromVaultCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "si_failed_processing_burn_without_dapp_txs_counter",
			Help: "Total number of failures when processing valid burn without dApp transactions",
		},
	)
)
