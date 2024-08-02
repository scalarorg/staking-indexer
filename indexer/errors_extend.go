package indexer

import "errors"

var (
	ErrInvalidVaultTx = errors.New("invalid vault tx")

	ErrInvalidSpendingTx = errors.New("invalid spending tx")

	ErrInvalidBurningTx = errors.New("invalid burning tx")

	ErrInvalidSlashingOrLostKeyTx = errors.New("invalid slashing or lost key tx")

	ErrInvalidBurnWithoutDAppTx = errors.New("invalid burning without dApp tx")
)
