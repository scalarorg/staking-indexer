package consumer

import (
	"github.com/babylonchain/staking-queue-client/client"
)

type EventConsumer interface {
	Start() error
	PushScalarStakingEvent(ev *client.ScalarStakingEvent) error
	PushStakingEvent(ev *client.ActiveStakingEvent) error
	PushUnbondingEvent(ev *client.UnbondingStakingEvent) error
	PushWithdrawEvent(ev *client.WithdrawStakingEvent) error
	PushBtcInfoEvent(ev *client.BtcInfoEvent) error
	Stop() error
}
