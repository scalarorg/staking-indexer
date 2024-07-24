// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: transaction.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type StakingTransaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// transaction_bytes is the full tx data
	TransactionBytes []byte `protobuf:"bytes,1,opt,name=transaction_bytes,json=transactionBytes,proto3" json:"transaction_bytes,omitempty"`
	StakingOutputIdx uint32 `protobuf:"varint,2,opt,name=staking_output_idx,json=stakingOutputIdx,proto3" json:"staking_output_idx,omitempty"`
	// inclusion_height is the height the tx included
	// on BTC
	InclusionHeight uint64 `protobuf:"varint,3,opt,name=inclusion_height,json=inclusionHeight,proto3" json:"inclusion_height,omitempty"`
	// staking info
	StakerPk           []byte `protobuf:"bytes,4,opt,name=staker_pk,json=stakerPk,proto3" json:"staker_pk,omitempty"`
	FinalityProviderPk []byte `protobuf:"bytes,5,opt,name=finality_provider_pk,json=finalityProviderPk,proto3" json:"finality_provider_pk,omitempty"`
	StakingTime        uint32 `protobuf:"varint,6,opt,name=staking_time,json=stakingTime,proto3" json:"staking_time,omitempty"`
	// Indicate if the staking tx would exceed the staking cap.
	IsOverflow bool `protobuf:"varint,7,opt,name=is_overflow,json=isOverflow,proto3" json:"is_overflow,omitempty"`
	// The staking amount
	StakingValue uint64 `protobuf:"varint,8,opt,name=staking_value,json=stakingValue,proto3" json:"staking_value,omitempty"`
}

func (x *StakingTransaction) Reset() {
	*x = StakingTransaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transaction_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StakingTransaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StakingTransaction) ProtoMessage() {}

func (x *StakingTransaction) ProtoReflect() protoreflect.Message {
	mi := &file_transaction_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StakingTransaction.ProtoReflect.Descriptor instead.
func (*StakingTransaction) Descriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{0}
}

func (x *StakingTransaction) GetTransactionBytes() []byte {
	if x != nil {
		return x.TransactionBytes
	}
	return nil
}

func (x *StakingTransaction) GetStakingOutputIdx() uint32 {
	if x != nil {
		return x.StakingOutputIdx
	}
	return 0
}

func (x *StakingTransaction) GetInclusionHeight() uint64 {
	if x != nil {
		return x.InclusionHeight
	}
	return 0
}

func (x *StakingTransaction) GetStakerPk() []byte {
	if x != nil {
		return x.StakerPk
	}
	return nil
}

func (x *StakingTransaction) GetFinalityProviderPk() []byte {
	if x != nil {
		return x.FinalityProviderPk
	}
	return nil
}

func (x *StakingTransaction) GetStakingTime() uint32 {
	if x != nil {
		return x.StakingTime
	}
	return 0
}

func (x *StakingTransaction) GetIsOverflow() bool {
	if x != nil {
		return x.IsOverflow
	}
	return false
}

func (x *StakingTransaction) GetStakingValue() uint64 {
	if x != nil {
		return x.StakingValue
	}
	return 0
}

type UnbondingTransaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// transaction_bytes is the full tx data
	TransactionBytes []byte `protobuf:"bytes,1,opt,name=transaction_bytes,json=transactionBytes,proto3" json:"transaction_bytes,omitempty"`
	// staking_tx_hash is the hash of the staking tx
	// that the unbonding tx spends
	StakingTxHash []byte `protobuf:"bytes,2,opt,name=staking_tx_hash,json=stakingTxHash,proto3" json:"staking_tx_hash,omitempty"`
}

func (x *UnbondingTransaction) Reset() {
	*x = UnbondingTransaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transaction_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnbondingTransaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnbondingTransaction) ProtoMessage() {}

func (x *UnbondingTransaction) ProtoReflect() protoreflect.Message {
	mi := &file_transaction_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnbondingTransaction.ProtoReflect.Descriptor instead.
func (*UnbondingTransaction) Descriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{1}
}

func (x *UnbondingTransaction) GetTransactionBytes() []byte {
	if x != nil {
		return x.TransactionBytes
	}
	return nil
}

func (x *UnbondingTransaction) GetStakingTxHash() []byte {
	if x != nil {
		return x.StakingTxHash
	}
	return nil
}

type VaultTransaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// transaction_bytes is the full tx data
	TransactionBytes []byte `protobuf:"bytes,1,opt,name=transaction_bytes,json=transactionBytes,proto3" json:"transaction_bytes,omitempty"`
	StakingOutputIdx uint32 `protobuf:"varint,2,opt,name=staking_output_idx,json=stakingOutputIdx,proto3" json:"staking_output_idx,omitempty"`
	// inclusion_height is the height the tx included
	// on BTC
	InclusionHeight uint64 `protobuf:"varint,3,opt,name=inclusion_height,json=inclusionHeight,proto3" json:"inclusion_height,omitempty"`
	// staking info
	StakerPk           []byte `protobuf:"bytes,4,opt,name=staker_pk,json=stakerPk,proto3" json:"staker_pk,omitempty"`
	FinalityProviderPk []byte `protobuf:"bytes,5,opt,name=finality_provider_pk,json=finalityProviderPk,proto3" json:"finality_provider_pk,omitempty"`
	StakingValue       uint64 `protobuf:"varint,6,opt,name=staking_value,json=stakingValue,proto3" json:"staking_value,omitempty"`
	// payload info
	ChainID                     []byte `protobuf:"bytes,7,opt,name=chainID,proto3" json:"chainID,omitempty"`
	ChainIdUserAddress          []byte `protobuf:"bytes,8,opt,name=chainIdUserAddress,proto3" json:"chainIdUserAddress,omitempty"`
	ChainIdSmartContractAddress []byte `protobuf:"bytes,9,opt,name=chainIdSmartContractAddress,proto3" json:"chainIdSmartContractAddress,omitempty"`
	MintingAmount               []byte `protobuf:"bytes,10,opt,name=amountVault,proto3" json:"amountVault,omitempty"`
	// Indicate if the staking tx would exceed the staking cap.
	IsOverflow bool `protobuf:"varint,11,opt,name=is_overflow,json=isOverflow,proto3" json:"is_overflow,omitempty"` // The staking amount
}

func (x *VaultTransaction) Reset() {
	*x = VaultTransaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transaction_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VaultTransaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VaultTransaction) ProtoMessage() {}

func (x *VaultTransaction) ProtoReflect() protoreflect.Message {
	mi := &file_transaction_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VaultTransaction.ProtoReflect.Descriptor instead.
func (*VaultTransaction) Descriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{2}
}

func (x *VaultTransaction) GetTransactionBytes() []byte {
	if x != nil {
		return x.TransactionBytes
	}
	return nil
}

func (x *VaultTransaction) GetStakingOutputIdx() uint32 {
	if x != nil {
		return x.StakingOutputIdx
	}
	return 0
}

func (x *VaultTransaction) GetInclusionHeight() uint64 {
	if x != nil {
		return x.InclusionHeight
	}
	return 0
}

func (x *VaultTransaction) GetStakerPk() []byte {
	if x != nil {
		return x.StakerPk
	}
	return nil
}

func (x *VaultTransaction) GetFinalityProviderPk() []byte {
	if x != nil {
		return x.FinalityProviderPk
	}
	return nil
}

func (x *VaultTransaction) GetStakingValue() uint64 {
	if x != nil {
		return x.StakingValue
	}
	return 0
}

func (x *VaultTransaction) GetChainID() []byte {
	if x != nil {
		return x.ChainID
	}
	return nil
}

func (x *VaultTransaction) GetChainIdUserAddress() []byte {
	if x != nil {
		return x.ChainIdUserAddress
	}
	return nil
}

func (x *VaultTransaction) GetChainIdSmartContractAddress() []byte {
	if x != nil {
		return x.ChainIdSmartContractAddress
	}
	return nil
}

func (x *VaultTransaction) GetMintingAmount() []byte {
	if x != nil {
		return x.MintingAmount
	}
	return nil
}

func (x *VaultTransaction) GetIsOverflow() bool {
	if x != nil {
		return x.IsOverflow
	}
	return false
}

type BurningTransaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// transaction_bytes is the full tx data
	TransactionBytes []byte `protobuf:"bytes,1,opt,name=transaction_bytes,json=transactionBytes,proto3" json:"transaction_bytes,omitempty"`
	// vault_tx_hash is the hash of the vault tx
	// that the burning tx spends
	VaultTxHash []byte `protobuf:"bytes,2,opt,name=vault_tx_hash,json=vaultTxHash,proto3" json:"vault_tx_hash,omitempty"`
}

func (x *BurningTransaction) Reset() {
	*x = BurningTransaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transaction_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BurningTransaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BurningTransaction) ProtoMessage() {}

func (x *BurningTransaction) ProtoReflect() protoreflect.Message {
	mi := &file_transaction_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BurningTransaction.ProtoReflect.Descriptor instead.
func (*BurningTransaction) Descriptor() ([]byte, []int) {
	return file_transaction_proto_rawDescGZIP(), []int{3}
}

func (x *BurningTransaction) GetTransactionBytes() []byte {
	if x != nil {
		return x.TransactionBytes
	}
	return nil
}

func (x *BurningTransaction) GetVaultTxHash() []byte {
	if x != nil {
		return x.VaultTxHash
	}
	return nil
}

var File_transaction_proto protoreflect.FileDescriptor

var file_transaction_proto_rawDesc = []byte{
	0x0a, 0x11, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd2, 0x02, 0x0a, 0x12, 0x53,
	0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x2b, 0x0a, 0x11, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12, 0x2c,
	0x0a, 0x12, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74,
	0x5f, 0x69, 0x64, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x73, 0x74, 0x61, 0x6b,
	0x69, 0x6e, 0x67, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x49, 0x64, 0x78, 0x12, 0x29, 0x0a, 0x10,
	0x69, 0x6e, 0x63, 0x6c, 0x75, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0f, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x73, 0x69, 0x6f,
	0x6e, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x74, 0x61, 0x6b, 0x65,
	0x72, 0x5f, 0x70, 0x6b, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x73, 0x74, 0x61, 0x6b,
	0x65, 0x72, 0x50, 0x6b, 0x12, 0x30, 0x0a, 0x14, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x74, 0x79,
	0x5f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x5f, 0x70, 0x6b, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x12, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x50, 0x6b, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e,
	0x67, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x73, 0x74,
	0x61, 0x6b, 0x69, 0x6e, 0x67, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x69, 0x73, 0x5f,
	0x6f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a,
	0x69, 0x73, 0x4f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x74,
	0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x0c, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22,
	0x6b, 0x0a, 0x14, 0x55, 0x6e, 0x62, 0x6f, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e,
	0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2b, 0x0a, 0x11, 0x74, 0x72, 0x61, 0x6e, 0x73,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x10, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42,
	0x79, 0x74, 0x65, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f,
	0x74, 0x78, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x73,
	0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x54, 0x78, 0x48, 0x61, 0x73, 0x68, 0x22, 0xe1, 0x03, 0x0a,
	0x12, 0x4d, 0x69, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x2b, 0x0a, 0x11, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10,
	0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x79, 0x74, 0x65, 0x73,
	0x12, 0x2c, 0x0a, 0x12, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x6f, 0x75, 0x74, 0x70,
	0x75, 0x74, 0x5f, 0x69, 0x64, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x73, 0x74,
	0x61, 0x6b, 0x69, 0x6e, 0x67, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x49, 0x64, 0x78, 0x12, 0x29,
	0x0a, 0x10, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x65, 0x69, 0x67,
	0x68, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0f, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x73,
	0x69, 0x6f, 0x6e, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x74, 0x61,
	0x6b, 0x65, 0x72, 0x5f, 0x70, 0x6b, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x73, 0x74,
	0x61, 0x6b, 0x65, 0x72, 0x50, 0x6b, 0x12, 0x30, 0x0a, 0x14, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69,
	0x74, 0x79, 0x5f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x5f, 0x70, 0x6b, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x50, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x50, 0x6b, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x74, 0x61, 0x6b,
	0x69, 0x6e, 0x67, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x0c, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x18, 0x0a,
	0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07,
	0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x44, 0x12, 0x2e, 0x0a, 0x12, 0x63, 0x68, 0x61, 0x69, 0x6e,
	0x49, 0x64, 0x55, 0x73, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x12, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x55, 0x73, 0x65, 0x72,
	0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x40, 0x0a, 0x1b, 0x63, 0x68, 0x61, 0x69, 0x6e,
	0x49, 0x64, 0x53, 0x6d, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1b, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x49, 0x64, 0x53, 0x6d, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x61,
	0x63, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x61, 0x6d, 0x6f,
	0x75, 0x6e, 0x74, 0x4d, 0x69, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0d, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x4d, 0x69, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x12,
	0x1f, 0x0a, 0x0b, 0x69, 0x73, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77, 0x18, 0x0b,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x69, 0x73, 0x4f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77,
	0x22, 0x69, 0x0a, 0x12, 0x42, 0x75, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x6e, 0x73,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2b, 0x0a, 0x11, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x10, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x79,
	0x74, 0x65, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x6d, 0x69, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x74,
	0x78, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x6d, 0x69,
	0x6e, 0x74, 0x69, 0x6e, 0x67, 0x54, 0x78, 0x48, 0x61, 0x73, 0x68, 0x42, 0x2c, 0x5a, 0x2a, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x63, 0x61, 0x6c, 0x61, 0x72,
	0x6f, 0x72, 0x67, 0x2f, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x2d, 0x69, 0x6e, 0x64, 0x65,
	0x78, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_transaction_proto_rawDescOnce sync.Once
	file_transaction_proto_rawDescData = file_transaction_proto_rawDesc
)

func file_transaction_proto_rawDescGZIP() []byte {
	file_transaction_proto_rawDescOnce.Do(func() {
		file_transaction_proto_rawDescData = protoimpl.X.CompressGZIP(file_transaction_proto_rawDescData)
	})
	return file_transaction_proto_rawDescData
}

var file_transaction_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_transaction_proto_goTypes = []any{
	(*StakingTransaction)(nil),   // 0: proto.StakingTransaction
	(*UnbondingTransaction)(nil), // 1: proto.UnbondingTransaction
	(*VaultTransaction)(nil),   // 2: proto.VaultTransaction
	(*BurningTransaction)(nil),   // 3: proto.BurningTransaction
}
var file_transaction_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_transaction_proto_init() }
func file_transaction_proto_init() {
	if File_transaction_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transaction_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*StakingTransaction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transaction_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*UnbondingTransaction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transaction_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*VaultTransaction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transaction_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*BurningTransaction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_transaction_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transaction_proto_goTypes,
		DependencyIndexes: file_transaction_proto_depIdxs,
		MessageInfos:      file_transaction_proto_msgTypes,
	}.Build()
	File_transaction_proto = out.File
	file_transaction_proto_rawDesc = nil
	file_transaction_proto_goTypes = nil
	file_transaction_proto_depIdxs = nil
}
