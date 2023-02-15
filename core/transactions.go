package core

import (
	"JumboChain/accounts"
	"JumboChain/accounts/state"
	"JumboChain/types"
	"time"
)

type Transaction struct {
	to        types.Address
	from      types.Address
	value     uint64
	nonce     uint64
	time      time.Time
	data      []byte
	hash      types.Hash
	signature *accounts.Signature
}

func (tx *Transaction) To() types.Address {
	return tx.to
}

func (tx *Transaction) From() types.Address {
	return tx.from
}

func (tx *Transaction) Value() uint64 {
	return tx.value
}

func (tx *Transaction) Time() time.Time {
	return tx.time
}

func (tx *Transaction) Nonce() uint64 {
	return tx.nonce
}
func (tx *Transaction) Hash() types.Hash {
	return tx.hash
}

func (tx *Transaction) Data() []byte {
	return tx.data
}

func (tx *Transaction) Signature() *accounts.Signature {
	return tx.signature
}

func (tx *Transaction) Sign(priv *accounts.PrivateKey) error {
	sig, err := priv.Sign(tx.data)
	if err != nil {
		return err
	}
	tx.signature = sig
	return nil
}

func NewTx(data *Transaction) *Transaction {
	tx := new(Transaction)
	return tx
}

func SendTx(to types.Address, value uint64) types.Hash {
	to = AccountState.Address
}
