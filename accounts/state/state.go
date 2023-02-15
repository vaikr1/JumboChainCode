package state

import (
	"JumboChain/types"
	"math/big"
)

type AccountState struct {
	Address types.Address
	Balance *big.Int
}

func (as *AccountState) GetBalance() *big.Int {
	return as.Balance
}
