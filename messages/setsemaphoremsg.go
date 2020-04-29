package messages

import (
	"assuredrelease.com/cypherlock-pe/binencode"
)

// Notes: Only ShareMsg when decoded by client needs to be in secure memory

/*
SetSemaphore
- Encrypt to long-term key:
    - Semaphore Name
    - SetFrom: Time from which the semaphore is considered set.
    - SetTo: Time until which the semaphore is considered set.
*/

const SetSemaphoreMsgTypeID = 1001

// SetSemaphoreMsg sets a semaphore between SetFrom and SetTo.
type SetSemaphoreMsg struct {
	SetFrom int64
	SetTo   int64
	Name    [32]byte // Must be 32 bytes.
}

// Marshal SetSemaphoreMsg. If out ==nil, a new output slice will be allocated.
func (self *SetSemaphoreMsg) Marshal(out []byte) []byte {
	d, err := binencode.Encode(out, 2, &self.SetFrom, &self.SetTo, binencode.SlicePointer(self.Name[:]))
	if err != nil {
		panic(err)
	}
	binencode.SetType(d, SetSemaphoreMsgTypeID)
	return d
}

// Unmarshal SetSemaphoreMsg. If receiver is nil, a new receiver is created. Otherwise the receiver is used.
func (self *SetSemaphoreMsg) Unmarshal(d []byte) (r *SetSemaphoreMsg, remainder []byte, err error) {
	if err := binencode.GetTypeExpect(d, SetSemaphoreMsgTypeID); err != nil {
		return nil, nil, err
	}
	if self != nil {
		r = self
	} else {
		r = new(SetSemaphoreMsg)
	}
	remainder, err = binencode.Decode(d, 2, &r.SetFrom, &r.SetTo, binencode.SlicePointer(r.Name[:]))
	if err != nil {
		return nil, remainder, err
	}
	return r, remainder, nil
}
