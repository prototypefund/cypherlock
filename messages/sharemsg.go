package messages

import (
	"errors"

	"assuredrelease.com/cypherlock-pe/binencode"
	"assuredrelease.com/cypherlock-pe/symmetriccrypto"
)

var ErrBufferSize = errors.New("messages: Buffer size too small")

// MaxShareSize is the maximum size of an embedded share
const MaxShareSize = 256

// ShareMsgPadSize is the size to which the ShareMsg will be padded
const ShareMsgPadSize = 512
const shareMsgPadTotal = ShareMsgPadSize + symmetriccrypto.PaddingOverhead

// ShareMsgSize is the size of an encrypted ShareMsg
const ShareMsgSize = shareMsgPadTotal + symmetriccrypto.EncryptionOverhead

// ShareMsgEncryptBufferSize is the size of the encryption buffer
const ShareMsgEncryptBufferSize = shareMsgPadTotal + ShareMsgSize

// ShareMsgDecryptBufferSize is the size of the decryption buffer
const ShareMsgDecryptBufferSize = shareMsgPadTotal

const ShareMsgTypeID = 1002

// ShareMsg contains a share of the secret.
type ShareMsg struct {
	Share     []byte   // Share contents.
	OracleKey [32]byte // Long term oracle key
}

// Marshal a ShareMsg into a byte slice. If out ==nil, a new output slice will be allocated.
func (self *ShareMsg) Marshal(out []byte) []byte {
	if len(self.Share) > MaxShareSize {
		panic("Share too long. Programming error.")
	}
	d, err := binencode.Encode(out, 2, &self.Share, binencode.SlicePointer(self.OracleKey[:]))
	if err != nil {
		panic(err)
	}
	binencode.SetType(d, ShareMsgTypeID)
	return d
}

// Encrypt a sharemessage. Key is the symmetric key to encrypt to. buf is used as buffer for marshalling and buf2 for encryption if it is not nil. Otherwise
// a new slice will be allocated.
func (self *ShareMsg) Encrypt(key []byte, buf []byte) ([]byte, error) {
	var buf1, buf2 []byte
	if buf != nil {
		if cap(buf) < ShareMsgEncryptBufferSize {
			return nil, ErrBufferSize
		}
		buf = buf[0:cap(buf)]
		buf1 = buf[0 : ShareMsgPadSize+8]
		buf2 = buf[ShareMsgPadSize+8:]
	}
	unpadded := self.Marshal(buf1)
	padded, err := symmetriccrypto.AddPadding(unpadded, buf1, ShareMsgPadSize, nil)
	if err != nil {
		return nil, err
	}
	return symmetriccrypto.Encrypt(key, padded, buf2)
}

// Unmarshal ShareMsg. If receiver is nil, a new receiver is created. Otherwise the receiver is used.
func (self *ShareMsg) Unmarshal(d []byte) (r *ShareMsg, remainder []byte, err error) {
	if err := binencode.GetTypeExpect(d, ShareMsgTypeID); err != nil {
		return nil, nil, err
	}
	if self != nil {
		r = self
	} else {
		r = new(ShareMsg)
	}
	remainder, err = binencode.Decode(d, 2, &r.Share, binencode.SlicePointer(r.OracleKey[:]))
	if err != nil {
		return nil, remainder, err
	}
	return r, remainder, nil
}

// Decrypt an encrypted sharemessage. buf, if not nil, will be used for buffering. To securely decrypt, the receiver should have
// the Share element set to a byteslice large enough to contain the share data. This will prevent allocation.
func (self *ShareMsg) Decrypt(msg, key []byte, buf []byte) (*ShareMsg, error) {
	padded, err := symmetriccrypto.Decrypt(key, msg, buf)
	if err != nil {
		return nil, err
	}
	unpadded, err := symmetriccrypto.RemovePadding(padded)
	if err != nil {
		return nil, err
	}
	r, _, err := self.Unmarshal(unpadded)
	return r, err
}
