package messages

import (
	"bytes"
	"testing"
)

func TestSemaphoreMsg(t *testing.T) {
	var semaphoreMsgT *SetSemaphoreMsg
	td := &SetSemaphoreMsg{
		SetFrom: 291,
		SetTo:   9612,
		Name:    [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10},
	}
	m := td.Marshal(nil)
	um, _, err := semaphoreMsgT.Unmarshal(m)
	if err != nil {
		t.Errorf("marshalling: %s", err)
	}
	if td.SetFrom != um.SetFrom {
		t.Error("SetFrom mismatch")
	}
	if td.SetTo != um.SetTo {
		t.Error("SetFrom mismatch")
	}
	if !bytes.Equal(td.Name[:], um.Name[:]) {
		t.Error("Name mismatch")
	}
}

func TestShareMsg(t *testing.T) {
	var shareMsgT *ShareMsg
	var buf, buf2 []byte
	for _, f := range []func(){
		func() {
			buf = nil
			buf2 = nil
		},
		func() {
			buf = make([]byte, 0, ShareMsgEncryptBufferSize)
			buf2 = make([]byte, 0, ShareMsgDecryptBufferSize)
		},
	} {
		f()
		// Force the random number source to be deterministic
		// symmetriccrypto.RandomSource = bytes.NewBufferString("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789")
		key := [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10}
		shareMsg := &ShareMsg{
			Share:     []byte("encrypted share"),
			OracleKey: [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10},
		}
		enc, err := shareMsg.Encrypt(key[:], buf)
		if err != nil {
			t.Fatalf("Encrypt: %s", err)
		}
		dec, err := shareMsgT.Decrypt(enc, key[:], buf2)
		if err != nil {
			t.Fatalf("Decrypt: %s", err)
		}
		if !bytes.Equal(shareMsg.Share, dec.Share) {
			t.Error("Share not equal")
		}
		if !bytes.Equal(shareMsg.OracleKey[:], dec.OracleKey[:]) {
			t.Error("OracleKey not equal")
		}
	}
}
