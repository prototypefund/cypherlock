package symmetriccrypto

import (
	"bytes"
	"testing"
)

func TestPadding(t *testing.T) {
	msg := []byte("This is a test message")
	paddedMsg, err := AddPadding(msg, nil, 30, nil)
	if err != nil {
		t.Fatalf("AddPadding: %s", err)
	}
	msg2, err := RemovePadding(paddedMsg)
	if err != nil {
		t.Errorf("RemovePadding: %s", err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Error("Message destroyed")
	}
	out := make([]byte, PaddedMessageSize(len(msg), 30))
	paddedMsg, err = AddPadding(msg, out, 30, nil)
	if err != nil {
		t.Fatalf("AddPadding Out: %s", err)
	}
	msg2, err = RemovePadding(paddedMsg)
	if err != nil {
		t.Errorf("RemovePadding Out: %s", err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Error("Message destroyed, Out")
	}
	msg3 := make([]byte, len(msg), PaddedMessageSize(len(msg), 30))
	copy(msg3, msg)
	paddedMsg, err = AddPadding(msg3, nil, 30, nil)
	if err != nil {
		t.Fatalf("AddPadding Msg: %s", err)
	}
	msg2, err = RemovePadding(paddedMsg)
	if err != nil {
		t.Errorf("RemovePadding Msg: %s", err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Error("Message destroyed, Msg")
	}
}
