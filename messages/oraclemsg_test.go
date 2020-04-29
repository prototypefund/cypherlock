package messages

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/signalstore"
)

func TestOracleMsg(t *testing.T) {
	tdir, err := ioutil.TempDir("", "CLPEtestStore")
	if err != nil {
		t.Fatalf("Cannot create temporary directory: %s", err)
	}
	defer os.RemoveAll(tdir)
	store, err := signalstore.New(tdir)
	if err != nil {
		t.Fatalf("New store: %s", err)
	}
	defer store.Close()

	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	oracle := NewOracle(store, engine)
	if err := oracle.Generate(time.Now().Unix(), 1000000, 100000); err != nil {
		t.Fatalf("Oracle.Generate: %s", err)
	}
	longTermKey, shortTermKey := oracle.PublicKeys()
	timeLockKeylist, err := oracle.TimelockKeys(10)
	if err != nil {
		t.Errorf("TimelockKeys: %s", err)
	}
	timeLockKey := timeLockKeylist.SelectKey(time.Now().Unix())
	// spew.Dump(timeLockKey)
	_ = shortTermKey
	key := [32]byte{0x00, 0x01, 0x02}
	td := &OracleMessage{
		ShareThreshold:          2,
		OracleURL:               []byte("http://testoracle.com"),
		LongTermOraclePublicKey: *longTermKey,
		TimelockPublicKey:       timeLockKey.PublicKey,
		TestSemaphores:          [3][32]byte{[32]byte{0x01, 0x01}, [32]byte{0x02, 0x01}, [32]byte{0x02, 0x01}},
		SetSemaphores:           [3][32]byte{[32]byte{0x01}, [32]byte{0x02}, [32]byte{0x02}},
		ValidFrom:               timeLockKey.ValidFrom,
		ValidTo:                 timeLockKey.ValidTo,
		Share:                   []byte("secret"),
	}
	container, err := td.Encrypt(key[:], engine)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	future, err := new(OracleMessageContainer).Send(key[:], container, func(url string) (*[32]byte, error) { return shortTermKey, nil }, engine)
	if err != nil {
		t.Errorf("Send: %s", err)
	}
	response, err := oracle.ReceiveMsg(future.Message)
	if err != nil {
		t.Errorf("ReceiveMsg: %s", err)
	}
	_ = response
	// spew.Dump(response)
	// containerDec, err := new(OracleMessageContainer).Decrypt(key[:], container)
	// if err != nil {
	// 	t.Fatalf("Decrypt: %s", err)
	// }

	// oracleMsg, err := oracle.decryptOracleMessage(containerDec.OracleMessage)
	// if err != nil {
	// 	t.Errorf("decryptOracleMessage: %s", err)
	// }
	// msg, err := oracle.verifyOracleMessage(oracleMsg)
	// if err != nil {
	// 	t.Errorf("verifyOracleMessage: %s", err)
	// }
	// _ = msg
}
