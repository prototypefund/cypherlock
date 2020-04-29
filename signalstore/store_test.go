package signalstore

import (
	"io/ioutil"
	"math"
	"os"
	"testing"
)

func TestStore(t *testing.T) {
	s1 := []byte("Signal 1")
	s2 := []byte("Signal 2")
	tdir, err := ioutil.TempDir("", "CLPEtestStore")
	if err != nil {
		t.Fatalf("Cannot create temporary directory: %s", err)
	}
	defer os.RemoveAll(tdir)
	store, err := New(tdir)
	if err != nil {
		t.Fatalf("New store: %s", err)
	}
	defer store.Close()
	if !store.TestSignal(s1) {
		t.Error("Unrecorded signal found")
	}
	if err := store.SetSignal(s1, 0, 0); err != nil {
		t.Errorf("SetSignal: %s", err)
	}
	if !store.TestSignal(s2) {
		t.Error("Unrecorded signal found 2")
	}
	if store.TestSignal(s1) {
		t.Error("Signal not recorded")
	}
	if err := store.SetSignal(s1, 0, 0); err != nil {
		t.Errorf("SetSignal duplicate: %s", err)
	}
}

func TestStoreTimes(t *testing.T) {
	s := []byte("signal")
	tdir, err := ioutil.TempDir("", "CLPEtestStore")
	if err != nil {
		t.Fatalf("Cannot create temporary directory: %s", err)
	}
	defer os.RemoveAll(tdir)
	store, err := New(tdir)
	if err != nil {
		t.Fatalf("New store: %s", err)
	}
	defer store.Close()
	if err := store.SetSignal(s, 10, 11); err != nil {
		t.Errorf("SetSignal: %s", err)
	}
	timeNow = func() int64 { return 10 }
	if store.TestSignal(s) {
		t.Error("Signal within range")
	}
	timeNow = func() int64 { return 9 }
	if !store.TestSignal(s) {
		t.Error("Signal outside range 1")
	}
	timeNow = func() int64 { return 11 }
	if !store.TestSignal(s) {
		t.Error("Signal outside range 2")
	}

	store.SetSignal(s, 9, 0)
	timeNow = func() int64 { return 9 }
	if store.TestSignal(s) {
		t.Error("Changed signal within range")
	}
	timeNow = func() int64 { return math.MaxInt64 }
	if store.TestSignal(s) {
		t.Error("Changed signal within range 2")
	}
	timeNow = func() int64 { return 8 }
	if !store.TestSignal(s) {
		t.Error("Signal outside range 3")
	}
}
