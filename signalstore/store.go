// Package signalstore implements persistant storage for signals.
package signalstore

import (
	"time"

	"github.com/dgraph-io/badger"
)

const (
	gcFactor = 0.7
)

// Store implements a signal store.
type Store struct {
	db     *badger.DB
	stopGC chan interface{}
}

// New returns a new signal store.
func New(dir string) (*Store, error) {
	opts := badger.DefaultOptions
	opts.Dir = dir
	opts.ValueDir = dir
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:     db,
		stopGC: make(chan interface{}, 1),
	}, nil
}

// Close the signal store.
func (self *Store) Close() {
	self.stopGC <- struct{}{}
	self.db.Close()
}

// GCRun runs the garbage collection.
func (self *Store) GCRun() error {
	return self.db.RunValueLogGC(gcFactor)
}

// RunGCService runs the garbage collection serivce every duration.
func (self *Store) RunGCService(dur time.Duration) {
	go func() {
		ticker := time.NewTicker(dur)
		for {
			select {
			case <-ticker.C:
				self.GCRun()
			case <-self.stopGC:
				ticker.Stop()
			}
		}
	}()
}

// SetSignal records a signal semaphore in persistant storage. setFrom is the time from which on the signal should be set
// (0 means beginning of time). setTo is the time to which the signal should be set (0 means forever). times are in unixtime seconds.
func (self *Store) SetSignal(signal []byte, setFrom, setTo int64) error {
	signalCopy := make([]byte, len(signal))
	copy(signalCopy, signal)
	return self.db.Update(func(txn *badger.Txn) error {
		var value []byte
		item, err := txn.Get(signalCopy)
		if err == nil {
			value, err = item.ValueCopy(nil)
			if err != nil {
				return err
			}
		} else if err != badger.ErrKeyNotFound {
			return err
		}
		newValue, changed := genTimes(value, setFrom, setTo)
		if changed {
			return txn.Set(signalCopy, newValue)
		}
		return nil
	})
}

// TestSignal tests the existence of signal in the database. It returns TRUE if the signal is _not known_, signalling that
// the process may proceed.
func (self *Store) TestSignal(signal []byte) (ok bool) {
	signalCopy := make([]byte, len(signal))
	copy(signalCopy, signal)
	err := self.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(signalCopy)
		if err == badger.ErrKeyNotFound {
			ok = true
			return nil
		} else if err != nil {
			ok = false
			return err
		}
		value, err := item.ValueCopy(nil)
		if err != nil {
			ok = false
			return err
		}
		ok = !isSignalTimeSetBinary(value)
		return nil
	})
	if err != nil {
		return false
	}
	return ok
}
