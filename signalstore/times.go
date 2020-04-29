package signalstore

import (
	"encoding/binary"
	"time"
)

var timeNow = func() int64 {
	return time.Now().Unix()
}

func encodeTimes(setFrom, setTo int64) []byte {
	r := make([]byte, 16)
	binary.BigEndian.PutUint64(r[0:8], uint64(setFrom))
	binary.BigEndian.PutUint64(r[8:16], uint64(setTo))
	return r
}

func decodeTimes(d []byte) (setFrom, setTo int64) {
	// Corrupted data always returns safe value: Signal is present.
	if len(d) < 16 {
		return 0, 0
	}
	setFrom = int64(binary.BigEndian.Uint64(d[0:8]))
	setTo = int64(binary.BigEndian.Uint64(d[8:16]))
	return setFrom, setTo
}

// isSignalTimeSet returns true of the current time is between setFrom and setTo, inclusive.
// setFrom value of 0 means "since the beginning of time". A setTo value of 0 means "forever".
func isSignalTimeSet(setFrom, setTo int64) bool {
	now := timeNow()
	return (setFrom <= now && ((setTo > 0 && setTo > now) || (setTo == 0)))
}

func isSignalTimeSetBinary(d []byte) bool {
	return isSignalTimeSet(decodeTimes(d))
}

// maxTime returns the maximum of a and b. 0 is considered a maximum.
func maxTime(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > b {
		return a
	}
	return b
}

func minTime(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// Merge the times and signal if there was a change
func mergeTimes(oldSetFrom, oldSetTo, newSetFrom, newSetTo int64) (setFrom, setTo int64, changed bool) {
	setFrom = minTime(oldSetFrom, newSetFrom)
	setTo = maxTime(oldSetTo, newSetTo)
	return setFrom, setTo, (setFrom != oldSetFrom || setTo != oldSetTo)
}

func genTimes(oldValue []byte, setFrom, setTo int64) (newValue []byte, changed bool) {
	if oldValue == nil {
		return encodeTimes(setFrom, setTo), true
	}
	oldSetFrom, oldSetTo := decodeTimes(oldValue)
	newSetFrom, newSetTo, changed := mergeTimes(oldSetFrom, oldSetTo, setFrom, setTo)
	if !changed {
		return oldValue, false
	}
	return encodeTimes(newSetFrom, newSetTo), true
}
