package signalstore

import (
	"math"
	"testing"
)

func TestTimeEnDecode(t *testing.T) {
	d := encodeTimes(0, math.MaxInt64)
	if a, b := decodeTimes(d); a != 0 || b != math.MaxInt64 {
		t.Error("Decode 0:max")
	}
	d = encodeTimes(math.MaxInt64, 0)
	if a, b := decodeTimes(d); a != math.MaxInt64 || b != 0 {
		t.Error("Decode 0:max")
	}
	d = encodeTimes(math.MaxInt64, math.MaxInt64)
	if a, b := decodeTimes(d); a != math.MaxInt64 || b != math.MaxInt64 {
		t.Error("Decode max:max")
	}
	d = encodeTimes(0, 0)
	if a, b := decodeTimes(d); a != 0 || b != 0 {
		t.Error("Decode 0:0")
	}
	d = encodeTimes(1, 1)
	if a, b := decodeTimes(d); a != 1 || b != 1 {
		t.Error("Decode 1:1")
	}
}

func TestTimeRange(t *testing.T) {
	timeNow = func() int64 { return 10 }
	if !isSignalTimeSet(0, 0) {
		t.Error("Signal is set: 0,0")
	}
	if !isSignalTimeSet(1, 11) {
		t.Error("Signal is set: 1,11")
	}
	if !isSignalTimeSet(10, 11) {
		t.Error("Signal is set: 10,11")
	}
	if !isSignalTimeSet(0, 11) {
		t.Error("Signal is set: 0,11")
	}
	if isSignalTimeSet(0, 10) {
		t.Error("Signal is NOT set: 0,10")
	}
	if isSignalTimeSet(1, 10) {
		t.Error("Signal is NOT set: 1,10")
	}
	if isSignalTimeSet(11, 11) {
		t.Error("Signal is NOT set: 11,11")
	}
	if isSignalTimeSet(11, 12) {
		t.Error("Signal is NOT set: 11,12")
	}
	if isSignalTimeSet(11, 0) {
		t.Error("Signal is NOT set: 11,0")
	}
}
