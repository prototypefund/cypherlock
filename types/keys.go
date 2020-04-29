package types

// RatchetPublicKey is a public key (list) of a ratchet key.
type RatchetPublicKey struct {
	StartTime, RatchetTime int64
	Key                    [][32]byte
}

type TimeKey struct {
	ValidFrom, ValidTo int64
	PublicKey          [32]byte
}

func (self *RatchetPublicKey) SelectKey(time int64) *TimeKey {
	if time < self.StartTime {
		return nil
	}
	time = time - self.StartTime
	pos := int(time / self.RatchetTime)
	if len(self.Key) <= pos {
		return nil
	}
	return &TimeKey{
		ValidFrom: self.StartTime + int64(pos)*self.RatchetTime,
		ValidTo:   self.StartTime + int64(pos+1)*self.RatchetTime - 1,
		PublicKey: self.Key[pos],
	}
}

func (self *RatchetPublicKey) absTime(time int64) int64 {
	time = time - self.StartTime
	time = (time / self.RatchetTime) * self.RatchetTime
	return time + self.StartTime
}

func (self *RatchetPublicKey) SelectKeyRange(begin, end int64) []TimeKey {
	if begin > end {
		return nil
	}
	if begin < self.StartTime {
		return nil
	}
	begin = self.absTime(begin)
	end = self.absTime(end)
	count := (end - begin) / self.RatchetTime
	ret := make([]TimeKey, 0, count)
	for i := begin; i <= end; i += self.RatchetTime {
		k := self.SelectKey(i)
		if k == nil {
			continue
		}
		ret = append(ret, *k)
	}
	return ret
}
