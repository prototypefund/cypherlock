package types

type ByteSliceMaker func(size int, capacity ...int) []byte

func MakeByteSlice(size int, capacity ...int) []byte {
	if len(capacity) > 0 {
		return make([]byte, size, capacity[0])
	}
	return make([]byte, size)
}
