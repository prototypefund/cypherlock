package unsafeconvert

import (
	"reflect"
	"unsafe"

	"assuredrelease.com/cypherlock-pe/util"
)

func To32(d []byte) *[32]byte {
	return (*[32]byte)(unsafe.Pointer(&d[0]))
}

func To24(d []byte) *[24]byte {
	return (*[24]byte)(unsafe.Pointer(&d[0]))
}

func To256(d []byte) *[256]byte {
	return (*[256]byte)(unsafe.Pointer(&d[0]))
}

func ToInt16(d []byte) *int16 {
	return (*int16)(unsafe.Pointer(&d[0]))
}

func ToInt32(d []byte) *int32 {
	return (*int32)(unsafe.Pointer(&d[0]))
}

func ToInt64(d []byte) *int64 {
	return (*int64)(unsafe.Pointer(&d[0]))
}

// Convert creates a pointer of the type of typeTemplate that is held in  memory at d[0].
// The return value should be converted to a pointer of the type of typeTemplate.
// If d is too small then this function will panic. util.TypeSize provides a function to get the required size.
// typeTemplate may NOT be of variable size, nor any of its elements.
func Convert(d []byte, typeTemplate interface{}) interface{} {
	t := reflect.TypeOf(util.RemovePointer(typeTemplate))
	l := int(t.Size())
	if len(d) < l {
		panic("memprotect type conversion failed due to lack of memory")
	}
	return reflect.NewAt(t, unsafe.Pointer(&d[0])).Interface()
}
