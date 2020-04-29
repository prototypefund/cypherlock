// Package util contains utility functions
package util

import (
	"reflect"
)

// RemovePointer indirects a pointer.
func RemovePointer(i interface{}) interface{} {
	t := reflect.Indirect(reflect.ValueOf(i))
	if t.IsValid() {
		return t.Interface()
	}
	return i
}

// TypeSize returns the number of bytes that a variable like typeTemplate requires in memory.
// typeTemplate is indirected, so it will work for pointers to structs as well of structs.
// typeTemplate may NOT be of variable size, nor any of its elements.
func TypeSize(typeTemplate interface{}) int {
	return int(reflect.TypeOf(RemovePointer(typeTemplate)).Size())
}
