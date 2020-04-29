package protectedcrypto

import (
	"bytes"
	"io"
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

func TestCombiner(t *testing.T) {
	// engine := new(memprotect.MemGuard)
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()
	combiner := NewSecretCombiner(engine)
	s1 := engine.Cell(32)
	s2 := engine.Cell(32)
	s3 := engine.Cell(32)
	s4 := engine.Cell(32)
	io.ReadFull(RandomSource, s1.Bytes())
	io.ReadFull(RandomSource, s2.Bytes())
	io.ReadFull(RandomSource, s3.Bytes())
	io.ReadFull(RandomSource, s4.Bytes())
	s12 := combiner.Combine(s1.Bytes(), s2.Bytes())
	s34 := combiner.Combine(s3.Bytes(), s4.Bytes())
	defer s12.Destroy()
	defer s34.Destroy()
	if bytes.Equal(s12.Bytes(), s34.Bytes()) {
		t.Error("No operation")
	}
}
