package types

import (
	"testing"
)

type TestType1 struct {
	S string
}

func (tt TestType1) TypeID() int32 {
	return 1
}

func (tt TestType1) New() interface{} {
	return new(TestType1)
}

func TestTypes(t *testing.T) {
	RegisterType(new(TestType1))
	td := &TestType1{
		S: "Some data",
	}
	_, err := Marshal(td)
	if err != nil {
		t.Fatalf("Marshal of pointer failed: %s", err)
	}
	d, err := Marshal(*td)
	if err != nil {
		t.Fatalf("Marshal of value failed: %s", err)
	}
	tdU, err := Unmarshal(d)
	if err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	td2, ok := tdU.(*TestType1)
	if !ok {
		t.Fatal("Decoded to wrong type")
	}
	if td.S != td2.S {
		t.Errorf("decode failure: \"%s\"!=\"%s\"", td.S, td2.S)
	}
}
