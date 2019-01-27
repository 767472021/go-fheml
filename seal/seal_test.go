package seal

import (
	"math"
	"testing"
)

func TestBasic(t *testing.T) {
	params := NewEncryptionParamsCKKS()
	c := NewContext(params)
	g := NewKeyGenerator(c)
	pub := g.PublicKey()
	sec := g.SecretKey()

	encryptor := NewEncryptor(c, pub)
	NewEvaluator(c)
	decryptor := NewDecryptor(c, sec)

	enc := NewCKKSEncoder(c)
	in := 10.0
	a := enc.Encode(in)
	ciphertext := encryptor.Encrypt(a)
	plain := decryptor.Decrypt(ciphertext)
	out := enc.Decode(plain)
	if math.Abs(in-out) > 0.00001 {
		t.Fatal("in != out", in, out)
	}
}

func TestCKKSEncoder(t *testing.T) {
	params := NewEncryptionParamsCKKS()
	c := NewContext(params)
	enc := NewCKKSEncoder(c)
	in := 10.0
	out := enc.Decode(enc.Encode(in))
	if math.Abs(in-out) > 0.00001 {
		t.Fatal("in != out", in, out)
	}
}

func TestBinaryFractionalEncoder(t *testing.T) {
	params := NewEncryptionParamsBFV()
	enc := NewBinaryFractionalEncoder(params)
	in := 10.0
	out := enc.Decode(enc.Encode(in))
	if in != out {
		t.Fatal("in != out")
	}
}
