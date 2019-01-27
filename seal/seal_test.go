package seal

import (
	"math"
	"testing"
)

func TestEncryptionOps(t *testing.T) {
	params := NewEncryptionParamsCKKS()
	c := NewContext(params)
	g := NewKeyGenerator(c)
	pub := g.PublicKey()
	sec := g.SecretKey()

	encryptor := NewEncryptor(c, pub)
	eval := NewEvaluator(c)
	decryptor := NewDecryptor(c, sec)

	enc := NewCKKSEncoder(c)

	encrypt := func(v float64) *Ciphertext {
		a := enc.Encode(v)
		return encryptor.Encrypt(a)
	}

	cases := []struct {
		want float64
		f    func() *Ciphertext
	}{
		{
			want: 10.0,
			f: func() *Ciphertext {
				return encrypt(10.0)
			},
		},
		{
			want: 25.0,
			f: func() *Ciphertext {
				c := encrypt(5.0)
				eval.SquareInplace(c)
				return c
			},
		},
		{
			want: -5.0,
			f: func() *Ciphertext {
				c := encrypt(5.0)
				eval.NegateInplace(c)
				return c
			},
		},
		{
			want: 7.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				b := encrypt(4.0)
				eval.AddInplace(a, b)
				return a
			},
		},
		{
			want: 7.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				b := enc.Encode(4.0)
				eval.AddPlainInplace(a, b)
				return a
			},
		},
		{
			want: -1.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				b := encrypt(4.0)
				eval.SubInplace(a, b)
				return a
			},
		},
		{
			want: -1.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				b := enc.Encode(4.0)
				eval.SubPlainInplace(a, b)
				return a
			},
		},
		{
			want: 12.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				b := encrypt(4.0)
				eval.MultiplyInplace(a, b)
				return a
			},
		},
		{
			want: 12.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				b := enc.Encode(4.0)
				eval.MultiplyPlainInplace(a, b)
				return a
			},
		},
		{
			want: 3.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				relinKeys := g.RelinKeys(60, 1)
				eval.RelinearizeInplace(a, relinKeys)
				return a
			},
		},
		{
			want: 3.0,
			f: func() *Ciphertext {
				a := encrypt(3.0)
				if !a.ParmsID().Eq(a.ParmsID()) {
					t.Fatalf("paramsID not eq")
				}
				return a
			},
		},
	}

	for i, c := range cases {
		ciphertext := c.f()
		plain := decryptor.Decrypt(ciphertext)
		out := enc.Decode(plain)
		if math.Abs(c.want-out) > 0.00001 {
			t.Fatal(i, "want != out", c.want, out)
		}
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
