package seal

// #cgo CXXFLAGS: -std=c++17
// #cgo LDFLAGS: -lseal
// #include "seal.h"
import "C"

import (
	"math"
	"runtime"
)

type EncryptionParams struct {
	ptr C.SEALEncryptionParameters
}

func NewEncryptionParamsBFV() *EncryptionParams {
	return newEncryptionParams(C.SEALEncryptionParametersBFV())
}

func NewEncryptionParamsCKKS() *EncryptionParams {
	return newEncryptionParams(C.SEALEncryptionParametersCKKS())
}

func newEncryptionParams(ptr C.SEALEncryptionParameters) *EncryptionParams {
	c := &EncryptionParams{
		ptr: ptr,
	}
	runtime.SetFinalizer(c, func(c *EncryptionParams) {
		C.SEALEncryptionParametersDelete(c.ptr)
		c.ptr = nil
	})
	return c
}

type Context struct {
	ptr C.SEALContext
}

func NewContext(params *EncryptionParams) *Context {
	c := &Context{
		ptr: C.SEALContextInit(params.ptr),
	}
	runtime.SetFinalizer(c, func(c *Context) {
		C.SEALContextDelete(c.ptr)
		c.ptr = nil
	})
	return c
}

type KeyGenerator struct {
	ptr C.SEALKeyGenerator
}

func NewKeyGenerator(c *Context) *KeyGenerator {
	g := &KeyGenerator{
		ptr: C.SEALKeyGeneratorInit(c.ptr),
	}
	runtime.SetFinalizer(g, func(g *KeyGenerator) {
		C.SEALKeyGeneratorDelete(g.ptr)
		g.ptr = nil
	})
	return g
}

type PublicKey struct {
	ptr C.SEALPublicKey
}

func (g *KeyGenerator) PublicKey() *PublicKey {
	k := &PublicKey{
		ptr: C.SEALKeyGeneratorPublicKey(g.ptr),
	}
	runtime.SetFinalizer(k, func(k *PublicKey) {
		C.SEALPublicKeyDelete(k.ptr)
		k.ptr = nil
	})
	return k
}

type SecretKey struct {
	ptr C.SEALSecretKey
}

func (g *KeyGenerator) SecretKey() *SecretKey {
	k := &SecretKey{
		ptr: C.SEALKeyGeneratorSecretKey(g.ptr),
	}
	runtime.SetFinalizer(k, func(k *SecretKey) {
		C.SEALSecretKeyDelete(k.ptr)
		k.ptr = nil
	})
	return k
}

type Encryptor struct {
	ptr C.SEALEncryptor
}

func NewEncryptor(c *Context, key *PublicKey) *Encryptor {
	e := &Encryptor{
		ptr: C.SEALEncryptorInit(c.ptr, key.ptr),
	}
	runtime.SetFinalizer(e, func(e *Encryptor) {
		C.SEALEncryptorDelete(e.ptr)
		e.ptr = nil
	})
	return e
}

func (e *Encryptor) Encrypt(p *Plaintext) *Ciphertext {
	return newCiphertext(C.SEALEncryptorEncrypt(e.ptr, p.ptr))
}

type Ciphertext struct {
	ptr C.SEALCiphertext
}

func newCiphertext(ptr C.SEALCiphertext) *Ciphertext {
	e := &Ciphertext{
		ptr: ptr,
	}
	runtime.SetFinalizer(e, func(e *Ciphertext) {
		C.SEALCiphertextDelete(e.ptr)
		e.ptr = nil
	})
	return e
}

type Evaluator struct {
	ptr C.SEALEvaluator
}

func NewEvaluator(c *Context) *Evaluator {
	e := &Evaluator{
		ptr: C.SEALEvaluatorInit(c.ptr),
	}
	runtime.SetFinalizer(e, func(e *Evaluator) {
		C.SEALEvaluatorDelete(e.ptr)
		e.ptr = nil
	})
	return e
}

type Decryptor struct {
	ptr C.SEALDecryptor
}

func NewDecryptor(c *Context, key *SecretKey) *Decryptor {
	d := &Decryptor{
		ptr: C.SEALDecryptorInit(c.ptr, key.ptr),
	}
	runtime.SetFinalizer(d, func(d *Decryptor) {
		C.SEALDecryptorDelete(d.ptr)
		d.ptr = nil
	})
	return d
}

func (d *Decryptor) Decrypt(c *Ciphertext) *Plaintext {
	return newPlaintext(C.SEALDecryptorDecrypt(d.ptr, c.ptr))
}

type BinaryFractionalEncoder struct {
	ptr C.SEALBinaryFractionalEncoder
}

func NewBinaryFractionalEncoder(params *EncryptionParams) *BinaryFractionalEncoder {
	d := &BinaryFractionalEncoder{
		ptr: C.SEALBinaryFractionalEncoderInit(params.ptr),
	}
	runtime.SetFinalizer(d, func(d *BinaryFractionalEncoder) {
		C.SEALBinaryFractionalEncoderDelete(d.ptr)
		d.ptr = nil
	})
	return d
}

func (e *BinaryFractionalEncoder) Encode(a float64) *Plaintext {
	return newPlaintext(C.SEALBinaryFractionalEncoderEncode(e.ptr, C.double(a)))
}

func (e *BinaryFractionalEncoder) Decode(p *Plaintext) float64 {
	return float64(C.SEALBinaryFractionalEncoderDecode(e.ptr, p.ptr))
}

type Plaintext struct {
	ptr C.SEALPlaintext
}

func newPlaintext(ptr C.SEALPlaintext) *Plaintext {
	obj := &Plaintext{
		ptr: ptr,
	}
	runtime.SetFinalizer(obj, func(obj *Plaintext) {
		C.SEALPlaintextDelete(obj.ptr)
		obj.ptr = nil
	})
	return obj
}

type CKKSEncoder struct {
	ptr C.SEALCKKSEncoder
}

func NewCKKSEncoder(c *Context) *CKKSEncoder {
	obj := &CKKSEncoder{
		ptr: C.SEALCKKSEncoderInit(c.ptr),
	}
	runtime.SetFinalizer(obj, func(obj *CKKSEncoder) {
		C.SEALCKKSEncoderDelete(obj.ptr)
		obj.ptr = nil
	})
	return obj
}

func (e *CKKSEncoder) Encode(num float64) *Plaintext {
	// 60 bits
	scale := math.Pow(2.0, 60)
	return newPlaintext(C.SEALCKKSEncoderEncode(e.ptr, C.double(num), C.double(scale)))
}

func (e *CKKSEncoder) Decode(p *Plaintext) float64 {
	return float64(C.SEALCKKSEncoderDecode(e.ptr, p.ptr))
}
