// Package x25519 implements Elliptic Curve Diffie-Hellman (ECDH) function over Curve25519.
// Details at https://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748
package x25519

import (
	"crypto/rand"
	"io"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of keys in bytes used in this package.
const KeySize = 32

// SecretKey is the type of Curve25519 secret keys.
type SecretKey struct {
	sk []byte
	pk PublicKey
	ur []byte // uniform representative of pk
}

// Bytes returns the secret key as a byte slice.
func (k *SecretKey) Bytes() []byte { return k.sk }

// Public returns the PublicKey corresponding to the secret key.
func (k *SecretKey) Public() PublicKey {
	if k.pk == nil {
		var pk, sk [32]byte
		copy(sk[:], k.sk)
		curve25519.ScalarBaseMult(&pk, &sk)
		k.pk = pk[:]
	}
	return k.pk
}

// PublicUniform returns the uniform representative of the public key corresponding to the secret key, or nil
// if the public key does not have a uniform representative.
func (k *SecretKey) PublicUniform() UniformRepresentative {
	if k.ur == nil {
		var sk, pk, ur [32]byte
		copy(sk[:], k.sk)
		if extra25519.ScalarBaseMult(&pk, &ur, &sk) {
			k.pk = pk[:]
			k.ur = ur[:]
		}
	}
	return k.ur
}

// Shared computes the shared secret between our secret key and peer's public key.
func (k *SecretKey) Shared(peer PublicKey) []byte {
	var shared, sk, pk [32]byte
	copy(sk[:], k.sk)
	copy(pk[:], peer)
	curve25519.ScalarMult(&shared, &sk, &pk)
	return shared[:]
}

// SharedUniform computes the shared secret between our secret key and peer public key's uniform representative.
func (k *SecretKey) SharedUniform(peer UniformRepresentative) []byte {
	var shared, pk, sk, ur [32]byte
	copy(ur[:], peer)
	copy(sk[:], k.sk)
	extra25519.RepresentativeToPublicKey(&pk, &ur)
	curve25519.ScalarMult(&shared, &sk, &pk)
	return shared[:]
}

// NewSecretKey creates a SecretKey from byte slice sk and len(sk) must be 32.
func NewSecretKey(sk []byte) *SecretKey {
	k := new(SecretKey)
	k.sk = sk
	return k
}

// GenerateKey generates a secret key using entropy from random, or crypto/rand.Reader
// if random is nil.
func GenerateKey(random io.Reader) (*SecretKey, error) {
	if random == nil {
		random = rand.Reader
	}
	k := new(SecretKey)
	k.sk = make([]byte, 32)
	_, err := io.ReadFull(random, k.sk)
	return k, err
}

// GenerateKeyUniform generates a secret key whose corresponding public key has a uniform representative
// using entropy from random, or crypto/rand.Reader if random is nil.
func GenerateKeyUniform(random io.Reader) (*SecretKey, error) {
	if random == nil {
		random = rand.Reader
	}
	var pk, sk, ur [32]byte
	for ok := false; !ok; ok = extra25519.ScalarBaseMult(&pk, &ur, &sk) {
		if _, err := io.ReadFull(random, sk[:]); err != nil {
			return nil, err
		}
	}
	k := new(SecretKey)
	k.sk = sk[:]
	k.pk = pk[:]
	k.ur = ur[:]
	return k, nil
}

// UniformRepresentative is the type of Curve25519 public key uniform representatives.
// See https://www.imperialviolet.org/2013/12/25/elligator.html
type UniformRepresentative []byte

// Public returns the curve25519 public key corresponding to the uniform presentative.
func (u UniformRepresentative) Public() PublicKey {
	var pk, ur [32]byte
	copy(ur[:], u)
	extra25519.RepresentativeToPublicKey(&pk, &ur)
	return pk[:]
}

// PublicKey is the type of Curve25519 public keys.
type PublicKey []byte
