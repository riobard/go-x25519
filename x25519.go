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

type PublicKey [32]byte

func (pk *PublicKey) String() string { return string(pk[:]) }

// SecretKey is the type of Curve25519 secret keys
type SecretKey struct {
	sk [32]byte
	pk *PublicKey
	ur *[32]byte
}

func NewSecretKey(sk []byte) *SecretKey {
	k := new(SecretKey)
	copy(k.sk[:], sk)
	return k
}

func (k *SecretKey) Bytes() []byte  { return k.sk[:] }
func (k *SecretKey) String() string { return string(k.sk[:]) }

// Public returns the PublicKey corresponding to the secret key.
func (k *SecretKey) Public() *PublicKey {
	if k.pk == nil {
		k.pk = new(PublicKey)
		curve25519.ScalarBaseMult((*[32]byte)(k.pk), &k.sk)
	}
	return k.pk
}

// Uniform returns the uniform representative of the public key corresponding to the secret key, or nil
// if the public key does not have a uniform representative.
func (k *SecretKey) Uniform() *[32]byte {
	if k.ur == nil {
		pk := new(PublicKey)
		ur := new([32]byte)
		if extra25519.ScalarBaseMult((*[32]byte)(pk), ur, &k.sk) {
			k.pk = pk
			k.ur = ur
		}
	}
	return k.ur
}

// Shared computes the shared secret between our secret key and their public key.
func (k *SecretKey) Shared(shared *[32]byte, theirPublic *PublicKey) {
	curve25519.ScalarMult(shared, &k.sk, (*[32]byte)(theirPublic))
}

// SharedUniform computes the shared secret between our secret key and their public key's uniform representative.
func (k *SecretKey) SharedUniform(shared, theirRepresentative *[32]byte) {
	pk := new([32]byte)
	extra25519.RepresentativeToPublicKey(pk, theirRepresentative)
	curve25519.ScalarMult(shared, &k.sk, pk)
}

// GenerateKey generates a secret key using entropy from random, or crypto/rand.Reader
// if random is nil.
func GenerateKey(random io.Reader) (*SecretKey, error) {
	if random == nil {
		random = rand.Reader
	}
	sk := new(SecretKey)
	_, err := io.ReadFull(random, sk.sk[:])
	return sk, err
}

// GenerateKeyUniform generates a secret key whose corresponding public key has a uniform representative
// using entropy from random, or crypto/rand.Reader if random is nil.
func GenerateKeyUniform(random io.Reader) (*SecretKey, error) {
	if random == nil {
		random = rand.Reader
	}
	sk := new(SecretKey)
	for ok := false; !ok; ok = extra25519.ScalarBaseMult((*[32]byte)(sk.pk), sk.ur, &sk.sk) {
		if _, err := io.ReadFull(random, sk.sk[:]); err != nil {
			return nil, err
		}
	}
	return sk, nil
}

// RepresentativeToPublicKey converts a uniform representative to a curve25519 public key.
func RepresentativeToPublicKey(publicKey, representative *[32]byte) {
	extra25519.RepresentativeToPublicKey(publicKey, representative)
}
