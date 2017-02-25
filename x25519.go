// Package x25519 implements Elliptic Curve Diffie-Hellman (ECDH) function over Curve25519.
// Details at https://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748
package x25519

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of keys in bytes used in this package.
const KeySize = 32

// PublicKey is the type of Curve25519 public keys
type PublicKey []byte

// SecretKey is the type of Curve25519 secret keys
type SecretKey []byte

// Public returns the PublicKey corresponding to the SecretKey.
func (k SecretKey) Public() PublicKey {
	var sk, pk [KeySize]byte
	copy(sk[:], k)
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk[:]
}

// GenerateKey generates a public/secret key pair using entropy from random, or crypto/rand.Reader
// if random is nil.
func GenerateKey(random io.Reader) (PublicKey, SecretKey, error) {
	var pk, sk [KeySize]byte
	if random == nil {
		random = rand.Reader
	}
	if _, err := io.ReadFull(random, sk[:]); err != nil {
		return nil, nil, err
	}
	// NOTE: clamping is not necessary because curve25519.ScaleMult will do it anyway.
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk[:], sk[:], nil
}

// ComputeSecret computes the shared secret between our secret key and their public key.
func ComputeSecret(our SecretKey, their PublicKey) []byte {
	var shared, sk, pk [KeySize]byte
	copy(sk[:], our)
	copy(pk[:], their)
	curve25519.ScalarMult(&shared, &sk, &pk)
	return shared[:]
}
