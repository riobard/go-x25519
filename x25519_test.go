package x25519

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	// Test vector from https://tools.ietf.org/html/rfc7748#section-6.1
	aliceSK      = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	alicePK      = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	bobSK        = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	bobPK        = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	sharedSecret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

func TestGenerateKey(t *testing.T) {
	ask, err := hex.DecodeString(aliceSK)
	if err != nil {
		t.Fatal(err)
	}

	apk := SecretKey(ask).Public()
	if alicePK != hex.EncodeToString(apk[:]) {
		t.Fatal("public key failed")
	}

	bsk, err := hex.DecodeString(bobSK)
	if err != nil {
		t.Fatal(err)
	}
	bpk := SecretKey(bsk).Public()

	if bobPK != hex.EncodeToString(bpk) {
		t.Fatal("public key failed")
	}

	s1 := hex.EncodeToString(ComputeSecret(ask, bpk))
	s2 := hex.EncodeToString(ComputeSecret(bsk, apk))
	if s1 != s2 {
		t.Fatal("shared secret failed")
	}
	if s1 != sharedSecret {
		t.Fatal("shared secret failed")
	}
}

func TestGenerateKey2(t *testing.T) {
	ourPK, ourSK, _ := GenerateKey(nil)
	theirPK, theirSK, _ := GenerateKey(nil)

	t.Logf("our secret = %0x", ourSK)
	t.Logf("our public = %0x", ourPK)
	t.Logf("their secret = %0x", theirSK)
	t.Logf("their public = %0x", theirPK)

	s1 := ComputeSecret(ourSK, theirPK)
	s2 := ComputeSecret(theirSK, ourPK)
	if !bytes.Equal(s1, s2) {
		t.Fatal("computed shared secrets differs")
	}
	t.Logf("shared secret = %0x", s1)
}
