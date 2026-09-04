// Package hermetic provides a small shared-secret byte scrambler.
//
// Seal and Unseal cycle a cipher over a subject and apply inverse byte shifts.
// This is intentional obfuscation for tokens and blobs that share a secret —
// not encryption. There is no authenticity check, nonce, or resistance to
// known-plaintext or key-recovery attacks. Anyone who has the cipher can
// reverse the sealed bytes.
//
// Both Seal and Unseal return a newly allocated slice; the caller's subject
// is never mutated.
package hermetic

// Seal scrambles subject with cipher and returns a new sealed slice.
// If cipher is empty, the result is a copy of subject unchanged.
func Seal(cipher, subject []byte) []byte {
	return scramble(seal, cipher, subject)
}

// Unseal reverses a Seal with the same cipher and returns a new slice.
// If cipher is empty, the result is a copy of subject unchanged.
func Unseal(cipher, subject []byte) []byte {
	return scramble(unseal, cipher, subject)
}

type sealerFN func(byte) byte

func seal(b byte) byte {
	return b - 128
}

func unseal(b byte) byte {
	return 128 - b
}

func scramble(fn sealerFN, cipher, subject []byte) []byte {
	out := make([]byte, len(subject))
	copy(out, subject)
	if len(cipher) == 0 {
		return out
	}
	for i, ix := 0, 0; i < len(out); i, ix = i+1, ix+1 {
		if ix == len(cipher) {
			ix = 0
		}
		out[i] = out[i] + fn(cipher[ix])
	}
	return out
}
