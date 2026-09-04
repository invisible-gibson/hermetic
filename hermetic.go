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
// If cipher is empty, the result is a copy of subject unchanged — this is
// deliberate (not an error): a missing/blank secret is treated as a no-op.
func Seal(cipher, subject []byte) []byte {
	return scramble(true, cipher, subject)
}

// Unseal reverses a Seal with the same cipher and returns a new slice.
// If cipher is empty, the result is a copy of subject unchanged.
func Unseal(cipher, subject []byte) []byte {
	return scramble(false, cipher, subject)
}

func scramble(seal bool, cipher, subject []byte) []byte {
	out := make([]byte, len(subject))
	copy(out, subject)
	if len(cipher) == 0 {
		return out
	}
	for i := 0; i < len(out); i++ {
		d := cipher[i%len(cipher)] - 128
		if seal {
			out[i] += d
		} else {
			out[i] -= d
		}
	}
	return out
}
