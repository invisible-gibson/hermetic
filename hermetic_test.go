package hermetic

import (
	"bytes"
	"testing"
)

func TestRoundTripShortString(t *testing.T) {
	cipher := []byte("secret-key")
	subject := []byte("hello hermetic")
	sealed := Seal(cipher, subject)
	if bytes.Equal(sealed, subject) {
		t.Fatal("sealed output should differ from plaintext for this input")
	}
	if !bytes.Equal(subject, []byte("hello hermetic")) {
		t.Fatal("Seal mutated the caller's subject")
	}
	got := Unseal(cipher, sealed)
	if !bytes.Equal(got, subject) {
		t.Fatalf("round-trip: got %q want %q", got, subject)
	}
}

func TestEmptySubject(t *testing.T) {
	cipher := []byte("abc")
	sealed := Seal(cipher, nil)
	if len(sealed) != 0 {
		t.Fatalf("sealed empty subject: len=%d", len(sealed))
	}
	unsealed := Unseal(cipher, sealed)
	if len(unsealed) != 0 {
		t.Fatalf("unsealed empty: len=%d", len(unsealed))
	}
}

func TestEmptyCipherLeavesCopy(t *testing.T) {
	subject := []byte("leave me")
	sealed := Seal(nil, subject)
	if !bytes.Equal(sealed, subject) {
		t.Fatalf("empty cipher Seal: got %q want %q", sealed, subject)
	}
	sealed[0] = 'X'
	if subject[0] != 'l' {
		t.Fatal("empty-cipher Seal should not share the subject buffer")
	}
	unsealed := Unseal(nil, []byte("leave me"))
	if !bytes.Equal(unsealed, []byte("leave me")) {
		t.Fatalf("empty cipher Unseal: got %q", unsealed)
	}
}

func TestCipherShorterAndLongerThanSubject(t *testing.T) {
	cases := []struct {
		name    string
		cipher  []byte
		subject []byte
	}{
		{"cipher shorter", []byte("ab"), []byte("abcdefgh")},
		{"cipher longer", []byte("abcdefghijklmnop"), []byte("xy")},
		{"cipher equal", []byte("same"), []byte("len4")},
		{"single-byte cipher", []byte{0x5a}, []byte("zzzzzzzz")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Unseal(tc.cipher, Seal(tc.cipher, tc.subject))
			if !bytes.Equal(got, tc.subject) {
				t.Fatalf("got %v want %v", got, tc.subject)
			}
		})
	}
}

func TestBinaryAndNonASCII(t *testing.T) {
	cipher := []byte{0x00, 0xff, 0x7f, 0x80}
	subject := []byte{0x00, 0x01, 0xfe, 0xff, 0x80, 0x7f}
	got := Unseal(cipher, Seal(cipher, subject))
	if !bytes.Equal(got, subject) {
		t.Fatalf("got %v want %v", got, subject)
	}
	unicode := []byte("café 日本語 🔐")
	got = Unseal(cipher, Seal(cipher, unicode))
	if !bytes.Equal(got, unicode) {
		t.Fatalf("unicode round-trip failed: %q", got)
	}
}

func TestSealDoesNotMutateInput(t *testing.T) {
	cipher := []byte("key")
	orig := []byte("mutable?")
	before := append([]byte(nil), orig...)
	_ = Seal(cipher, orig)
	if !bytes.Equal(orig, before) {
		t.Fatalf("Seal mutated input: got %q want %q", orig, before)
	}
	_ = Unseal(cipher, orig)
	if !bytes.Equal(orig, before) {
		t.Fatalf("Unseal mutated input: got %q want %q", orig, before)
	}
}

func TestUnsealThenSeal(t *testing.T) {
	cipher := []byte("round")
	// Start from "sealed-looking" bytes and prove Unseal+Seal is identity too.
	blob := []byte{10, 20, 30, 40, 50, 60}
	got := Seal(cipher, Unseal(cipher, blob))
	if !bytes.Equal(got, blob) {
		t.Fatalf("Unseal then Seal: got %v want %v", got, blob)
	}
}

func TestKnownGoldenVector(t *testing.T) {
	cipher := []byte{1, 2, 3}
	subject := []byte{10, 20, 30, 40}
	wantSealed := []byte{139, 150, 161, 169}
	got := Seal(cipher, subject)
	if !bytes.Equal(got, wantSealed) {
		t.Fatalf("golden Seal: got %v want %v", got, wantSealed)
	}
	if !bytes.Equal(Unseal(cipher, got), subject) {
		t.Fatal("golden Unseal failed")
	}
}

func TestDifferentCiphersDoNotRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		cipher  []byte
		subject []byte
		sealed  []byte
	}{
		{
			name:    "alpha over payload",
			cipher:  []byte("alpha-key"),
			subject: []byte("payload"),
			sealed:  []byte{81, 77, 105, 84, 80, 14, 79},
		},
		{
			name:    "short cipher vs long subject",
			cipher:  []byte{1, 2},
			subject: []byte{10, 20, 30, 40},
			sealed:  []byte{139, 150, 159, 170},
		},
		{
			name:    "binary cipher",
			cipher:  []byte{0x00, 0xff},
			subject: []byte{0x10, 0x20, 0x30},
			sealed:  []byte{0x90, 0x9f, 0xb0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Seal(tc.cipher, tc.subject)
			if !bytes.Equal(got, tc.sealed) {
				t.Fatalf("Seal: got %v want %v", got, tc.sealed)
			}
			if !bytes.Equal(Unseal(tc.cipher, got), tc.subject) {
				t.Fatal("same-cipher Unseal failed")
			}
			wrongCipher := append([]byte(nil), tc.cipher...)
			if len(wrongCipher) > 0 {
				wrongCipher[0] ^= 0xff
			} else {
				wrongCipher = []byte{0x42}
			}
			wrong := Unseal(wrongCipher, got)
			if bytes.Equal(wrong, tc.subject) {
				t.Fatal("different cipher should not recover plaintext")
			}
		})
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("cipher"), []byte("subject"))
	f.Add([]byte{1, 2, 3}, []byte{10, 20, 30, 40})
	f.Add([]byte{}, []byte("plain"))
	f.Add([]byte("k"), []byte{})
	f.Fuzz(func(t *testing.T, cipher, subject []byte) {
		got := Unseal(cipher, Seal(cipher, subject))
		if !bytes.Equal(got, subject) {
			t.Fatalf("round-trip failed: cipher=%v subject=%v got=%v", cipher, subject, got)
		}
	})
}
