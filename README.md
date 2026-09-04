# hermetic

A tiny Go package that seals and unseals byte slices with a shared cipher.

## What this is (and isn't)

`Seal` / `Unseal` cycle a cipher over a subject and apply inverse byte shifts.
Anyone who has the same cipher can reverse the result. There is **no** authenticity
check, nonce, or resistance to known-plaintext or key-recovery style attacks.

Use it when you want shared-secret **obfuscation** for tokens or blobs — not when
you need encryption.

## Install

```shell
go get github.com/invisible-gibson/hermetic@latest
```

## Usage

```go
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/invisible-gibson/hermetic"
)

func main() {
	cipher := []byte("shared-secret")
	token := hermetic.Seal(cipher, []byte(`{"sub":"ada","role":"reader"}`))
	fmt.Println(base64.URLEncoding.EncodeToString(token))

	plain := hermetic.Unseal(cipher, token)
	fmt.Println(string(plain))
}
```

Both `Seal` and `Unseal` return a new slice; they never mutate the caller's input.
An empty cipher returns a copy of the subject unchanged.

## License

See [LICENSE](LICENSE).
