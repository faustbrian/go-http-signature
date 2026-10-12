package httpsignature

import (
	"context"
	"net/http"
	"testing"
)

// BenchmarkCreateSignatureBase measures one POST base with
// method/authority/path/content-type/content-digest coverage; request construction
// and parsing are excluded.
func BenchmarkCreateSignatureBase(b *testing.B) {
	request, err := http.NewRequest(http.MethodPost, "https://example.com/pay?tenant=one", nil)
	if err != nil {
		b.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Digest", "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:")
	inputs, _ := ParseSignatureInputs([]string{`sig=("@method" "@authority" "@path" "content-type" "content-digest");created=1700000000;keyid="key"`})
	input := inputs.Entries()[0]
	b.ReportAllocs()
	for b.Loop() {
		if _, err := CreateSignatureBase(MessageContext{Request: request}, input); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHMACSHA256SignVerify measures primitive signing/verification of one
// fixed short base; copied HMAC key construction is excluded, without
// resolver/replay policy.
func BenchmarkHMACSHA256SignVerify(b *testing.B) {
	key, _ := NewHMACKey([]byte("0123456789abcdef0123456789abcdef"))
	base := []byte(`"@method": POST
"@signature-params": ("@method");created=1700000000;keyid="key"`)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		signature, err := Sign(ctx, HMACSHA256, key, base, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := Verify(ctx, HMACSHA256, key, base, signature); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSHA256ContentDigest1MiB measures SHA-256 dictionary construction over 1
// MiB of zero bytes; content allocation is excluded, without I/O.
func BenchmarkSHA256ContentDigest1MiB(b *testing.B) {
	content := make([]byte, 1<<20)
	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ComputeDigests([]DigestAlgorithm{SHA256}, content); err != nil {
			b.Fatal(err)
		}
	}
}
