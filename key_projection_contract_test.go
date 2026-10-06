package httpsignature_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	hs "github.com/faustbrian/go-http-signature"
)

// KP-01/KP-03: independent complete literals distinguish member projection
// from a signer/verifier pair sharing the same serialization bug.
func TestKeyProjectionPreservesRFC8941Members(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"bare true", []string{"a"}, "?1"},
		{"true", []string{"a=?1"}, "?1"},
		{"false", []string{"a=?0"}, "?0"},
		{"integer", []string{"a=-7"}, "-7"},
		{"decimal", []string{"a=1.250"}, "1.25"},
		{"string", []string{`a="text"`}, `"text"`},
		{"token", []string{"a=token"}, "token"},
		{"binary padding", []string{"a=:aGVsbG8:"}, ":aGVsbG8=:"},
		{"parameters", []string{"a=?1;flag"}, "?1;flag"},
		{"valued true parameters", []string{"a=?1;p;z=1"}, "?1;p;z=1"},
		{"string true parameter", []string{`a=?1;p="text"`}, `?1;p="text"`},
		{"inner list", []string{`a=(1 "two");flag`}, `(1 "two");flag`},
		{"empty inner list", []string{"a=()"}, "()"},
		{"combined field lines", []string{"a=1", "b=2"}, "1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, input := keyProjectionInput(t, test.values)
			got, err := hs.CreateSignatureBase(ctx, input)
			want := "\"@method\": GET\n\"x-structured\";key=\"a\": " + test.want + "\n\"@signature-params\": (\"@method\" \"x-structured\";key=\"a\")"
			if err != nil || got != want {
				t.Fatalf("base=%q error=%v; want literal %q", got, err, want)
			}
		})
	}
}

// KP-02/KP-04: every value and parameter is constrained by the complete
// RFC8941 Dictionary, including members outside the selected key.
func TestKeyProjectionRejectsLaterDialectAtomically(t *testing.T) {
	tests := []struct{ name, wire string }{
		{"display string", `a=%""`}, {"date", "a=@1"},
		{"display parameter", `a=?1;p=%""`}, {"date parameter", "a=?1;p=@1"},
		{"display inner item", `a=(%"")`}, {"date inner item", "a=(@1)"},
		{"display inner item parameter", `a=(1;p=%"")`}, {"date inner item parameter", "a=(1;p=@1)"},
		{"display inner list parameter", `a=(1);p=%""`}, {"date inner list parameter", "a=(1);p=@1"},
		{"unselected display", `a=1, b=%""`}, {"unselected display first", `b=%"", a=1`}, {"unselected date", "a=1, b=@1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, input := keyProjectionInput(t, []string{test.wire})
			base, err := hs.CreateSignatureBase(ctx, input)
			if base != "" || !errors.Is(err, hs.ErrSignatureBase) {
				t.Fatalf("unsupported Dictionary base=%q error=%v; want empty base and ErrSignatureBase", base, err)
			}
		})
	}
}

func keyProjectionInput(t *testing.T, values []string) (hs.MessageContext, hs.SignatureInput) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header["X-Structured"] = values
	inputs, err := hs.ParseSignatureInputs([]string{`sig=("@method" "x-structured";key="a")`})
	if err != nil {
		t.Fatal(err)
	}
	return hs.MessageContext{Request: request}, inputs.Entries()[0]
}

type keyProjectionProvider struct{ key hs.SigningKey }

func (p keyProjectionProvider) SigningKey(context.Context) (hs.SigningKey, error) { return p.key, nil }

type keyProjectionResolver struct{ key hs.ResolvedKey }

func (r keyProjectionResolver) Resolve(context.Context, string) (hs.ResolvedKey, error) {
	return r.key, nil
}

// KP-05: modify only the covered field after a real valid signature. The
// expected base-stage failure is independent of cryptographic round trips.
func TestKeyProjectionRejectsSignedDisplayStringTampering(t *testing.T) {
	assertKeyProjectionTampering(t, "a=?1", `a=%""`, true)
}

func TestKeyProjectionRejectsSignedTrueParameterTampering(t *testing.T) {
	assertKeyProjectionTampering(t, "a=?1;p=1", "a=1", false)
}

func assertKeyProjectionTampering(t *testing.T, original, modified string, invalidDialect bool) {
	t.Helper()
	now := time.Unix(1700000000, 0)
	key, err := hs.NewHMACKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	components := []hs.ComponentIdentifier{{Name: "@method"}, {Name: "x-structured", Parameters: []hs.Parameter{{Name: "key", Value: "a"}}}}
	signing, err := hs.NewSigningProfile(hs.SigningProfileConfig{
		AllowedAlgorithms: []hs.Algorithm{hs.HMACSHA256}, CoveredComponents: components,
		Expires: hs.ParameterForbidden, AlgorithmParameter: hs.ParameterRequired, Nonce: hs.ParameterForbidden, Tag: hs.ParameterForbidden,
		ResolveTimeout: time.Second, Now: func() time.Time { return now }, Provider: keyProjectionProvider{hs.SigningKey{KeyID: "key-projection", Algorithm: hs.HMACSHA256, Key: key, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := hs.NewVerificationProfile(hs.VerificationProfileConfig{
		AllowedAlgorithms: []hs.Algorithm{hs.HMACSHA256}, RequiredComponents: components,
		Created: hs.ParameterRequired, Expires: hs.ParameterForbidden, AlgorithmParameter: hs.ParameterRequired, Nonce: hs.ParameterForbidden, Tag: hs.ParameterForbidden,
		MaxAge: time.Minute, ClockSkew: time.Second, ResolveTimeout: time.Second, Now: func() time.Time { return now }, Resolver: keyProjectionResolver{hs.ResolvedKey{Algorithm: hs.HMACSHA256, Key: key, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), FreshUntil: now.Add(time.Minute)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := keyProjectionInput(t, []string{original})
	signer := hs.NewSigner(signing)
	verifier := hs.NewVerifier(verification)
	fields, err := signer.Sign(context.Background(), ctx, "sig", hs.SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := hs.ParseSignatureInputs([]string{fields.SignatureInputField()})
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := hs.ParseSignatures([]string{fields.SignatureField()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.Verify(context.Background(), ctx, "sig", inputs, signatures); err != nil {
		t.Fatal("valid original signature", err)
	}
	ctx.Request.Header.Set("X-Structured", modified)
	verified, err := verifier.Verify(context.Background(), ctx, "sig", inputs, signatures)
	var failure *hs.VerificationError
	wrongFailure := !errors.Is(err, hs.ErrInvalidSignatureValue)
	if invalidDialect {
		wrongFailure = !errors.As(err, &failure) || failure.Failure != hs.VerificationBase
	}
	if wrongFailure || !reflect.ValueOf(verified).IsZero() {
		t.Fatalf("tampered field accepted or wrong failure: result=%+v error=%v", verified, err)
	}
	if !invalidDialect {
		return
	}
	invalidFields, err := signer.Sign(context.Background(), ctx, "sig", hs.SigningOptions{})
	if !errors.Is(err, hs.ErrSigningBase) || !reflect.ValueOf(invalidFields).IsZero() {
		t.Fatalf("invalid signing produced fields or wrong failure: fields=%+v error=%v", invalidFields, err)
	}
}
