package comparison_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"

	dadrus "github.com/dadrus/httpsig"
	httpsignature "github.com/faustbrian/go-http-signature"
	peer "github.com/yaronf/httpsign"
)

var benchmarkKey = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

type signingProvider struct{ key httpsignature.SigningKey }

func (provider signingProvider) SigningKey(context.Context) (httpsignature.SigningKey, error) {
	return provider.key, nil
}

type keyResolver struct{ key httpsignature.ResolvedKey }

func (resolver keyResolver) Resolve(context.Context, string) (httpsignature.ResolvedKey, error) {
	return resolver.key, nil
}

type localCandidate struct {
	signer   *httpsignature.Signer
	verifier *httpsignature.Verifier
}

type peerCandidate struct {
	signer   *peer.Signer
	verifier *peer.Verifier
}

type dadrusCandidate struct {
	signer   dadrus.Signer
	verifier dadrus.Verifier
}

func TestCandidatesSignAndVerifyEquivalentRequestCoverage(t *testing.T) {
	t.Parallel()
	for name, signAndVerify := range map[string]func(*http.Request) error{
		"local":  newLocalCandidate(t).signAndVerify,
		"yaron":  newPeerCandidate(t).signAndVerify,
		"dadrus": newDadrusCandidate(t).signAndVerify,
	} {
		t.Run(name, func(t *testing.T) {
			request := benchmarkRequest(t)
			before := time.Now().Unix()
			if err := signAndVerify(request); err != nil {
				t.Fatalf("sign and verify: %v", err)
			}
			assertEquivalentSignedOperation(t, request, before, time.Now().Unix())
		})
	}
}

func assertEquivalentSignedOperation(t *testing.T, request *http.Request, before, after int64) {
	t.Helper()
	inputs, err := httpsignature.ParseSignatureInputs(request.Header.Values("Signature-Input"))
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := httpsignature.ParseSignatures(request.Header.Values("Signature"))
	if err != nil {
		t.Fatal(err)
	}
	entries, values := inputs.Entries(), signatures.Entries()
	if len(entries) != 1 || len(values) != 1 || entries[0].Label != "sig" || values[0].Label != "sig" {
		t.Fatal("want exactly one matching sig field pair")
	}
	input := entries[0]
	if len(input.Components) != 3 {
		t.Fatalf("covered components = %#v", input.Components)
	}
	for index, name := range []string{"@method", "@authority", "content-type"} {
		if input.Components[index].Name != name || len(input.Components[index].Parameters) != 0 {
			t.Fatalf("component %d = %#v, want %s without parameters", index, input.Components[index], name)
		}
	}
	created, ok := input.Parameter("created")
	stamp, integer := created.(int64)
	if !ok || !integer || stamp < before || stamp > after {
		t.Fatalf("created = %#v, want signing interval [%d, %d]", created, before, after)
	}
	for name, want := range map[string]string{"keyid": "benchmark-key", "alg": "hmac-sha256"} {
		if value, present := input.Parameter(name); !present || value != want {
			t.Fatalf("%s = %#v, want %q", name, value, want)
		}
	}
	if len(input.Parameters) != 3 || len(values[0].Parameters) != 0 {
		t.Fatal("unexpected signature parameters")
	}
	// Fixed component bytes and standard-library HMAC do not trust candidate verification.
	base := "\"@method\": POST\n\"@authority\": api.example.test\n\"content-type\": application/json\n\"@signature-params\": " + strings.TrimPrefix(inputs.String(), "sig=")
	mac := hmac.New(sha256.New, benchmarkKey)
	_, _ = mac.Write([]byte(base))
	if !hmac.Equal(mac.Sum(nil), values[0].Value) {
		t.Fatal("signature does not authenticate the equivalent operation")
	}
}

func TestPeerVerificationRejectsCoveredHeaderTampering(t *testing.T) {
	t.Parallel()
	candidate := newPeerCandidate(t)
	request := benchmarkRequest(t)
	if err := candidate.signAndVerify(request); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "text/plain")
	if err := peer.VerifyRequest("sig", *candidate.verifier, request); err == nil {
		t.Fatal("peer verified modified covered content-type without re-signing")
	}
}

func TestCandidatesDoNotAccumulateSignatureFieldsAcrossCalls(t *testing.T) {
	t.Parallel()

	t.Run("HTTPMessageSignature", func(t *testing.T) {
		candidate := newLocalCandidate(t)
		assertCandidateDoesNotAccumulateSignatures(t, candidate.signAndVerify)
	})
	t.Run("YaronFHTTPSign", func(t *testing.T) {
		candidate := newPeerCandidate(t)
		assertCandidateDoesNotAccumulateSignatures(t, candidate.signAndVerify)
	})
	t.Run("DadrusHTTPSig", func(t *testing.T) {
		candidate := newDadrusCandidate(t)
		assertCandidateDoesNotAccumulateSignatures(t, candidate.signAndVerify)
	})
}

func assertCandidateDoesNotAccumulateSignatures(t *testing.T, signAndVerify func(*http.Request) error) {
	t.Helper()

	request := benchmarkRequest(t)
	for range 2 {
		if err := signAndVerify(request); err != nil {
			t.Fatalf("sign and verify: %v", err)
		}
	}
	inputs, err := httpsignature.ParseSignatureInputs(request.Header.Values("Signature-Input"))
	if err != nil {
		t.Fatalf("parse Signature-Input: %v", err)
	}
	signatures, err := httpsignature.ParseSignatures(request.Header.Values("Signature"))
	if err != nil {
		t.Fatalf("parse Signature: %v", err)
	}
	if entries := inputs.Entries(); len(entries) != 1 || entries[0].Label != "sig" {
		t.Fatalf("Signature-Input entries = %#v, want one sig entry", entries)
	}
	if entries := signatures.Entries(); len(entries) != 1 || entries[0].Label != "sig" {
		t.Fatalf("Signature entries = %#v, want one sig entry", entries)
	}
}

func BenchmarkRequestHMACSHA256SignVerify(b *testing.B) {
	b.Run("HTTPMessageSignature", func(b *testing.B) {
		candidate := newLocalCandidate(b)
		request := benchmarkRequest(b)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := candidate.signAndVerify(request); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("YaronFHTTPSign", func(b *testing.B) {
		candidate := newPeerCandidate(b)
		request := benchmarkRequest(b)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := candidate.signAndVerify(request); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("DadrusHTTPSig", func(b *testing.B) {
		candidate := newDadrusCandidate(b)
		request := benchmarkRequest(b)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := candidate.signAndVerify(request); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func newLocalCandidate(tb testing.TB) localCandidate {
	tb.Helper()
	key, err := httpsignature.NewHMACKey(benchmarkKey)
	if err != nil {
		tb.Fatal(err)
	}
	components := []httpsignature.ComponentIdentifier{{Name: "@method"}, {Name: "@authority"}, {Name: "content-type"}}
	signingProfile, err := httpsignature.NewSigningProfile(httpsignature.SigningProfileConfig{
		AllowedAlgorithms:  []httpsignature.Algorithm{httpsignature.HMACSHA256},
		CoveredComponents:  components,
		Expires:            httpsignature.ParameterForbidden,
		AlgorithmParameter: httpsignature.ParameterRequired,
		Nonce:              httpsignature.ParameterForbidden,
		Tag:                httpsignature.ParameterForbidden,
		ResolveTimeout:     time.Second,
		Now:                time.Now,
		Provider: signingProvider{key: httpsignature.SigningKey{
			KeyID: "benchmark-key", Algorithm: httpsignature.HMACSHA256, Key: key,
			NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<62, 0),
		}},
	})
	if err != nil {
		tb.Fatal(err)
	}
	verificationProfile, err := httpsignature.NewVerificationProfile(httpsignature.VerificationProfileConfig{
		AllowedAlgorithms:  []httpsignature.Algorithm{httpsignature.HMACSHA256},
		RequiredComponents: components,
		Created:            httpsignature.ParameterRequired,
		Expires:            httpsignature.ParameterForbidden,
		AlgorithmParameter: httpsignature.ParameterRequired,
		Nonce:              httpsignature.ParameterForbidden,
		Tag:                httpsignature.ParameterForbidden,
		MaxAge:             time.Minute,
		ClockSkew:          time.Second,
		ResolveTimeout:     time.Second,
		Now:                time.Now,
		Resolver: keyResolver{key: httpsignature.ResolvedKey{
			Algorithm: httpsignature.HMACSHA256, Key: key,
			NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<62, 0), FreshUntil: time.Unix(1<<62, 0),
		}},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return localCandidate{signer: httpsignature.NewSigner(signingProfile), verifier: httpsignature.NewVerifier(verificationProfile)}
}

func (candidate localCandidate) signAndVerify(request *http.Request) error {
	resetSignatureFields(request)
	signed, err := candidate.signer.Sign(context.Background(), httpsignature.MessageContext{Request: request}, "sig", httpsignature.SigningOptions{})
	if err != nil {
		return err
	}
	request.Header.Set("Signature-Input", signed.SignatureInputField())
	request.Header.Set("Signature", signed.SignatureField())
	inputs, err := httpsignature.ParseSignatureInputs(request.Header.Values("Signature-Input"))
	if err != nil {
		return err
	}
	signatures, err := httpsignature.ParseSignatures(request.Header.Values("Signature"))
	if err != nil {
		return err
	}
	_, err = candidate.verifier.Verify(context.Background(), httpsignature.MessageContext{Request: request}, "sig", inputs, signatures)
	return err
}

func newPeerCandidate(tb testing.TB) peerCandidate {
	tb.Helper()
	fields := peer.Headers("@method", "@authority", "content-type")
	signer, err := peer.NewHMACSHA256Signer(benchmarkKey, peer.NewSignConfig().SetKeyID("benchmark-key"), fields)
	if err != nil {
		tb.Fatal(err)
	}
	verifier, err := peer.NewHMACSHA256Verifier(benchmarkKey, peer.NewVerifyConfig().SetKeyID("benchmark-key"), fields)
	if err != nil {
		tb.Fatal(err)
	}
	return peerCandidate{signer: signer, verifier: verifier}
}

func (candidate peerCandidate) signAndVerify(request *http.Request) error {
	resetSignatureFields(request)
	signatureInput, signature, err := peer.SignRequest("sig", *candidate.signer, request)
	if err != nil {
		return err
	}
	request.Header.Set("Signature-Input", signatureInput)
	request.Header.Set("Signature", signature)
	return peer.VerifyRequest("sig", *candidate.verifier, request)
}

func newDadrusCandidate(tb testing.TB) dadrusCandidate {
	tb.Helper()
	key := dadrus.Key{KeyID: "benchmark-key", Algorithm: dadrus.HmacSha256, Key: benchmarkKey}
	signer, err := dadrus.NewSigner(key,
		dadrus.WithLabel("sig"),
		dadrus.WithTTL(0),
		dadrus.WithNonce(dadrus.NonceGetterFunc(func(context.Context) (string, error) { return "", nil })),
		dadrus.WithComponents("@method", "@authority", "content-type"),
	)
	if err != nil {
		tb.Fatal(err)
	}
	verifier, err := dadrus.NewVerifier(key,
		dadrus.WithValidateAllSignatures(),
		dadrus.WithRequiredComponents("@method", "@authority", "content-type"),
		dadrus.WithCreatedTimestampRequired(true),
		dadrus.WithExpiredTimestampRequired(false),
		dadrus.WithMaxAge(time.Minute),
		dadrus.WithValidityTolerance(time.Second),
	)
	if err != nil {
		tb.Fatal(err)
	}
	return dadrusCandidate{signer: signer, verifier: verifier}
}

func (candidate dadrusCandidate) signAndVerify(request *http.Request) error {
	resetSignatureFields(request)
	header, err := candidate.signer.Sign(dadrus.MessageFromRequest(request))
	if err != nil {
		return err
	}
	request.Header.Set("Signature-Input", header.Get("Signature-Input"))
	request.Header.Set("Signature", header.Get("Signature"))
	return candidate.verifier.Verify(dadrus.MessageFromRequest(request))
}

func resetSignatureFields(request *http.Request) {
	request.Header.Del("Signature-Input")
	request.Header.Del("Signature")
}

func benchmarkRequest(tb testing.TB) *http.Request {
	tb.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://api.example.test/payments?tenant=one", nil)
	if err != nil {
		tb.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}
