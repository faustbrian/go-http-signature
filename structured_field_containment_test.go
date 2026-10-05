package httpsignature

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dunglas/httpsfv"
)

func TestStructuredFieldParserFaultContainment(t *testing.T) {
	t.Parallel()
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("a", httpsfv.NewItem(int64(1)))
	t.Run("dictionary", func(t *testing.T) { assertStructuredParserContainment(t, dictionary) })
	t.Run("list", func(t *testing.T) {
		assertStructuredParserContainment(t, httpsfv.List{httpsfv.NewItem("value")})
	})
	t.Run("item", func(t *testing.T) { assertStructuredParserContainment(t, httpsfv.NewItem("value")) })
}

func assertStructuredParserContainment[T any](t *testing.T, want T) {
	t.Helper()
	input := []string{`"0000`, `"`}
	ordinaryError := errors.New("ordinary supplier error")
	for _, test := range []struct {
		name string
		err  error
	}{{"success", nil}, {"ordinary-error", ordinaryError}} {
		t.Run(test.name, func(t *testing.T) {
			value, err := unmarshalStructuredField(input, func(values []string) (T, error) {
				if !reflect.DeepEqual(values, []string{`"0000, "`}) {
					t.Fatalf("normalized values = %q", values)
				}
				return want, test.err
			})
			if !reflect.DeepEqual(value, want) || err != test.err {
				t.Fatalf("ordinary result = %#v, %v; want %#v, %v", value, err, want, test.err)
			}
		})
	}
	t.Run("panic", func(t *testing.T) {
		value, err := unmarshalStructuredField(input, func([]string) (T, error) {
			panic("private supplier fault")
		})
		var zero T
		if !reflect.DeepEqual(value, zero) || err != errStructuredFieldParse {
			t.Fatalf("panic result = %#v, %v; want zero result and parse failure", value, err)
		}
		if strings.Contains(err.Error(), "private supplier fault") {
			t.Fatal("panic payload escaped in returned error")
		}
	})
}

func TestStructuredFieldFailureDoesNotReturnPartialSignatureBase(t *testing.T) {
	t.Parallel()
	const malformed = `%"00000000000000"0000`
	for _, test := range []struct {
		name, component, valid, invalid, canonical string
		kind                                       StructuredFieldType
	}{
		{"dictionary", `"x-structured";sf`, "a=1", "a=" + malformed, "a=1", StructuredFieldDictionary},
		{"list", `"x-structured";sf`, "token;flag", "a, " + malformed, "token;flag", StructuredFieldList},
		{"item", `"x-structured";sf`, `"value";flag`, "a;x=" + malformed, `"value";flag`, StructuredFieldItem},
		{"key", `"x-structured";key="a"`, "a=1", "a=" + malformed, "1", StructuredFieldDictionary},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			inputs, err := ParseSignatureInputs([]string{`sig=("@method" ` + test.component + `)`})
			if err != nil {
				t.Fatal(err)
			}
			context := MessageContext{Request: request, StructuredFields: map[string]StructuredFieldType{"x-structured": test.kind}}
			request.Header.Set("X-Structured", test.valid)
			base, err := CreateSignatureBase(context, inputs.Entries()[0])
			want := `"@method": GET` + "\n" + test.component + ": " + test.canonical + "\n" +
				`"@signature-params": ("@method" ` + test.component + `)`
			if err != nil || base != want {
				t.Fatalf("valid base = %q, %v; want %q", base, err, want)
			}
			request.Header.Set("X-Structured", test.invalid)
			base, err = CreateSignatureBase(context, inputs.Entries()[0])
			if base != "" || !errors.Is(err, ErrSignatureBase) {
				t.Fatalf("invalid base = %q, %v; want empty base and ErrSignatureBase", base, err)
			}
		})
	}
}
