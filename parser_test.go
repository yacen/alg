package alg

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

var keyFuncError error = fmt.Errorf("error loading key")

var (
	jwtTestDefaultKey *rsa.PublicKey
	defaultKeyFunc    Keyfunc = func(t *Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	emptyKeyFunc      Keyfunc = func(t *Token) (interface{}, error) { return nil, nil }
	errorKeyFunc      Keyfunc = func(t *Token) (interface{}, error) { return nil, keyFuncError }
	nilKeyFunc        Keyfunc = nil
)

func init() {
	jwtTestDefaultKey = LoadRSAPublicKeyFromDisk("test/sample_key.pub")
}

var jwtTestData = []struct {
	name        string
	tokenString string
	keyfunc     Keyfunc
	claims      Claims
	valid       bool
	errors      uint32
	parser      *Parser
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		true,
		0,
		nil,
	},
	{
		"basic expired",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		ValidationErrorExpired,
		nil,
	},
	{
		"basic nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		ValidationErrorNotValidYet,
		nil,
	},
	{
		"expired and nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		false,
		ValidationErrorNotValidYet | ValidationErrorExpired,
		nil,
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic nokeyfunc",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nilKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorUnverifiable,
		nil,
	},
	{
		"basic nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		emptyKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic errorkey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		errorKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorUnverifiable,
		nil,
	},
	{
		"invalid signing method",
		"",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorSignatureInvalid,
		&Parser{ValidMethods: []string{"HS256"}},
	},
	{
		"valid signing method",
		"",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		true,
		0,
		&Parser{ValidMethods: []string{"RS256", "HS256"}},
	},
	{
		"JSON Number",
		"",
		defaultKeyFunc,
		MapClaims{"foo": json.Number("123.4")},
		true,
		0,
		&Parser{UseJSONNumber: true},
	},
	{
		"Standard Claims",
		"",
		defaultKeyFunc,
		&StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * 10).Unix(),
		},
		true,
		0,
		&Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - basic expired",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		ValidationErrorExpired,
		&Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - basic nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		false,
		ValidationErrorNotValidYet,
		&Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - expired and nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		ValidationErrorNotValidYet | ValidationErrorExpired,
		&Parser{UseJSONNumber: true},
	},
	{
		"SkipClaimsValidation during token parsing",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		true,
		0,
		&Parser{UseJSONNumber: true, SkipClaimsValidation: true},
	},
}

func TestParser_Parse(t *testing.T) {
	privateKey := LoadRSAPrivateKeyFromDisk("test/sample_key")

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = MakeSampleToken(data.claims, privateKey)
		}

		// Parse the token
		var token *Token
		var err error
		var parser = data.parser
		if parser == nil {
			parser = new(Parser)
		}
		// Figure out correct claims type
		switch data.claims.(type) {
		case MapClaims:
			token, err = parser.ParseWithClaims(data.tokenString, MapClaims{}, data.keyfunc)
		case *StandardClaims:
			token, err = parser.ParseWithClaims(data.tokenString, &StandardClaims{}, data.keyfunc)
		}

		// Verify result matches expectation
		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}

		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
		}

		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid token passed validation", data.name)
		}

		if (err == nil && !token.Valid) || (err != nil && token.Valid) {
			t.Errorf("[%v] Inconsistent behavior between returned error and token.Valid", data.name)
		}

		if data.errors != 0 {
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
			} else {

				ve := err.(*ValidationError)
				// compare the bitfield part of the error
				if e := ve.Errors; e != data.errors {
					t.Errorf("[%v] Errors don't match expectation.  %v != %v", data.name, e, data.errors)
				}

				if err.Error() == keyFuncError.Error() && ve.Inner != keyFuncError {
					t.Errorf("[%v] Inner error does not match expectation.  %v != %v", data.name, ve.Inner, keyFuncError)
				}
			}
		}
		if data.valid && token.Signature == "" {
			t.Errorf("[%v] Signature is left unpopulated after parsing", data.name)
		}
	}
}

func TestParser_ParseUnverified(t *testing.T) {
	privateKey := LoadRSAPrivateKeyFromDisk("test/sample_key")

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = MakeSampleToken(data.claims, privateKey)
		}

		// Parse the token
		var token *Token
		var err error
		var parser = data.parser
		if parser == nil {
			parser = new(Parser)
		}
		// Figure out correct claims type
		switch data.claims.(type) {
		case MapClaims:
			token, _, err = parser.ParseUnverified(data.tokenString, MapClaims{})
		case *StandardClaims:
			token, _, err = parser.ParseUnverified(data.tokenString, &StandardClaims{})
		}

		if err != nil {
			t.Errorf("[%v] Invalid token", data.name)
		}

		// Verify result matches expectation
		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}

		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
		}
	}
}

// Helper method for benchmarking various methods
func benchmarkSigning(b *testing.B, method SigningMethod, key interface{}) {
	t := New(method)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := t.SignedString(key); err != nil {
				b.Fatal(err)
			}
		}
	})

}
