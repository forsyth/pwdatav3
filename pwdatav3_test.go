package pwdatav3

import (
	"bytes"
	"encoding/base64"
	_ "fmt"
	"testing"
)

type testuser struct {
	name string
	b64  string
	pw   string
	err1 string
	err2 string
}

var testusers = []testuser{
	{
		"josephine@example.com",
		"AQAAAAEAACcQAAAAEO4k5r1SgFuCYAS8xfu/Mnu5iZUqh+DgSRU4IyJpD+mVo4KdbI1BwiF3KcY1V6AapQ==",
		"In2Egypt!",
		"pw data: illegal base64 data at input byte 84",
		ErrCorrupt.Error(),
	},
	{
		"jake@example.com",
		"AQAAAAEAACcQAAAAEHhGT2mW9BMcWhMNA4lNj80h8OULQyuvqbSR99lZ+GWsuhA2H6HLxcZI8+RhtxV5FA==",
		"REdNuIlsAnyejH3",
		"pw data: illegal base64 data at input byte 84",
		ErrCorrupt.Error(),
	},
}

func unpack(a []byte, t *testing.T) *PWDataV3 {
	var pwdata PWDataV3
	err := pwdata.unpack(a)
	if err != nil {
		t.Errorf("want nil; got %v", err)
	}
	return &pwdata
}

func frombase64(s string, t *testing.T) []byte {
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Errorf("error decoding [%s]; got %v", s, err)
	}
	return out
}

func TestPWDataV3(t *testing.T) {
	t.Run("VerifyHash", func(t *testing.T) {
		for _, user := range testusers {
			pwdata, err := fromBase64(user.b64)
			if err != nil {
				t.Errorf("%s: error decoding [%s]; got %v", user.name, user.b64, err)
			}
			//fmt.Printf("%s %#v\n", user.name, pwdata)
			s := pwdata.toBase64()
			//fmt.Printf("%#v\n", s)
			if s != user.b64 {
				t.Errorf("%s: repacked base64 encoding differs: want %v got %v", user.name, user.b64, s)
			}
			ok, err := VerifyHash(user.b64, user.pw)
			if !ok {
				if err == nil {
					t.Errorf("%s: failed to verify password against stored hash", user.name)
				} else {
					t.Errorf("%s: failed to unpack hash value: %v", user.name, err)
				}
			}
			ok, err = VerifyHash(user.b64+"????", user.pw)
			if ok {
				t.Errorf("%s: invalid stored hash still verified", user.name)
			} else if err.Error() != user.err1 {
				t.Errorf("%s: invalid hash detected but different error: want %s; got %v", user.name, user.err1, err.Error())
			}
		}
	})
	t.Run("hashPW", func(t *testing.T) {
		for _, user := range testusers {
			pwdata, err := fromBase64(user.b64)
			if err != nil {
				t.Errorf("%s: error decoding; got %v", user.name, err)
			}
			dk := hashPW(user.pw, pwdata.salt, int(pwdata.iter))
			if !bytes.Equal(dk, pwdata.hash) {
				t.Errorf("%s: hashed value not equal; want %#v got %#v", user.name, pwdata.hash, dk)
			}
			//fmt.Printf("%s: %#v\n", user.name, dk)
			dk = hashPW(user.pw+"X", pwdata.salt, int(pwdata.iter))
			if bytes.Equal(dk, pwdata.hash) {
				t.Errorf("%s: hashed values unexpectedly equal", user.name)
			}
			if !pwdata.VerifyPassword(user.pw) {
				t.Errorf("%s: failed to verify correct password %q", user.name, user.pw)
			}
			if pwdata.VerifyPassword(user.pw + "XXX") {
				t.Errorf("%s: verified incorrect passwrod", user.name)
			}
			n, err := NewFromPassword(user.pw, DefaultIter)
			if err != nil {
				t.Errorf("%s: new from password: %v", user.name, err)
			}
			//fmt.Printf("%s: new: %#v", user.name, n)
			if user.b64 == n.toBase64() {
				t.Errorf("%s: implausibly got same b64 with new salt", user.name)
			}
		}
	})
}
