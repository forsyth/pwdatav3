package pwdatav3

import (
	"bytes"
	_ "fmt"
	"testing"
)

type testuser struct {
	name string
	b64  string
	pw   string
	err1 string
}

var testusers = []testuser{
	{
		"josephine@example.com",
		"AQAAAAEAACcQAAAAEO4k5r1SgFuCYAS8xfu/Mnu5iZUqh+DgSRU4IyJpD+mVo4KdbI1BwiF3KcY1V6AapQ==",
		"In2Egypt!",
		"password encoding: illegal base64 data at input byte 84",
	},
	{
		"jake@example.com",
		"AQAAAAEAACcQAAAAEHhGT2mW9BMcWhMNA4lNj80h8OULQyuvqbSR99lZ+GWsuhA2H6HLxcZI8+RhtxV5FA==",
		"REdNuIlsAnyejH3",
		"password encoding: illegal base64 data at input byte 84",
	},
}

type testhash struct {
	hash []byte
	err  error
}

var hashes = []testhash{
	{[]byte{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, ErrCorrupt},
	{[]byte{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, ErrVersion},
	{[]byte{v3, 0, 0, 0, 0, 4, 5, 6, 7, 8, 9, 10, 11}, ErrFunction},
	{[]byte{v3, 0, 0, 0, byte(prfSHA256), 4, 5, 6, 7, 8, 9, 10, 11}, ErrParameter},
	{[]byte{v3, 0, 0, 0, byte(prfSHA256), 0, 0, 0, 0, 8, 9, 10, 11}, ErrParameter},
	{[]byte{v3, 0, 0, 0, byte(prfSHA256), 0, 0, 0, 1, 8, 9, 10, 11}, ErrParameter},
	{[]byte{v3, 0, 0, 0, byte(prfSHA256), 0, 0, 0, 1, 0, 0, 0, 1}, ErrCorrupt},
	{[]byte{v3, 0, 0, 0, byte(prfSHA256), 0, 0, 0, 1, 0, 0, 0, 1, 0xEE}, ErrCorrupt},
	{append([]byte{v3, 0, 0, 0, byte(prfSHA256), 0, 0, 0, 1, 0, 0, 0, 1, 0xEE}, hashPW("hello", []byte{0xEE}, 1)...), nil},
}

func toBase64(pwd *PWHash) (string, error) {
	a, err := pwd.MarshalText()
	if err != nil {
		return "", err
	}
	return string(a), nil
}

func fromBase64(s string) (*PWHash, error) {
	var pwd PWHash
	err := pwd.UnmarshalText([]byte(s))
	if err != nil {
		return nil, err
	}
	return &pwd, nil
}

func TestPWHash(t *testing.T) {
	t.Run("Verify", func(t *testing.T) {
		for _, user := range testusers {
			pwd, err := fromBase64(user.b64)
			if err != nil {
				t.Errorf("%s: error decoding [%s]; got %v", user.name, user.b64, err)
				continue
			}
			s, err := toBase64(pwd)
			if err != nil {
				t.Errorf("%s: error converting to base64; got %v", user.name, err)
				continue
			}
			if s != user.b64 {
				t.Errorf("%s: repacked base64 encoding differs: want %v got %v", user.name, user.b64, s)
			}
			if ok := pwd.Verify(user.pw); !ok {
				t.Errorf("%s: failed to verify correct password %q against stored hash", user.name, user.pw)
			}
			if ok := pwd.Verify(user.pw + "?"); ok {
				t.Errorf("%s: wrong password still verified", user.name)
			}
			if ok := pwd.Verify(""); ok {
				t.Errorf("%s: empty password still verified", user.name)
			}
			pwd, err = fromBase64(user.b64 + "??")
			if err == nil {
				t.Errorf("%s: invalid hash accepted without error; want %s", user.name, user.err1)
			} else if err.Error() != user.err1 {
				t.Errorf("%s: invalid hash detected but different error: want %s; got %v", user.name, user.err1, err.Error())
			}
			n, err := New(user.pw, DefaultIter)
			if err != nil {
				t.Errorf("%s: new from password: want no error; got %v", user.name, err)
			}
			s, _ = toBase64(n)
			if user.b64 == s {
				t.Errorf("%s: implausibly got same b64 with new salt", user.name)
			}
		}
	})
	t.Run("hashPW", func(t *testing.T) {
		for _, user := range testusers {
			pwd, err := fromBase64(user.b64)
			if err != nil {
				t.Errorf("%s: error decoding; got %v", user.name, err)
			}
			dk := hashPW(user.pw, pwd.salt, int(pwd.iter))
			if !bytes.Equal(dk, pwd.hash) {
				t.Errorf("%s: hashed value not equal; want %#v got %#v", user.name, pwd.hash, dk)
			}
			//fmt.Printf("%s: %#v\n", user.name, dk)
			dk = hashPW(user.pw+"X", pwd.salt, int(pwd.iter))
			if bytes.Equal(dk, pwd.hash) {
				t.Errorf("%s: hashed values unexpectedly equal", user.name)
			}
		}
	})
	t.Run("UnmarshalBinary", func(t *testing.T) {
		for i, h := range hashes {
			var pwd PWHash
			err := pwd.UnmarshalBinary(h.hash)
			if err != h.err {
				t.Errorf("hash test %d: want error %v; got %v", i, h.err, err)
			}
		}
	})
	t.Run("GenerateFromPassword", func(t *testing.T) {
		for _, user := range testusers {
			pw := []byte(user.pw) // bad planning
			for iter := DefaultIter; iter > 0; iter /= 10 {
				hashed, err := GenerateFromPassword(pw, DefaultIter)
				if err != nil {
					t.Errorf("GenerateFromPassword: user %q pw %q: got error %v", user.name, user.pw, err)
					continue
				}
				if err = CompareHashAndPassword(hashed, pw); err != nil {
					t.Errorf("hash and password mismatch: user %q pw %q: got error %v", user.name, user.pw, err)
					continue
				}
				if err = CompareHashAndPassword(hashed, []byte(user.pw+"zonk")); err == nil {
					t.Errorf("hash and wrong password matched: user %q", user.name)
				}
			}
		}
	})
}
