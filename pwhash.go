// Package pwdatav3 implements password hashing and verification compatible with Microsoft's ASP.NET Core, including
// equality of the hashed salted passwords.
// It is useful when switching from C# to Go for the server side of an application,
// avoiding the need to reset passwords when switching.
//
// The type [PWHash] provides compatible hashing and verify functions.
package pwdatav3

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

var (
	// errors returned for a corrupt base64 representation.
	ErrCorrupt   = errors.New("malformed hashed value")
	ErrVersion   = errors.New("unknown hashed format version")
	ErrFunction  = errors.New("unknown hash function")
	ErrParameter = errors.New("invalid hash function parameter")
)

// PWHash represents a hashed value (version 3 for ASP.NET) using
// PBKDF2 with HMAC-SHA256, and by default, 128-bit salt, 256-bit hash and 10000 iterations.
type PWHash struct {
	ver  uint8  // 0x01 => v3 (!)
	prf  uint32 // 1 => sha256
	iter uint32
	salt []byte
	hash []byte
}

const (
	v3        = 1
	prfSHA256 = 1

	// Default hash iterations used by ASP.NET.
	DefaultIter = 10000

	// Default salt length used by ASP.NET.
	DefaultSaltLen = 16
)

// New returns a hashed value for the given password and iterations (DefaultIter is an ASP.NET-compatible choice),
// using a random salt that is DefaultSaltLen bytes long. It returns nil and an error only if it cannot make a random salt,
// which suggests trouble with the underlying random number source.
func New(pw string, iter int) (*PWHash, error) {
	salt := make([]byte, DefaultSaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("cannot make salt value: %v", err)
	}
	pd := &PWHash{
		ver:  v3,
		prf:  prfSHA256,
		iter: uint32(iter),
		salt: salt,
		hash: hashPW(pw, salt, iter),
	}
	return pd, nil
}

// Verify returns true iff the given plaintext password corresponds to the
// value hashed in pd.
func (pd *PWHash) Verify(pw string) bool {
	dk := hashPW(pw, pd.salt, int(pd.iter))
	return subtle.ConstantTimeCompare(pd.hash, dk) == 1
}

// hashPW applies the underlying key transformation to a plaintext password.
// The other parameter values are typically extracted from an encoded PWHash in
// an authentication database or supplied when that value was created.
func hashPW(password string, salt []byte, iter int) []byte {
	return pbkdf2.Key([]byte(password), salt, iter, sha256.Size, sha256.New)
}

// String returns the Base64 encoding.
func (pd *PWHash) String() string {
	a, _ := pd.MarshalText()	// no error return, see below
	return string(a)
}

// UnmarshalText unmarshals a hashed value decoded from text, typically the value stored in a user table record.
func (pd *PWHash) UnmarshalText(text []byte) error {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	n, err := base64.StdEncoding.Decode(out, text)
	if err != nil {
		return fmt.Errorf("password encoding: %v", err)
	}
	return pd.UnmarshalBinary(out[:n])
}

// MarshalText returns the hashed value encoded as required for ASP.NET's user table.
// No error can result.
func (pd *PWHash) MarshalText() ([]byte, error) {
	p, _ := pd.MarshalBinary()
	out := make([]byte, base64.StdEncoding.EncodedLen(len(p)))
	base64.StdEncoding.Encode(out, p)
	return out, nil
}

const hdrLength = 1 + 3*4 // byte and 3 ints

// MarshalBinary returns a binary representation of a hashed value that is identical to ASP.NET's:
//
//	ver[1]=0x01, prf[4]=0x01, iter[4], saltLen[4], salt[n], hashed[sha256.Size]
//
// (All 32-bit ints are stored big-endian.)
// No error can result.
func (pd *PWHash) MarshalBinary() ([]byte, error) {
	out := make([]byte, hdrLength+len(pd.salt)+len(pd.hash))
	out[0] = pd.ver
	binary.BigEndian.PutUint32(out[1:], pd.prf)
	binary.BigEndian.PutUint32(out[1+4:], pd.iter)
	binary.BigEndian.PutUint32(out[1+4+4:], uint32(len(pd.salt)))
	copy(out[hdrLength:], pd.salt)
	copy(out[hdrLength+len(pd.salt):], pd.hash)
	return out, nil
}

// UnmarshalBinary extracts the components from a packed value.
// Various errors can be returned if the format is wrong or uses unsupported parameters.
// The pd value is unchanged on error.
func (pd *PWHash) UnmarshalBinary(a []byte) error {
	// check values before assigning anything to pd
	if len(a) < hdrLength {
		return ErrCorrupt
	}
	ver := a[0]
	if ver != v3 {
		return ErrVersion
	}
	prf := binary.BigEndian.Uint32(a[1:])
	if prf != prfSHA256 {
		return ErrFunction
	}
	iter := binary.BigEndian.Uint32(a[1+4:])
	if iter < 1 || iter > 100000 {
		return ErrParameter
	}
	saltlen := binary.BigEndian.Uint32(a[1+4+4:])
	if saltlen < 1 || saltlen > 64 {
		return ErrParameter
	}
	if hdrLength+saltlen+sha256.Size != uint32(len(a)) {
		return ErrCorrupt
	}
	pd.ver = ver
	pd.prf = prf
	pd.iter = iter
	pd.salt = bytes.Clone(a[hdrLength : hdrLength+saltlen])
	pd.hash = bytes.Clone(a[hdrLength+saltlen:])
	return nil
}
