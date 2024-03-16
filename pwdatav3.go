// Package pwdatav3 implements password handling compatible with Microsoft's ASP.NET Core, including
// equality of the hashed salted passwords.
// It is useful when switching from C# to Go for the server side of an application,
// avoiding the need to reset passwords when switching.
//
// To allow implementation of different databases but with ASP.NET compatible encryption,
// the package exports the low-level PWDataV3 type, with a set of operations to hash and verify passwords.
package pwdatav3

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

var (
	// errors returned for a corrupt base64 representation.
	ErrCorrupt   = errors.New("malformed hashed value")
	ErrVersion   = errors.New("unknown hashed format version")
	ErrFunction  = errors.New("unknown hash function")
	ErrParameter = errors.New("invalid hash function parameter")
)

// PWDataV3 represents Version 3 of
// PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
// Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
// (All UInt32s are stored big-endian.)
type PWDataV3 struct {
	ver  uint8  // 0x01
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

// New returns a PWDataV3 value for the given salt, iterations and hash.
func New(salt []byte, iter int, hash []byte) *PWDataV3 {
	saltc := make([]byte, len(salt))
	copy(saltc, salt)
	hashc := make([]byte, len(hash))
	copy(hashc, hash)
	return &PWDataV3{
		ver:  v3,
		prf:  prfSHA256,
		iter: uint32(iter),
		salt: saltc,
		hash: hashc,
	}
}

// NewFromPassword returns a PWDataV3 value for the given password and iterations (DefaultIter is a compatible choice),
// using a salt of DefaultSaltLen. It returns nil and an error if it cannot make a random salt.
func NewFromPassword(pw string, iter int) (*PWDataV3, error) {
	salt := make([]byte, DefaultSaltLen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, fmt.Errorf("cannot make salt value: %v", err)
	}
	dk := hashPW(pw, salt, iter)
	o := &PWDataV3{
		ver:  v3,
		prf:  prfSHA256,
		iter: uint32(iter),
		salt: salt,
		hash: dk,
	}
	return o, nil
}

// Must insists that NewFromPassword did not fail, by panicking if it does.
// Failure implies a problem with (access to) cryptographic random numbers.
func Must(pw *PWDataV3, err error) *PWDataV3 {
	if err != nil {
		panic(err)
	}
	return pw
}

// VerifyPassword returns true iff the given plaintext password corresponds to the
// version hashed in d.
func (d *PWDataV3) VerifyPassword(pw string) bool {
	dk := hashPW(pw, d.salt, int(d.iter))
	return subtle.ConstantTimeCompare(d.hash, dk) == 1
}

// VerifyHash returns true iff the plaintext password pw corresponds to the version
// hashed and encoded (in base 64) in hash. If the base 64 encoding is wrong or corrupt,
// VerifyHash returns false and the error describes the internal error,
// but VerifyHash wastes time so it's less obvious to an observer.
func VerifyHash(hash, pw string) (bool, error) {
	d, err := fromBase64(hash)
	if err != nil {
		d = Must(NewFromPassword("", DefaultIter))
		return subtle.ConstantTimeCompare(d.hash, d.hash) != 1, err // ie, false
	}
	dk := hashPW(pw, d.salt, int(d.iter))
	return subtle.ConstantTimeCompare(d.hash, dk) == 1, nil
}

// String returns the base 64 encoding used in the database, for Stringer.
func (d *PWDataV3) String() string {
	return d.toBase64()
}

// hashPW applies the underlying key transformation to a plaintext password.
// The other parameter values are typically extracted from an encoded PWDataV3 in
// an authentication database or supplied when that value was created.
func hashPW(password string, salt []byte, iter int) []byte {
	return pbkdf2.Key([]byte(password), salt, iter, sha256.Size, sha256.New)
}

func fromBase64(s string) (*PWDataV3, error) {
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("pw data: %v", err)
	}
	pwd := &PWDataV3{}
	err = pwd.unpack(out)
	if err != nil {
		return nil, err
	}
	return pwd, nil
}

func (d *PWDataV3) toBase64() string {
	return base64.StdEncoding.EncodeToString(d.pack())
}

const hdrLength = 1 + 3*4

func (d *PWDataV3) unpack(a []byte) error {
	if len(a) < hdrLength {
		return ErrCorrupt
	}
	d.ver = a[0]
	if d.ver != v3 {
		return ErrVersion
	}
	d.prf = binary.BigEndian.Uint32(a[1:])
	if d.prf != prfSHA256 {
		return ErrFunction
	}
	d.iter = binary.BigEndian.Uint32(a[1+4:])
	if d.iter > 100000 {
		return ErrParameter
	}
	saltlen := binary.BigEndian.Uint32(a[1+4+4:])
	if saltlen > 64 {
		return ErrParameter
	}
	if hdrLength+saltlen >= uint32(len(a)) {
		return ErrCorrupt
	}
	d.salt = a[hdrLength : hdrLength+saltlen]
	d.hash = a[hdrLength+saltlen:]
	return nil
}

func (d *PWDataV3) pack() []byte {
	out := make([]byte, hdrLength+len(d.salt)+len(d.hash))
	out[0] = d.ver
	binary.BigEndian.PutUint32(out[1:], d.prf)
	binary.BigEndian.PutUint32(out[1+4:], d.iter)
	binary.BigEndian.PutUint32(out[1+4+4:], uint32(len(d.salt)))
	copy(out[hdrLength:], d.salt)
	copy(out[hdrLength+len(d.salt):], d.hash)
	return out
}
