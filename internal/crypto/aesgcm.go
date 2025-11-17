package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	DEKSize      = 32
	NonceSizeGCM = 12
)

// GenerateDEK creates a new random 256-bit data encryption key.
func GenerateDEK() ([]byte, error) {
	k := make([]byte, DEKSize)
	_, err := rand.Read(k)
	return k, err
}

// EncryptAESGCM encrypts plaintext with AES-GCM using DEK and optional AAD.
// AAD (Associated Authenticated Data) binds metadata (like filename/object-name)

func EncryptAESGCM(plain, dek, aad []byte) (nonce, ct []byte, err error) {
	if len(dek) != DEKSize {
		return nil, nil, errors.New("invalid DEK size")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, NonceSizeGCM)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ct = gcm.Seal(nil, nonce, plain, aad)
	return nonce, ct, nil
}

// DecryptAESGCM decrypts ciphertext with AES-GCM using DEK and AAD.
func DecryptAESGCM(nonce, ct, dek, aad []byte) ([]byte, error) {
	if len(dek) != DEKSize {
		return nil, errors.New("invalid DEK size")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSizeGCM {
		return nil, errors.New("invalid nonce size")
	}
	return gcm.Open(nil, nonce, ct, aad)
}
