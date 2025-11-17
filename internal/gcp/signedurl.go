package gcp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"time"

	"cloud.google.com/go/storage"
)

type Signer struct {
	Email string
	Key   []byte // exported and used consistently
}

func NewSignerFromCred(ctx context.Context, saEmail string) (*Signer, error) {
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		return nil, errors.New("GOOGLE_APPLICATION_CREDENTIALS not set")
	}

	data, err := ioutil.ReadFile(credPath)
	if err != nil {
		return nil, err
	}

	// Parse JSON and extract privatekey
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	pkVal, ok := m["private_key"]
	if !ok {
		return nil, errors.New("private_key not found in SA JSON")
	}
	pkStr, ok := pkVal.(string)
	if !ok {
		return nil, errors.New("private_key in SA JSON is not a string")
	}

	return &Signer{
		Email: saEmail,
		Key:   []byte(pkStr),
	}, nil
}

func (s *Signer) SignedPutURL(bucket, object string, expiry time.Duration) (string, error) {
	opts := &storage.SignedURLOptions{
		Scheme:         storage.SigningSchemeV4,
		Method:         "PUT",
		GoogleAccessID: s.Email,
		PrivateKey:     parsePEMKey(s.Key),
		Expires:        time.Now().Add(expiry),
		ContentType:    "application/octet-stream",
	}
	return storage.SignedURL(bucket, object, opts)
}

func (s *Signer) SignedGetURL(bucket, object string, expiry time.Duration) (string, error) {
	opts := &storage.SignedURLOptions{
		Scheme:         storage.SigningSchemeV4,
		Method:         "GET",
		GoogleAccessID: s.Email,
		PrivateKey:     parsePEMKey(s.Key),
		Expires:        time.Now().Add(expiry),
	}
	return storage.SignedURL(bucket, object, opts)
}

func parsePEMKey(pemBytes []byte) []byte {

	block, _ := pem.Decode(pemBytes)
	if block != nil && (block.Type == "PRIVATE KEY" || block.Type == "RSA PRIVATE KEY") {

		_, _ = x509.ParsePKCS8PrivateKey(block.Bytes)
		return pemBytes
	}

	return pemBytes
}
