package gcp

import (
	"context"
	"fmt"
	"os"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// KMSClient wraps the Google KMS client and the resource name (KEK).
type KMSClient struct {
	name   string
	client *kms.KeyManagementClient
}

func NewKMS(ctx context.Context) (*KMSClient, error) {
	keyName := os.Getenv("KMS_KEY_NAME")
	if keyName == "" {
		return nil, fmt.Errorf("KMS_KEY_NAME env not set")
	}
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	return &KMSClient{
		name:   keyName,
		client: c,
	}, nil
}

func (k *KMSClient) WrapDEK(ctx context.Context, dek []byte) ([]byte, error) {
	if k == nil || k.client == nil {
		return nil, fmt.Errorf("kms client not initialized")
	}
	if k.name == "" {
		return nil, fmt.Errorf("kms key name empty")
	}
	req := &kmspb.EncryptRequest{
		Name:      k.name,
		Plaintext: dek,
	}
	resp, err := k.client.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (k *KMSClient) UnwrapDEK(ctx context.Context, wrapped []byte) ([]byte, error) {
	if k == nil || k.client == nil {
		return nil, fmt.Errorf("kms client not initialized")
	}
	if k.name == "" {
		return nil, fmt.Errorf("kms key name empty")
	}
	req := &kmspb.DecryptRequest{
		Name:       k.name,
		Ciphertext: wrapped,
	}
	resp, err := k.client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (k *KMSClient) Close() error {
	if k == nil || k.client == nil {
		return nil
	}
	return k.client.Close()
}
