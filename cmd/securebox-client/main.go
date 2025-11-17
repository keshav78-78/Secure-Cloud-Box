package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/keshav78-78/secure-cloud-box/internal/crypto"
)

var server = env("SERVER_URL", "http://localhost:8080")

func main() {
	up := flag.NewFlagSet("upload", flag.ExitOnError)
	down := flag.NewFlagSet("download", flag.ExitOnError)

	var upFile, upObject string
	up.StringVar(&upFile, "file", "", "path to file")
	up.StringVar(&upObject, "object", "", "gcs object name")

	var downObject, outFile string
	down.StringVar(&downObject, "object", "", "gcs object name")
	down.StringVar(&outFile, "out", "", "output file path")

	if len(os.Args) < 2 {
		fmt.Println("usage: securebox-client [upload|download] ...")
		return
	}
	switch os.Args[1] {
	case "upload":
		up.Parse(os.Args[2:])
		if upFile == "" || upObject == "" {
			fmt.Println("need -file and -object")
			return
		}
		if err := doUpload(upFile, upObject); err != nil {
			fmt.Println("err:", err)
		}
	case "download":
		down.Parse(os.Args[2:])
		if downObject == "" || outFile == "" {
			fmt.Println("need -object and -out")
			return
		}
		if err := doDownload(downObject, outFile); err != nil {
			fmt.Println("err:", err)
		}
	default:
		fmt.Println("unknown command")
	}
}

func doUpload(path, object string) error {
	ctx := context.Background()

	plain, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	//  Generate DEK & encrypt
	dek, err := crypto.GenerateDEK()
	if err != nil {
		return err
	}
	nonce, ct, err := crypto.EncryptAESGCM(plain, dek, []byte(object))
	if err != nil {
		return err
	}

	// Wrap DEK via server (KMS)
	wrapResp := struct {
		Wrapped string `json:"wrapped_b64"`
	}{}
	if err := postJSON("/v1/wrap-dek", map[string]string{
		"dek_b64": base64.StdEncoding.EncodeToString(dek),
	}, &wrapResp); err != nil {
		return fmt.Errorf("wrap dek: %w (KMS configured?)", err)
	}

	//  Signed PUT URL
	sign := struct {
		URL string `json:"url"`
	}{}
	if err := getJSON("/v1/sign-upload?name="+object, &sign); err != nil {
		return err
	}

	//  PUT upload
	req, _ := http.NewRequestWithContext(ctx, "PUT", sign.URL, bytes.NewReader(ct))
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("upload failed: %s %s", res.Status, string(b))
	}

	//  Save metadata
	err = postNoResp("/v1/save-meta", map[string]any{
		"object_name":  object,
		"wrapped_b64":  wrapResp.Wrapped,
		"nonce_b64":    base64.StdEncoding.EncodeToString(nonce),
		"orig_name":    filepath.Base(path),
		"content_type": "application/octet-stream",
		"size":         len(ct),
	})
	if err != nil {
		return err
	}

	fmt.Println("✅ Upload done:", object)
	return nil
}

func doDownload(object, outPath string) error {
	// 1) Meta lao
	meta := struct {
		Wrapped string `json:"wrapped_b64"`
		Nonce   string `json:"nonce_b64"`
		Orig    string `json:"orig_name"`
	}{}
	if err := getJSON("/v1/get-meta?name="+object, &meta); err != nil {
		return fmt.Errorf("get meta: %w", err)
	}

	// 2) Signed GET URL
	sign := struct {
		URL string `json:"url"`
	}{}
	if err := getJSON("/v1/sign-download?name="+object, &sign); err != nil {
		return err
	}

	// 3) Download ciphertext
	res, err := http.Get(sign.URL)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("download failed: %s %s", res.Status, string(b))
	}
	ct, _ := io.ReadAll(res.Body)

	// 4) Unwrap DEK via server
	uw := struct {
		DEK string `json:"dek_b64"`
	}{}
	if err := postJSON("/v1/unwrap-dek", map[string]string{
		"wrapped_b64": meta.Wrapped,
	}, &uw); err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}
	dek, _ := base64.StdEncoding.DecodeString(uw.DEK)

	// 5) Decrypt locally
	nonce, _ := base64.StdEncoding.DecodeString(meta.Nonce)
	pt, err := crypto.DecryptAESGCM(nonce, ct, dek, []byte(object))
	if err != nil {
		return err
	}

	// 6) Save output
	if outPath == "" {
		outPath = meta.Orig
	}
	return os.WriteFile(outPath, pt, 0644)
}

func postJSON(path string, body any, out any) error {
	b, _ := json.Marshal(body)
	res, err := http.Post(server+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		x, _ := io.ReadAll(res.Body)
		return fmt.Errorf("status %s: %s", res.Status, x)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func postNoResp(path string, body any) error {
	b, _ := json.Marshal(body)
	res, err := http.Post(server+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		x, _ := io.ReadAll(res.Body)
		return fmt.Errorf("status %s: %s", res.Status, x)
	}
	return nil
}

func getJSON(path string, out any) error {
	res, err := http.Get(server + path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		x, _ := io.ReadAll(res.Body)
		return fmt.Errorf("status %s: %s", res.Status, x)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
