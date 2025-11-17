package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keshav78-78/secure-cloud-box/internal/gcp"
	"github.com/keshav78-78/secure-cloud-box/internal/store"
)

var jwtSecret = []byte(env("JWT_SECRET", "change-me"))

func issueToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(12 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		parts := strings.SplitN(h, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "missing bearer", 401)
			return
		}
		tkn, err := jwt.Parse(parts[1], func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("alg")
			}
			return jwtSecret, nil
		})
		if err != nil || !tkn.Valid {
			http.Error(w, "invalid token", 401)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// login endpoint - very small demo using env test creds
func login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// demo creds from env (set DEMO_USER & DEMO_PASS)
	demoUser := env("DEMO_USER", "keshav")
	demoPass := env("DEMO_PASS", "pass123")

	if body.User != demoUser || body.Pass != demoPass {
		http.Error(w, "bad creds", http.StatusUnauthorized)
		return
	}

	tok, err := issueToken(body.User)
	if err != nil {
		http.Error(w, "could not issue token", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

type Server struct {
	signer *gcp.Signer
	kms    *gcp.KMSClient
	db     *store.DB
	bucket string
}

func main() {
	ctx := context.Background()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	bucket := os.Getenv("GCS_BUCKET")
	if bucket == "" {
		log.Fatal("GCS_BUCKET not set")
	}

	signer, err := gcp.NewSignerFromCred(ctx, os.Getenv("SA_EMAIL"))
	if err != nil {
		log.Fatalf("signer: %v", err)
	}

	var kmsClient *gcp.KMSClient
	if os.Getenv("KMS_KEY_NAME") != "" {
		kmsClient, err = gcp.NewKMS(ctx)
		if err != nil {
			log.Fatalf("kms: %v", err)
		}
	}

	db, err := store.Open(env("DB_PATH", "securebox.db"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}

	s := &Server{signer: signer, kms: kmsClient, db: db, bucket: bucket}
	http.HandleFunc("/v1/login", login)

	// protected (require Authorization: Bearer <token>)
	http.HandleFunc("/v1/sign-upload", authMiddleware(s.signUpload))
	http.HandleFunc("/v1/sign-download", authMiddleware(s.signDownload))
	http.HandleFunc("/v1/save-meta", authMiddleware(s.saveMeta))
	http.HandleFunc("/v1/list", authMiddleware(s.list))
	http.HandleFunc("/v1/wrap-dek", authMiddleware(s.wrapDEK))
	http.HandleFunc("/v1/unwrap-dek", authMiddleware(s.unwrapDEK))
	http.HandleFunc("/v1/get-meta", authMiddleware(s.getMeta))

	log.Printf("server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (s *Server) signUpload(w http.ResponseWriter, r *http.Request) {
	obj := r.URL.Query().Get("name")
	if obj == "" {
		http.Error(w, "name required", 400)
		return
	}
	ttl := parseTTL(r.URL.Query().Get("ttl"), 15*time.Minute)
	url, err := s.signer.SignedPutURL(s.bucket, obj, ttl)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"url": url})
}

func (s *Server) signDownload(w http.ResponseWriter, r *http.Request) {
	obj := r.URL.Query().Get("name")
	if obj == "" {
		http.Error(w, "name required", 400)
		return
	}
	ttl := parseTTL(r.URL.Query().Get("ttl"), 15*time.Minute)
	url, err := s.signer.SignedGetURL(s.bucket, obj, ttl)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"url": url})
}

func (s *Server) wrapDEK(w http.ResponseWriter, r *http.Request) {
	if s.kms == nil {
		http.Error(w, "KMS not configured", 400)
		return
	}
	var body struct {
		DEKBase64 string `json:"dek_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	dek, err := base64.StdEncoding.DecodeString(body.DEKBase64)
	if err != nil {
		http.Error(w, "bad base64", 400)
		return
	}
	ct, err := s.kms.WrapDEK(r.Context(), dek)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"wrapped_b64": base64.StdEncoding.EncodeToString(ct)})
}

func (s *Server) unwrapDEK(w http.ResponseWriter, r *http.Request) {
	if s.kms == nil {
		http.Error(w, "KMS not configured", 400)
		return
	}
	var body struct {
		WrappedBase64 string `json:"wrapped_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	wrapped, err := base64.StdEncoding.DecodeString(body.WrappedBase64)
	if err != nil {
		http.Error(w, "bad base64", 400)
		return
	}
	pt, err := s.kms.UnwrapDEK(r.Context(), wrapped)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"dek_b64": base64.StdEncoding.EncodeToString(pt)})
}

func (s *Server) getMeta(w http.ResponseWriter, r *http.Request) {
	obj := r.URL.Query().Get("name")
	if obj == "" {
		http.Error(w, "name required", 400)
		return
	}
	rec, err := s.db.Get(obj)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "not found", 404)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	resp := map[string]any{
		"object_name":  rec.ObjectName,
		"wrapped_b64":  base64.StdEncoding.EncodeToString(rec.WrappedDEK),
		"nonce_b64":    base64.StdEncoding.EncodeToString(rec.Nonce),
		"orig_name":    rec.OrigName,
		"content_type": rec.ContentType,
		"size":         rec.Size,
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) saveMeta(w http.ResponseWriter, r *http.Request) {
	var m struct {
		ObjectName  string `json:"object_name"`
		WrappedB64  string `json:"wrapped_b64"`
		NonceB64    string `json:"nonce_b64"`
		OrigName    string `json:"orig_name"`
		ContentType string `json:"content_type"`
		Size        int64  `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	wrapped, err := base64.StdEncoding.DecodeString(m.WrappedB64)
	if err != nil {
		http.Error(w, "bad wrapped_b64", 400)
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(m.NonceB64)
	if err != nil {
		http.Error(w, "bad nonce_b64", 400)
		return
	}

	if err := s.db.Insert(store.FileMeta{
		ObjectName:  m.ObjectName,
		WrappedDEK:  wrapped,
		Nonce:       nonce,
		OrigName:    m.OrigName,
		ContentType: m.ContentType,
		Size:        m.Size,
	}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)

}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	items, err := s.db.List()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(items)
}

func parseTTL(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	if v, err := strconv.Atoi(s); err == nil {
		return time.Duration(v) * time.Minute
	}
	return def
}
