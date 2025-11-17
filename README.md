🔐 Secure-Cloud-Box  
End-to-End Encrypted Cloud Storage System using AES-256-GCM + Google Cloud KMS

Secure-Cloud-Box is a fully functional secure file storage system that encrypts files locally, uploads encrypted blobs to Google Cloud Storage (GCS), and protects encryption keys using Google Cloud Key Management Service (KMS).

It includes:

- ✔ Secure backend server (Go)
- ✔ Interactive CLI/TUI client (BubbleTea)
- ✔ SQLite metadata store
- ✔ Auto JWT authentication
- ✔ AES-256-GCM encryption with AAD binding
- ✔ Google KMS-based key wrapping

---

## 🧠 How it Works

```
          ┌───────────┐
          │   Client  │
          │ (TUI/CLI) │
          └─────┬─────┘
                │
   Generate AES-256 DEK
                │
        Encrypt File Locally
                │
     ┌────────────────────────────┐
     │ Send DEK → Google KMS Wrap│
     └────────────────────────────┘
                │
      Upload Ciphertext to GCS
                │
    Store Metadata in SQLite
```

---

## 🔐 Security Design

| Component      | Technology |
|----------------|------------|
| Encryption     | AES-256-GCM |
| Key Protection | Google Cloud KMS |
| Integrity      | GCM Tag Authentication |
| Identity       | JWT (12-hour token) |
| Storage        | Google Cloud Storage |
| Metadata       | SQLite |

Even Google cannot decrypt your files without:
1️⃣ The wrapped DEK  
2️⃣ Your KMS key  
3️⃣ Correct AAD (object name)

---

## 🏗 Project Structure

```
Secure-Cloud-Box
 ├── cmd/
 │   ├── securebox-server   -> Backend API
 │   ├── securebox-client   -> Minimal client
 │   └── securebox-tui      -> BubbleTea UI
 ├── internal/
 │   ├── crypto             -> AES-GCM helpers
 │   ├── gcp                -> KMS & Signed URLs
 │   ├── store              -> SQLite DB
 │   └── ui                 -> FZF file picker
 ├── decrypt-files/         -> Decrypted output
 ├── makefile
 ├── go.mod
 ├── README.md
```

---

🚀 Quick Start

1️⃣ Configure Environment

export Your Credentials and Requirements

Windows:

```
setx GCS_BUCKET GCP-STORAGE NAME
```

---

2️⃣ Run Backend

```
make server
```

Runs at:

```
http://localhost:8080
```

---

3️⃣ Run Secure CLI UI

```
make tui
```

Upload / Download securely.

---

🧪 Demo Commands (For Professors)

Show encrypted files in cloud

```
gsutil ls gs://"GCP-STORAGE/user1/
```

Download encrypted blob

```
gsutil cp gs://"GCP-STORAGE/user1/FILE.enc .
```

Show that it is unreadable

```
type FILE.enc
```

Show stored metadata

```
curl http://localhost:8080/v1/get-meta?name=user1/FILE.enc
```

---

🧮 Encryption Strength (Real Numbers)

AES-256 has:

```
2^256 = 1.15 × 10^77 possible keys
```

Even if a **supercomputer** checks  
**1 trillion keys / second**, it still needs:

> 6.7 × 10⁵⁵ years  
> ≈ 670,000,000,000,000,000,000,000,000,000,000 YEARS

➡️ Brute-force is mathematically impossible

---

📡 API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/v1/login` | Generate JWT |
| GET | `/v1/sign-upload` | Get Signed PUT URL |
| GET | `/v1/sign-download` | Get Signed GET URL |
| POST | `/v1/wrap-dek` | KMS Wrap DEK |
| POST | `/v1/unwrap-dek` | KMS Unwrap DEK |
| POST | `/v1/save-meta` | Save metadata |
| GET | `/v1/get-meta` | Read metadata |
| GET | `/v1/list` | List stored files |

---

🦾 Production-Grade Features

- 🔒 End-to-end Zero-Trust design
- 🧠 Encryption happens **before upload**
- 🗄 No plaintext ever reaches server or cloud
- 📦 SQLite metadata mapping
- 🧰 Modular Go code, ready for extension
- ☁ GCS today → S3 / Azure Blob tomorrow

---
🧱 Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Go 1.21 |
| UI | BubbleTea |
| Cloud | Google Cloud Storage |
| Key Mgmt | Google Cloud KMS |
| DB | SQLite |
| Crypto | AES-256-GCM |
| Auth | JWT |

---

👨‍💻 Author

Keshav Kapoor 

LICENCE

MIT License – Free to modify & use.
