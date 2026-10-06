
# VaultTrace
### Secure Document Sharing with Version Control, Leak Tracing & Tamper-Evident Auditing

Link: 

VaultTrace is a secure document-sharing platform that simulates core cloud object-storage functionality while adding security and accountability features.

It allows users to upload, version, share, trace, and audit sensitive documents while maintaining control over how and for how long they can be accessed.

---

## 🚀 Features

### 🔐 Authentication
- User registration and login
- Bcrypt password hashing
- JWT-based authentication
- Login-failure throttling

### 🗂️ Object Storage
- Create storage buckets
- Upload and download files
- Store file metadata
- SHA-256 file integrity checks

### 🕒 Version Management
- Automatic file versioning
- View complete version history
- Restore previous versions
- Delete individual versions

Example:

```text
hello.txt
 ├── v1
 ├── v2
 └── v3  ← restored version

♻️ Lifecycle Management
Configure automatic cleanup of old objects.
- Set object expiration periods
- Preview objects that will expire
- Execute lifecycle cleanup
- Automatically remove expired files

🔗 Secure File Sharing
Create controlled sharing links with:
- Recipient identification
- Expiration time
- Maximum view count
- Manual revocation
- Cryptographically signed URLs
Share links use HMAC-SHA256 signatures to prevent URL tampering.
/v/{share_id}?e={expires}&sig={signature}

📧 Email Sharing
Secure sharing links can be sent directly to the recipient through SMTP email.
Gmail App Passwords can be used for authentication.

🕵️ Leak Tracing
VaultTrace provides recipient-specific document personalization.
Image Watermarking
Shared images receive a visible recipient watermark.
        CONFIDENTIAL
     Shared with:
     recipient@email.com

Hidden Fingerprinting
Each shared copy also contains a hidden identifier linked to its share.
For images, a hidden binary fingerprint is embedded into the image.
For .txt files, invisible zero-width Unicode characters are used.
Leak Tracer
If a personalized document is leaked, the owner can upload it to the Leak Tracer.
The system attempts to recover:
- Recipient
- Original file
- Share ID
- Share status
- View information
- Sharing details

If no fingerprint is found, the system reports that the file could not be associated with a VaultTrace share.

🛡️ Tamper-Evident Audit Logs
VaultTrace records important security events such as:
REGISTER
LOGIN
CREATE_BUCKET
PUT_OBJECT
RESTORE_VERSION
DELETE_VERSION
CREATE_SHARE
VIEW_SHARE
VIEW_DENIED
REVOKE_SHARE
LIFECYCLE_RUN
TRACE

Hash-Chained Audit Trail
Each audit entry is cryptographically linked to the previous entry.
Entry 1
   ↓
Hash 1
   ↓
Entry 2 + Hash 1
   ↓
Hash 2
   ↓
Entry 3 + Hash 2

Changing or deleting an entry breaks the chain and allows VaultTrace to detect tampering.
Checkpoints
VaultTrace also supports trusted checkpoints.
This allows the system to detect a sophisticated attacker who modifies an old entry and recalculates the remaining hashes.
Possible results include:
✓ Integrity verified
🚨 TAMPERING DETECTED
⚠ HISTORY REWRITTEN

🧪 Security Demonstrations
VaultTrace includes demonstrations for:
1. Modifying an audit record
2. Deleting an audit record
3. Rewriting the audit chain
4. Detecting rewritten history using checkpoints
5. Tampering with signed share URLs
6. Expired share access
7. Exhausting view limits
8. Revoking active shares
9. Tracing leaked personalized documents

🏗️ Architecture
              ┌───────────────┐
              │    Browser    │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │    FastAPI    │
              │    Backend    │
              └───────┬───────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
    Storage       Security       Auditing
     Engine        Engine          Engine
        │             │             │
        └─────────────┼─────────────┘
                      ▼
              ┌───────────────┐
              │ Oracle DB     │
              └───────────────┘

🛠️ Technology Stack
Backend
- Python
- FastAPI
- Uvicorn
- JWT
- bcrypt
Database
- Oracle Database
- SQL*Plus
Frontend
- HTML
- CSS
- JavaScript
Security & Processing
- HMAC-SHA256
- SHA-256
- Pillow
- NumPy
Email
- SMTP / Gmail App Password

📁 Project Structure
VaultTrace/
│
├── main.py
├── config.py
├── db.py
├── auth.py
├── audit.py
├── s3sim.py
├── presign.py
├── fingerprint.py
├── mail.py
│
├── schema.sql
├── step4.sql
├── seed_demo.py
├── rewrite_demo.py
│
└── static/
    ├── app.html
    ├── app.js
    ├── api.js
    ├── share.js
    ├── trace.js
    ├── audit.js
    ├── view.html
    └── style.css

⚙️ Installation
1. Clone the repository
git clone https://github.com/YOUR_USERNAME/VaultTrace.git
cd VaultTrace

2. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

3. Install dependencies
pip install -r requirements.txt

4. Configure Oracle
Start Oracle Database and connect using SQL*Plus:
sqlplus vault/vault123@localhost:1521/XEPDB1

Run:
@schema.sql
@step4.sql

5. Configure environment variables
Example:
$env:SMTP_USER="your-email@gmail.com"
$env:SMTP_PASSWORD="your-app-password"

Never commit passwords, API keys, .env, venv/, or storage/ to GitHub.
6. Run VaultTrace
uvicorn main:app --reload

Open:
http://127.0.0.1:8000

🎬 Demo Flow
A complete demonstration can be performed as:
Login
  ↓
Create Bucket
  ↓
Upload File
  ↓
Create Versions
  ↓
Restore Version
  ↓
Configure Lifecycle
  ↓
Create Secure Share
  ↓
Email Share Link
  ↓
Open Document
  ↓
Test View Limit
  ↓
Revoke Link
  ↓
Test URL Tampering
  ↓
Watermarked Image
  ↓
Leak Tracer
  ↓
Audit Logs
  ↓
Verify Integrity
  ↓
Demonstrate Tampering

🔒 Security Overview
Mechanism	Purpose
Bcrypt	Password protection
JWT	Authentication
HMAC-SHA256	Secure share URLs
SHA-256	File integrity
Expiration	Time-limited access
View limits	Controlled usage
Revocation	Immediate access removal
Watermarking	Visible recipient identification
Hidden fingerprint	Leak tracing
Hash chain	Audit tamper detection
Checkpoints	History rewriting detection
Login throttling	Brute-force protection


📌 Project Status
VaultTrace is a completed academic prototype.
Core functionality includes:
- Authentication
- Object storage
- Version control
- Version restoration
- Lifecycle management
- Secure sharing
- Expiring links
- View limits
- Link revocation
- Email delivery
- Watermarking
- Hidden fingerprinting
- Leak tracing
- Audit logging
- Hash-chain verification
- Tamper detection
- History rewriting detection

Author
Samyuktha Chowdary Vadlamudi
Computer Science & Engineering
VIT University
