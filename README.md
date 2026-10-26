# Analisis Keamanan REST API Berbasis Otorisasi Objek dan Fungsi Menggunakan OWASP API Security Top 10 2023

[![Target](https://img.shields.io/badge/Target-Crater%20Invoicing%20v6.0.6-blue.svg)](https://github.com/crater-invoice-inc/crater)
[![Commit](https://img.shields.io/badge/Commit-05d5ce2-success.svg)](https://github.com/crater-invoice-inc/crater/commit/05d5ce26fdd8d9466009163444e944259bc0cc2a)
[![Standards](https://img.shields.io/badge/Standards-OWASP%20API%20%7C%20WSTG%20v4.2%20%7C%20CVSS%20v4.0-orange.svg)](https://owasp.org)
[![Institution](https://img.shields.io/badge/Institution-Politeknik%20Negeri%20Batam-red.svg)](https://www.polibatam.ac.id)

Repositori ini memuat seluruh artefak penelitian, test harness otomatis, data seeder deterministik, log bukti uji (*evidence*), patch kontrol mutasi, dan patch mitigasi untuk Tugas Akhir Program Studi Rekayasa Keamanan Siber, Politeknik Negeri Batam.

---

## 1. Identitas Penelitian & Institusi

- **Judul Penelitian**: Analisis Keamanan REST API Berbasis Otorisasi Objek dan Fungsi Menggunakan OWASP API Security Top 10 2023
- **Peneliti**: Shalahuddin Al-Ayyubi
- **Program Studi**: Sarjana Terapan Rekayasa Keamanan Siber (Cyber Security Engineering)
- **Jurusan**: Teknik Informatika
- **Institusi**: Politeknik Negeri Batam
- **Tahun**: 2026

---

## 2. Spesifikasi Baseline Target

Eksperimen dieksekusi secara deterministik pada lingkungan lokal terisolasi (*testbed*) berbasis Docker:

| Parameter | Spesifikasi Riset |
|---|---|
| **Aplikasi Target** | Crater Invoicing (Self-hosted Invoicing Platform) |
| **Repositori Sumber** | `https://github.com/crater-invoice-inc/crater.git` |
| **Commit Hash Terpin** | `05d5ce26fdd8d9466009163444e944259bc0cc2a` |
| **Framework Backend** | Laravel Framework v8.83.16 |
| **Runtime Language** | PHP 8.1.34 (NTS) FPM |
| **Database Server** | MariaDB 13.0.2-MariaDB-ubu2604 (TCP Port: 33006 / Container Port: 3306) |
| **Web Server / Reverse Proxy**| Nginx 1.17.10 Alpine (HTTP Port: 8000 & 80) |
| **Otorisasi Engine** | Silber/Bouncer v1.0.0-rc.9 & Laravel Gate/Policy |

---

## 3. Ringkasan Metodologi Pengujian

Penelitian mengombinasikan standar evaluasi keamanan internasional:
1. **OWASP API Security Top 10 2023**:
   - `API1:2023 - Broken Object Level Authorization (BOLA)`: Pengujian isolasi tenant dan hak akses instance objek antar perwakilan perusahaan yang setara (User A vs User B).
   - `API5:2023 - Broken Function Level Authorization (BFLA)`: Pengujian pembatasan fungsi administratif dan konfigurasi sensitif pada tenant yang sama (User Low vs Owner A).
2. **OWASP Web Security Testing Guide (WSTG v4.2)**:
   - `WSTG-ATHZ-02`: Bypassing Authorization Schema (BOLA Object ID Tampering).
   - `WSTG-ATHZ-03`: Bypassing Privilege Elevation (BFLA Administrative Function Execution).
   - `WSTG-ATHZ-04`: Testing for Inconsistent Access Control (Tenancy Middleware Fallback Manipulation).
3. **OWASP ASVS v4.0.3**:
   - Bagian V4 (Access Control Verification Requirements) Chapter 4.1, 4.2, dan 4.3.
4. **Common Vulnerability Scoring System (CVSS v4.0)**:
   - Penilaian kuantitatif keparahan celah berbasis Base Metrics vektor `CVSS:4.0`.
5. **Prinsip Oracle Deny Ketat**:
   - Kode status HTTP (200, 403, 404, 422) tidak dijadikan penentu tunggal. Evaluasi memvalidasi ketiadaan kebocoran metadata, ketiadaan mutasi state basis data (`state_mutated == False`), dan ketiadaan side-effect sistem. Respons `HTTP 500` akibat ketiadaan handler metode (*BadMethodCallException*) dicatat sebagai `Not Applicable (NA)`.

---

## 4. Struktur Direktori Repositori

```text
crater-api-security-audit/
├── manifests/
│   ├── collect_manifest.sh           # Otomasi pengumpulan manifest lingkungan container aktif
│   └── environment_manifest.json     # Manifest beku versi runtime & hash SHA-256 artefak
├── seeder/
│   └── SecurityResearchSeeder.php    # Seeder deterministik 2 Tenant, 4 Role, & Data sintetis berpasangan
├── harness/
│   ├── tests_security_runner.py      # Test harness otomatis 100% riil (Fail-Fast, MariaDB TCP, Sanctum)
│   └── generate_coverage_matrix.py   # Parser rekaman JSONL ke Coverage Matrix (Markdown & CSV)
├── patches/
│   ├── mutation_bola_invoice_policy.diff  # Canary control mutasi otorisasi objek (InvoicePolicy)
│   ├── mutation_bfla_owner_check.diff     # Canary control mutasi otorisasi fungsi (SettingsPolicy)
│   └── remediation.diff                   # Patch terpadu perbaikan 10 celah Confirmed Vulnerable
├── evidence/
│   └── security_audit_evidence.jsonl # Rekaman log bukti uji lengkap berstandar Tabel 3.8
├── reports/
│   ├── coverage_matrix.md            # Matriks cakupan pra-mitigasi (Markdown)
│   ├── coverage_matrix.csv           # Matriks cakupan pra-mitigasi (CSV)
│   ├── coverage_matrix_post_mitigation.md  # Matriks cakupan pasca-mitigasi (Markdown)
│   └── coverage_matrix_post_mitigation.csv # Matriks cakupan pasca-mitigasi (CSV)
├── .gitignore                        # Pengecualian venv, cache bytecode, dan file lokal
└── README.md                         # Dokumentasi riset berstandar akademik
```

---

## 5. Ringkasan Temuan & Penilaian CVSS v4.0

### Tabel Penilaian Skor CVSS v4.0 (10 Temuan Confirmed Vulnerable)

| No | Test ID | Target Endpoint | Vektor CVSS v4.0 | Skor | Kategori | Ringkasan Dampak Teknis |
|---|---|---|---|---|---|---|
| 1 | `BOLA-CLONE-INV` | `POST /api/v1/invoices/{id}/clone` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` | **7.1** | **High** | Duplikasi data invoice tenant lain tanpa otorisasi baca sumber. |
| 2 | `BOLA-DEL-CUSTOMERS` | `POST /api/v1/customers/delete` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N` | **8.6** | **High** | Cascade deletion pelanggan, faktur, transaksi, dan pembayaran korban. |
| 3 | `BOLA-DEL-ITEMS` | `POST /api/v1/items/delete` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N` | **7.1** | **High** | Pemusnahan master item katalog produk/jasa tenant lain. |
| 4 | `BOLA-DEL-INVOICES` | `POST /api/v1/invoices/delete` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N` | **8.6** | **High** | Penghapusan faktur penagihan aktif dan rekaman transaksi kas legal. |
| 5 | `BOLA-DEL-ESTIMATES` | `POST /api/v1/estimates/delete` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N` | **7.1** | **High** | Pemusnahan dokumen penawaran harga korban tanpa validasi tenant. |
| 6 | `BOLA-DEL-EXPENSES` | `POST /api/v1/expenses/delete` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N` | **7.1** | **High** | Manipulasi pengeluaran yang mendistorsi laporan laba/rugi korban. |
| 7 | `BOLA-DEL-PAYMENTS` | `POST /api/v1/payments/delete` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N` | **8.6** | **High** | Penghapusan bukti pelunasan; invoice korban kembali berstatus unpaid. |
| 8 | `BOLA-DEL-RECURRING-INVOICES` | `POST /api/v1/recurring-invoices/delete` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N` | **8.6** | **High** | Penghentian permanen otomasi penagihan langganan berkala korban. |
| 9 | `BFLA-MAIL2` | `GET /api/v1/company/mail/config` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` | **5.3** | **Medium** | Pembocoran identitas dan alamat email pengirim sistem ke User Low. |
| 10 | `BFLA-COMP2` | `POST /api/v1/transfer/ownership/{u}` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | **8.4** | **High** | Inversi logika otorisasi membuka pengambilalihan kontrol tenant ke penyerang luar. |

### Perbandingan Efektivitas Pra vs Pasca Remediasi

```text
+------------------------------+--------------------+---------------------+
| Rekomendasi Status           | Pra-Mitigasi       | Pasca-Mitigasi      |
+------------------------------+--------------------+---------------------+
| Confirmed Vulnerable         | 10 temuan (41.7%)  |  0 temuan (  0.0%)  |
| Not Confirmed (Aman/Denied)  | 10 temuan (41.7%)  | 20 temuan ( 83.3%)  |
| Not Applicable (HTTP 500)    |  4 temuan (16.6%)  |  4 temuan ( 16.7%)  |
| Total Skenario Diuji         | 24 kasus uji       | 24 kasus uji        |
+------------------------------+--------------------+---------------------+
```

---

## 6. Panduan Reproduksi Eksperimen Langkah Demi Langkah

### Prasyarat Sistem
- Docker Engine `>= 20.10` & Docker Compose v2.
- Python `>= 3.9` dengan virtual environment (`pymysql`, `requests`, `pytest`).

### Langkah 1: Kloning Repositori Riset & Target Crater
```bash
# Direktori kerja
cd /home/shalahuddin/skripsi

# Pastikan Crater berada pada commit terpin
git clone https://github.com/crater-invoice-inc/crater.git crater
cd crater
git checkout 05d5ce26fdd8d9466009163444e944259bc0cc2a
```

### Langkah 2: Salin Seeder Riset & Jalankan Docker
```bash
# Salin seeder riset deterministik ke dalam pohon source Crater
cp ../crater-api-security-audit/seeder/SecurityResearchSeeder.php database/seeders/

# Nyalakan container terisolasi
docker compose up -d

# Jalankan migrasi dan seeding
docker compose exec -T app composer install
docker compose exec -T app php artisan key:generate
docker compose exec -T app php artisan migrate:fresh --seed --seeder=SecurityResearchSeeder
```

### Langkah 3: Eksekusi Test Runner Baseline (Pra-Mitigasi)
```bash
cd /home/shalahuddin/skripsi/crater-api-security-audit

# Setup virtual environment jika belum ada
python3 -m venv venv
source venv/bin/activate
pip install pymysql requests pytest

# Jalankan test suite riil
python harness/tests_security_runner.py

# Generate laporan matriks pra-mitigasi
python harness/generate_coverage_matrix.py reports/coverage_matrix.md reports/coverage_matrix.csv
```

### Langkah 4: Verifikasi Sensitivitas Harness (Canary Mutation Testing)
```bash
cd /home/shalahuddin/skripsi/crater

# 1. Canary BOLA: Melemahkan guard InvoicePolicy::view
git apply ../crater-api-security-audit/patches/mutation_bola_invoice_policy.diff
python ../crater-api-security-audit/harness/tests_security_runner.py
# Amati: Kasus uji CANARY-BOLA-INV terdeteksi tripped (HTTP 200)
git apply -R ../crater-api-security-audit/patches/mutation_bola_invoice_policy.diff

# 2. Canary BFLA: Melemahkan guard SettingsPolicy::manageFileDisk
git apply ../crater-api-security-audit/patches/mutation_bfla_owner_check.diff
python ../crater-api-security-audit/harness/tests_security_runner.py
# Amati: Kasus uji CANARY-BFLA-DISK terdeteksi tripped (HTTP 200)
git apply -R ../crater-api-security-audit/patches/mutation_bfla_owner_check.diff
```

### Langkah 5: Penerapan Remediasi & Verifikasi Pasca-Mitigasi
```bash
cd /home/shalahuddin/skripsi/crater

# Buat branch mitigasi dan terapkan patch terpadu
git checkout -b fix/security-mitigations
git apply ../crater-api-security-audit/patches/remediation.diff

# Reset dan seed ulang basis data
docker compose exec -T app php artisan migrate:fresh --seed --seeder=SecurityResearchSeeder

# Eksekusi ulang runner verifikasi pasca-mitigasi
cd /home/shalahuddin/skripsi/crater-api-security-audit
python harness/tests_security_runner.py

# Generate laporan matriks pasca-mitigasi
python harness/generate_coverage_matrix.py reports/coverage_matrix_post_mitigation.md reports/coverage_matrix_post_mitigation.csv
```

---

## 7. Lisensi & Hak Penggunaan

Artefak ini disusun khusus untuk keperluan pengujian akademik dan penelitian skripsi di **Politeknik Negeri Batam**. Seluruh kode sumber pihak ketiga tetap berada di bawah lisensi masing-masing (Crater Invoicing - GNU AGPL v3.0 / Fair Source License).
