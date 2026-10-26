# Lampiran H: Coverage Matrix Analisis Keamanan REST API Crater Invoicing

**Commit Terpin**: `05d5ce26fdd8d9466009163444e944259bc0cc2a`  
**Total Kasus Uji**: 24  
- **Confirmed Vulnerable**: 0
- **Not Confirmed (Aman/Denied)**: 20
- **Not Applicable (HTTP 500)**: 4
- **Canary Controls Tripped**: 0

| Test ID | WSTG Mapping | Endpoint | Method | Tipe Kontrol | User Role | HTTP Status | DB Mutated | Rekomendasi Status | Keterangan / Temuan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BOLA-H1 | WSTG-ATHZ-04 | /customers | GET | BOLA | User A | 200 | Tidak | Not Confirmed | CompanyMiddleware otomatis fallback ke company pertama milik user ($user->companies()->first()->id) |
| BOLA-H2 | WSTG-ATHZ-04 | /customers | GET | BOLA | User A | 200 | Tidak | Not Confirmed | CompanyMiddleware silent fallback menimpa header company yang bukan haknya menjadi ID company milik user |
| BOLA-P1 | WSTG-ATHZ-02 | /items | POST | BOLA | User A | 200 | Tidak | Not Confirmed | Payload company_id 2 ditolak atau di-override ke tenant 1 |
| BOLA-CTRL-DEL-CUSTOMERS | WSTG-ATHZ-02 | /customers/3 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CTRL-DEL-INVOICES | WSTG-ATHZ-02 | /invoices/3 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CTRL-DEL-ITEMS | WSTG-ATHZ-02 | /items/3 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CTRL-DEL-ESTIMATES | WSTG-ATHZ-02 | /estimates/3 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CLONE-INV | WSTG-ATHZ-02 | /invoices/3/clone | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses clone invoice ditolak secara aman oleh validasi otorisasi view invoice sumber (HTTP 403) |
| BFLA-CLONE-INV-LOW | WSTG-ATHZ-03 | /invoices/1/clone | POST | BFLA | User Low | 403 | Tidak | Not Confirmed | Gate/Policy create Invoice::class berhasil menolak User Low yang tidak memiliki ability create-invoice |
| BFLA-F9-DISK | WSTG-ATHZ-03 | /disks | GET | BFLA | User Low | 403 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /disks |
| BFLA-F10-BACKUP | WSTG-ATHZ-03 | /backups | GET | BFLA | User Low | 403 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /backups |
| BFLA-F11-UPDATE | WSTG-ATHZ-03 | /check/update | GET | BFLA | User Low | 401 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /check/update |
| BFLA-F4-USER | WSTG-ATHZ-03 | /users | GET | BFLA | User Low | 403 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /users |
| BFLA-MAIL2 | WSTG-ATHZ-03 | /company/mail/config | GET | BFLA | User Low | 403 | Tidak | Not Confirmed | Endpoint mail terlindungi otorisasi manage email config (HTTP 403) |
| BFLA-COMP2 | WSTG-ATHZ-03 | /transfer/ownership/3 | POST | BFLA | Owner A | 200 | Ya | Not Confirmed | Logika transfer kepemilikan berhasil diperbaiki (anggota company diterima, status success: true) |
| CANARY-BOLA-INV | WSTG-ATHZ-02 | /invoices/3 | GET | CONTROL-ONLY | User A | 403 | Tidak | Not Confirmed | [Control-Only] Baseline guard masih aktif |
| CANARY-BFLA-DISK | WSTG-ATHZ-03 | /disks | GET | CONTROL-ONLY | User Low | 403 | Tidak | Not Confirmed | [Control-Only] Baseline guard masih aktif |
| BOLA-DEL-CUSTOMERS | WSTG-ATHZ-02 | /customers/delete | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses batch delete /customers/delete ditolak secara aman oleh validasi tenant ownership (HTTP 403) |
| BOLA-DEL-ITEMS | WSTG-ATHZ-02 | /items/delete | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses batch delete /items/delete ditolak secara aman oleh validasi tenant ownership (HTTP 403) |
| BOLA-DEL-INVOICES | WSTG-ATHZ-02 | /invoices/delete | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses batch delete /invoices/delete ditolak secara aman oleh validasi tenant ownership (HTTP 403) |
| BOLA-DEL-ESTIMATES | WSTG-ATHZ-02 | /estimates/delete | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses batch delete /estimates/delete ditolak secara aman oleh validasi tenant ownership (HTTP 403) |
| BOLA-DEL-EXPENSES | WSTG-ATHZ-02 | /expenses/delete | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses batch delete /expenses/delete ditolak secara aman oleh validasi tenant ownership (HTTP 403) |
| BOLA-DEL-PAYMENTS | WSTG-ATHZ-02 | /payments/delete | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses batch delete /payments/delete ditolak secara aman oleh validasi tenant ownership (HTTP 403) |
| BOLA-DEL-RECURRING-INVOICES | WSTG-ATHZ-02 | /recurring-invoices/delete | POST | BOLA | User A | 403 | Tidak | Not Confirmed | Akses batch delete /recurring-invoices/delete ditolak secara aman oleh validasi tenant ownership (HTTP 403) |
