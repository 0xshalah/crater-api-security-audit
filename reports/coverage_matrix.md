# Lampiran H: Coverage Matrix Analisis Keamanan REST API Crater Invoicing

**Commit Terpin**: `05d5ce26fdd8d9466009163444e944259bc0cc2a`  
**Total Kasus Uji**: 24  
- **Confirmed Vulnerable**: 10
- **Not Confirmed (Aman/Denied)**: 10
- **Not Applicable (HTTP 500)**: 4
- **Canary Controls Tripped**: 0

| Test ID | WSTG Mapping | Endpoint | Method | Tipe Kontrol | User Role | HTTP Status | DB Mutated | Rekomendasi Status | Keterangan / Temuan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BOLA-H1 | WSTG-ATHZ-04 | /customers | GET | BOLA | User A | 200 | Tidak | Not Confirmed | CompanyMiddleware otomatis fallback ke company pertama milik user ($user->companies()->first()->id) |
| BOLA-H2 | WSTG-ATHZ-04 | /customers | GET | BOLA | User A | 200 | Tidak | Not Confirmed | CompanyMiddleware silent fallback menimpa header company yang bukan haknya menjadi ID company milik user |
| BOLA-P1 | WSTG-ATHZ-02 | /items | POST | BOLA | User A | 200 | Tidak | Not Confirmed | Payload company_id 2 ditolak atau di-override ke tenant 1 |
| BOLA-CTRL-DEL-CUSTOMERS | WSTG-ATHZ-02 | /customers/6 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CTRL-DEL-INVOICES | WSTG-ATHZ-02 | /invoices/18 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CTRL-DEL-ITEMS | WSTG-ATHZ-02 | /items/7 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CTRL-DEL-ESTIMATES | WSTG-ATHZ-02 | /estimates/12 | DELETE | NA | User A | 500 | Tidak | Not Applicable | Controller tidak memiliki metode destroy() sehingga menghasilkan BadMethodCallException (HTTP 500) |
| BOLA-CLONE-INV | WSTG-ATHZ-02 | /invoices/18/clone | POST | BOLA | User A | 201 | Ya | Confirmed | CloneInvoiceController hanya mengecek ability create level kelas tanpa validasi izin baca terhadap source invoice |
| BFLA-CLONE-INV-LOW | WSTG-ATHZ-03 | /invoices/1/clone | POST | BFLA | User Low | 403 | Tidak | Not Confirmed | Gate/Policy create Invoice::class berhasil menolak User Low yang tidak memiliki ability create-invoice |
| BFLA-F9-DISK | WSTG-ATHZ-03 | /disks | GET | BFLA | User Low | 403 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /disks |
| BFLA-F10-BACKUP | WSTG-ATHZ-03 | /backups | GET | BFLA | User Low | 403 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /backups |
| BFLA-F11-UPDATE | WSTG-ATHZ-03 | /check/update | GET | BFLA | User Low | 401 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /check/update |
| BFLA-F4-USER | WSTG-ATHZ-03 | /users | GET | BFLA | User Low | 403 | Tidak | Not Confirmed | Pemeriksaan isOwner() berhasil memblokir User Low pada /users |
| BFLA-MAIL2 | WSTG-ATHZ-03 | /company/mail/config | GET | BFLA | User Low | 200 | Tidak | Confirmed | GetCompanyMailConfigurationController tidak memiliki pemanggilan authorize() maupun isOwner() |
| BFLA-COMP2 | WSTG-ATHZ-03 | /transfer/ownership/3 | POST | BFLA | Owner A | 200 | Tidak | Confirmed | Inversi logika if ($user->hasCompany()) menyebabkan penolakan transfer kepemilikan yang sah |
| CANARY-BOLA-INV | WSTG-ATHZ-02 | /invoices/18 | GET | CONTROL-ONLY | User A | 403 | Tidak | Not Confirmed | [Control-Only] Baseline guard masih aktif |
| CANARY-BFLA-DISK | WSTG-ATHZ-03 | /disks | GET | CONTROL-ONLY | User Low | 403 | Tidak | Not Confirmed | [Control-Only] Baseline guard masih aktif |
| BOLA-DEL-CUSTOMERS | WSTG-ATHZ-02 | /customers/delete | POST | BOLA | User A | 200 | Ya | Confirmed | Batch delete pada /customers/delete menghapus record milik tenant 2 tanpa verifikasi company_id di database |
| BOLA-DEL-ITEMS | WSTG-ATHZ-02 | /items/delete | POST | BOLA | User A | 200 | Ya | Confirmed | Batch delete pada /items/delete menghapus record milik tenant 2 tanpa verifikasi company_id di database |
| BOLA-DEL-INVOICES | WSTG-ATHZ-02 | /invoices/delete | POST | BOLA | User A | 200 | Ya | Confirmed | Batch delete pada /invoices/delete menghapus record milik tenant 2 tanpa verifikasi company_id di database |
| BOLA-DEL-ESTIMATES | WSTG-ATHZ-02 | /estimates/delete | POST | BOLA | User A | 200 | Ya | Confirmed | Batch delete pada /estimates/delete menghapus record milik tenant 2 tanpa verifikasi company_id di database |
| BOLA-DEL-EXPENSES | WSTG-ATHZ-02 | /expenses/delete | POST | BOLA | User A | 200 | Ya | Confirmed | Batch delete pada /expenses/delete menghapus record milik tenant 2 tanpa verifikasi company_id di database |
| BOLA-DEL-PAYMENTS | WSTG-ATHZ-02 | /payments/delete | POST | BOLA | User A | 200 | Ya | Confirmed | Batch delete pada /payments/delete menghapus record milik tenant 2 tanpa verifikasi company_id di database |
| BOLA-DEL-RECURRING-INVOICES | WSTG-ATHZ-02 | /recurring-invoices/delete | POST | BOLA | User A | 200 | Ya | Confirmed | Batch delete pada /recurring-invoices/delete menghapus record milik tenant 2 tanpa verifikasi company_id di database |
