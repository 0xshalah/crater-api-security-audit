#!/usr/bin/env python3
"""
test_functional_regression.py
=============================
Uji Regresi Fungsional (Kontrol Positif) Pasca-Mitigasi untuk Crater Invoicing.
Memverifikasi bahwa patch perbaikan (remediation.diff) tidak merusak alur bisnis normal
dan bahwa hak akses sah (Expected Allow) tetap berfungsi 100% normal.
"""

import os
import sys
import json
import pymysql
import pymysql.cursors
import requests
from typing import Dict, Any, List

BASE_URL = os.getenv("CRATER_BASE_URL", "http://127.0.0.1:8000/api/v1")
DB_HOST = os.getenv("CRATER_DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("CRATER_DB_PORT", "33006"))
DB_USER = os.getenv("CRATER_DB_USER", "crater")
DB_PASSWORD = os.getenv("CRATER_DB_PASSWORD", "crater")
DB_NAME = os.getenv("CRATER_DB_NAME", "crater")

def get_db_connection():
    """Membuka koneksi TCP langsung ke port expose MariaDB container."""
    try:
        return pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=5
        )
    except pymysql.MySQLError as err:
        raise ConnectionError(
            f"[-] Gagal terhubung ke MariaDB riil di {DB_HOST}:{DB_PORT} ({err}). "
            f"Pastikan container db berjalan (docker compose ps)."
        ) from err

def execute_sql(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Mengeksekusi kueri SQL riil ke MariaDB dan mengembalikan snapshot record."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return list(rows)
    finally:
        conn.close()

class TestClient:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()

    def get_token(self, email: str, password: str = "Password123!") -> str:
        login_url = f"{self.base_url}/auth/login"
        payload = {
            "username": email,
            "password": password,
            "device_name": "functional-regression-test"
        }
        res = self.session.post(login_url, json=payload, headers={"Accept": "application/json"}, timeout=10)
        if res.status_code != 200:
            raise RuntimeError(f"[-] Autentikasi login riil gagal untuk {email}: HTTP {res.status_code} - {res.text}")
        data = res.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(f"[-] Respons otentikasi tidak memuat token: {res.text}")
        return token

    def request(
        self,
        method: str,
        path: str,
        token: str,
        company_header: str = "1",
        json_data: Any = None
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "company": str(company_header)
        }
        return self.session.request(method, url, headers=headers, json=json_data, timeout=10)

client = TestClient()

# ==============================================================================
# SUITE REGRESI FUNGSIONAL (KONTROL POSITIF)
# ==============================================================================

def test_reg_batch_delete_own_tenant():
    """
    1. Kontrol Positif Batch Delete (Tenant Sendiri):
       User A (Company 1) menghapus record Customer dan Invoice miliknya sendiri di Company 1.
       Expected: HTTP 200 OK, success: true, dan record terhapus dari MariaDB.
    """
    token_a = client.get_token("user.a@crater.test")
    
    target_cust = execute_sql("SELECT id FROM customers WHERE company_id = 1 ORDER BY id DESC LIMIT 1")
    target_inv = execute_sql("SELECT id FROM invoices WHERE company_id = 1 ORDER BY id DESC LIMIT 1")
    assert target_cust and target_inv, "Fixture Customer / Invoice Company 1 tidak mencukupi untuk pengujian"
    
    cust_id = target_cust[0]["id"]
    inv_id = target_inv[0]["id"]
    
    # Eksekusi Delete Invoice Sah
    pre_inv = execute_sql(f"SELECT id FROM invoices WHERE id = {inv_id}")
    res_inv = client.request("POST", "/invoices/delete", token_a, company_header="1", json_data={"ids": [inv_id]})
    post_inv = execute_sql(f"SELECT id FROM invoices WHERE id = {inv_id}")
    
    assert res_inv.status_code == 200, f"Gagal delete invoice sah: HTTP {res_inv.status_code} {res_inv.text}"
    assert res_inv.json().get("success") is True, f"Delete invoice sah respons bukan success: {res_inv.text}"
    assert len(pre_inv) > 0 and len(post_inv) == 0, f"Invoice {inv_id} tidak terhapus dari database MariaDB"
    
    # Eksekusi Delete Customer Sah
    pre_cust = execute_sql(f"SELECT id FROM customers WHERE id = {cust_id}")
    res_cust = client.request("POST", "/customers/delete", token_a, company_header="1", json_data={"ids": [cust_id]})
    post_cust = execute_sql(f"SELECT id FROM customers WHERE id = {cust_id}")
    
    assert res_cust.status_code == 200, f"Gagal delete customer sah: HTTP {res_cust.status_code} {res_cust.text}"
    assert res_cust.json().get("success") is True, f"Delete customer sah respons bukan success: {res_cust.text}"
    assert len(pre_cust) > 0 and len(post_cust) == 0, f"Customer {cust_id} tidak terhapus dari database MariaDB"

def test_reg_mail_config_owner_access():
    """
    2. Kontrol Positif Akses Konfigurasi Email:
       Owner A mengeksekusi GET /api/v1/company/mail/config.
       Expected: HTTP 200 OK, from_name dan from_mail berhasil dibaca (Owner berhak membaca).
    """
    token_owner = client.get_token("owner.a@crater.test")
    res = client.request("GET", "/company/mail/config", token_owner, company_header="1")
    
    assert res.status_code == 200, f"Owner ditolak mengakses konfigurasi mail: HTTP {res.status_code} {res.text}"
    data = res.json()
    assert "from_mail" in data or "from_name" in data, f"Respons tidak memuat informasi konfigurasi email: {data}"

def test_reg_transfer_ownership_legitimate_member():
    """
    3. Kontrol Positif Transfer Kepemilikan Internal Sah:
       Owner A mentransfer kepemilikan Company 1 kepada User A (anggota sah Company 1, ID: 3).
       Expected: HTTP 200 OK, success: true, dan kolom companies.owner_id berubah menjadi 3 di MariaDB.
    """
    token_owner = client.get_token("owner.a@crater.test")
    user_a_record = execute_sql("SELECT id FROM users WHERE email = 'user.a@crater.test'")
    assert user_a_record, "User A tidak ditemukan di basis data"
    target_user_id = user_a_record[0]["id"]
    
    pre_company = execute_sql("SELECT owner_id FROM companies WHERE id = 1")
    assert pre_company and pre_company[0]["owner_id"] == 1, "Owner awal bukan Owner A (ID: 1)"
    
    res = client.request("POST", f"/transfer/ownership/{target_user_id}", token_owner, company_header="1")
    assert res.status_code == 200, f"Transfer kepemilikan gagal HTTP: {res.status_code} {res.text}"
    assert res.json().get("success") is True, f"Transfer kepemilikan ditolak: {res.text}"
    
    post_company = execute_sql("SELECT owner_id FROM companies WHERE id = 1")
    assert post_company[0]["owner_id"] == target_user_id, f"Kolom owner_id tidak berubah ke {target_user_id} (Nilai aktual: {post_company[0]['owner_id']})"

def test_reg_clone_invoice_own_tenant():
    """
    4. Kontrol Positif Duplikasi Faktur Sah (Tenant Sendiri):
       User A (memiliki create-invoice dan view-invoice) mengkloning Invoice miliknya di Company 1.
       Expected: HTTP 201/200, faktur baru terbentuk di Company 1 dan total faktur Company 1 bertambah 1.
    """
    token_a = client.get_token("user.a@crater.test")
    target_inv = execute_sql("SELECT id FROM invoices WHERE company_id = 1 ORDER BY id ASC LIMIT 1")
    assert target_inv, "Invoice sah milik Company 1 tidak ditemukan untuk pengujian kloning"
    source_inv_id = target_inv[0]["id"]
    
    pre_count = execute_sql("SELECT COUNT(*) as c FROM invoices WHERE company_id = 1")[0]["c"]
    res = client.request("POST", f"/invoices/{source_inv_id}/clone", token_a, company_header="1")
    post_count = execute_sql("SELECT COUNT(*) as c FROM invoices WHERE company_id = 1")[0]["c"]
    
    assert res.status_code in [200, 201], f"Kloning invoice sah gagal: HTTP {res.status_code} {res.text}"
    assert post_count == pre_count + 1, f"Jumlah faktur Company 1 tidak bertambah (Pre: {pre_count}, Post: {post_count})"
    new_inv_id = res.json().get("data", {}).get("id")
    assert new_inv_id, f"Respons tidak memuat ID faktur baru: {res.text}"
    new_inv_db = execute_sql(f"SELECT id, company_id FROM invoices WHERE id = {new_inv_id}")
    assert new_inv_db and new_inv_db[0]["company_id"] == 1, f"Faktur baru di MariaDB tidak memiliki company_id = 1: {new_inv_db}"

# ==============================================================================
# ENTRYPOINT CLI
# ==============================================================================

if __name__ == "__main__":
    print("[*] Memulai Uji Regresi Fungsional (Kontrol Positif Pasca-Mitigasi)...")
    print(f"[*] Target Endpoint : {BASE_URL}")
    print(f"[*] Target Database : {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    
    tests = [
        ("Batch Deletion Sah (Tenant Sendiri)", test_reg_batch_delete_own_tenant),
        ("Akses Konfigurasi Email oleh Owner", test_reg_mail_config_owner_access),
        ("Transfer Kepemilikan Internal Sah", test_reg_transfer_ownership_legitimate_member),
        ("Duplikasi Faktur Sah (Tenant Sendiri)", test_reg_clone_invoice_own_tenant),
    ]
    
    passed = 0
    failed = 0
    for title, fn in tests:
        name = fn.__name__
        try:
            fn()
            print(f"  [+] {title:<44} ({name}): PASSED")
            passed += 1
        except AssertionError as ae:
            print(f"  [-] {title:<44} ({name}): REGRESSION DETECTED! ({ae})")
            failed += 1
        except Exception as e:
            print(f"  [!] {title:<44} ({name}): ERROR ({e})")
            failed += 1
            
    print(f"\n[*] Hasil Uji Regresi: {passed} passed, {failed} failed.")
    if failed > 0:
        sys.exit(1)
