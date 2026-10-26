#!/usr/bin/env python3
"""
generate_coverage_matrix.py
===========================
Parser mandiri untuk membaca security_audit_evidence.jsonl dan mengonversinya
menjadi draf tabel Coverage Matrix (Lampiran H) dalam format Markdown dan CSV.
"""

import os
import sys
import json
import csv
from typing import List, Dict, Any

DEFAULT_EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence", "security_audit_evidence.jsonl")
EVIDENCE_FILE = os.getenv("EVIDENCE_LOG_FILE", DEFAULT_EVIDENCE)
DEFAULT_MD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports", "coverage_matrix.md")
DEFAULT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports", "coverage_matrix.csv")
MD_OUTPUT = sys.argv[1] if len(sys.argv) > 1 else os.getenv("COVERAGE_MD_OUTPUT", DEFAULT_MD)
CSV_OUTPUT = sys.argv[2] if len(sys.argv) > 2 else os.getenv("COVERAGE_CSV_OUTPUT", DEFAULT_CSV)

def map_wstg(record: Dict[str, Any]) -> str:
    """Memetakan kasus uji ke kategori OWASP WSTG v4.2."""
    if "wstg_ref" in record and record["wstg_ref"]:
        return record["wstg_ref"]
    category = record.get("category", "").upper()
    if "BOLA" in category:
        return "WSTG-ATHZ-02"
    elif "BFLA" in category:
        return "WSTG-ATHZ-03"
    elif "NA" in category:
        return "WSTG-ATHZ-02"
    return "WSTG-ATHZ-04"

def map_recommendation_status(verdict: str, status_code: int) -> str:
    """Memetakan oracle verdict ke Rekomendasi Status Awal (Lampiran H)."""
    v = verdict.upper()
    if "CONFIRMED_VULNERABLE" in v:
        return "Confirmed"
    elif "NOT_CONFIRMED_DENIED" in v:
        return "Not Confirmed"
    elif "NOT_APPLICABLE" in v or status_code == 500:
        return "Not Applicable"
    elif "CANARY_TRIPPED" in v:
        return "Canary Tripped (Control-Only)"
    return "Not Confirmed"

def main():
    if not os.path.exists(EVIDENCE_FILE):
        print(f"[-] Berkas log evidence tidak ditemukan: {EVIDENCE_FILE}")
        sys.exit(1)

    records: List[Dict[str, Any]] = []
    with open(EVIDENCE_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    print(f"[*] Membaca {len(records)} rekaman audit dari {EVIDENCE_FILE}...")

    # Struktur Header Matriks
    headers = [
        "Test ID",
        "WSTG Mapping",
        "Endpoint",
        "Method",
        "Tipe Kontrol",
        "User Role",
        "HTTP Status",
        "DB Mutated",
        "Rekomendasi Status",
        "Keterangan / Temuan"
    ]

    rows = []
    summary_counts = {
        "Confirmed": 0,
        "Not Confirmed": 0,
        "Not Applicable": 0,
        "Canary Tripped (Control-Only)": 0
    }

    for r in records:
        test_id = r.get("test_id", "N/A")
        wstg = map_wstg(r)
        endpoint = r.get("endpoint", "")
        method = r.get("method", "")
        category = r.get("category", "")
        user_role = r.get("user_role", "")
        status_code = r.get("response", {}).get("status_code", 0)
        db_mutated = "Ya" if r.get("database_verification", {}).get("state_mutated") else "Tidak"
        
        rec_status = map_recommendation_status(r.get("oracle_verdict", ""), status_code)
        summary_counts[rec_status] = summary_counts.get(rec_status, 0) + 1
        
        justification = r.get("justification", "").replace("|", "-").replace("\n", " ")

        rows.append([
            test_id,
            wstg,
            endpoint,
            method,
            category,
            user_role,
            str(status_code),
            db_mutated,
            rec_status,
            justification
        ])

    # 1. Export ke CSV
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"[+] Coverage matrix diekspor ke format CSV: {CSV_OUTPUT}")

    # 2. Export ke Markdown
    md_content = []
    md_content.append("# Lampiran H: Coverage Matrix Analisis Keamanan REST API Crater Invoicing\n")
    md_content.append(f"**Commit Terpin**: `05d5ce26fdd8d9466009163444e944259bc0cc2a`  ")
    md_content.append(f"**Total Kasus Uji**: {len(rows)}  ")
    md_content.append(f"- **Confirmed Vulnerable**: {summary_counts.get('Confirmed', 0)}")
    md_content.append(f"- **Not Confirmed (Aman/Denied)**: {summary_counts.get('Not Confirmed', 0)}")
    md_content.append(f"- **Not Applicable (HTTP 500)**: {summary_counts.get('Not Applicable', 0)}")
    md_content.append(f"- **Canary Controls Tripped**: {summary_counts.get('Canary Tripped (Control-Only)', 0)}\n")

    # Header baris
    md_content.append("| " + " | ".join(headers) + " |")
    md_content.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for row in rows:
        md_content.append("| " + " | ".join(row) + " |")

    with open(MD_OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(md_content) + "\n")
    print(f"[+] Coverage matrix diekspor ke format Markdown: {MD_OUTPUT}")

    # Print Cuplikan Tabel di Terminal
    print("\n--- RINGKASAN COVERAGE MATRIX (TOP 5 ENTRIES) ---")
    for r in rows[:5]:
        print(f"[{r[0]:<18}] {r[1]:<14} {r[3]:<6} {r[2]:<24} -> {r[8]:<15} (HTTP {r[6]})")
    print(f"...\nTotal {len(rows)} baris telah diproses.")

if __name__ == "__main__":
    main()
