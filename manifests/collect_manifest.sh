#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATER_DIR="${CRATER_DIR:-$(cd "$SCRIPT_DIR/../../crater" 2>/dev/null && pwd || echo "$SCRIPT_DIR")}"
OUTPUT_FILE="${1:-$SCRIPT_DIR/environment_manifest.json}"
cd "$CRATER_DIR"

echo "[*] Memeriksa status runtime Docker Compose Crater Invoicing..."

# 1. Pastikan Docker CLI dan Docker Compose terpasang
if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Error: Docker CLI tidak ditemukan pada sistem." >&2
    exit 1
fi

# 2. Validasi status container aktif (Prinsip Fail-Fast)
# Container app dan db wajib berstatus Up/running
RUNNING_CONTAINERS=$(docker compose ps --services --filter "status=running" 2>/dev/null || true)
if [ -z "$RUNNING_CONTAINERS" ] || ! echo "$RUNNING_CONTAINERS" | grep -q "app" || ! echo "$RUNNING_CONTAINERS" | grep -q "db"; then
    echo "[-] Error: Container Docker belum berjalan atau belum sehat." >&2
    echo "    Pastikan lingkungan aktif dengan menjalankan: docker compose up -d" >&2
    docker compose ps >&2 || true
    exit 1
fi

echo "[+] Container terdeteksi aktif. Mengumpulkan versi runtime riil dari dalam container..."

# 3. Kumpulkan versi runtime riil langsung dari dalam container
PHP_VERSION=$(docker compose exec -T app php -v | head -n 1 | tr -d '\r')
ARTISAN_VERSION=$(docker compose exec -T app php artisan --version | tr -d '\r')

MARIADB_VERSION=$(docker compose exec -T db mariadb -u crater -pcrater -s -N -e "SELECT VERSION();" 2>/dev/null || docker compose exec -T db mysql -u crater -pcrater -s -N -e "SELECT VERSION();" 2>/dev/null | tr -d '\r')
DOCKER_VERSION=$(docker --version | tr -d '\r')
DOCKER_COMPOSE_VERSION=$(docker compose version | tr -d '\r')

# 5. Git Commit Hash dari repositori terpin
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "UNKNOWN")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "DETACHED")

# 6. Hitung Checksum SHA-256 Artefak Uji
HASH_COMPOSE=$(sha256sum docker-compose.yml | awk '{print $1}')
HASH_SEEDER=$(sha256sum database/seeders/SecurityResearchSeeder.php | awk '{print $1}')
HASH_ENV=$(sha256sum .env.testing | awk '{print $1}')

# 7. Tulis Manifest Riil ke JSON
cat <<EOF > "$OUTPUT_FILE"
{
  "manifest_metadata": {
    "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "target_repository": "https://github.com/crater-invoice-inc/crater.git",
    "pinned_commit": "$GIT_COMMIT",
    "git_branch": "$GIT_BRANCH"
  },
  "runtime_environment": {
    "php_version": "$PHP_VERSION",
    "artisan_version": "$ARTISAN_VERSION",
    "docker_version": "$DOCKER_VERSION",
    "docker_compose_version": "$DOCKER_COMPOSE_VERSION",
    "mariadb_version": "$MARIADB_VERSION"
  },
  "artifact_checksums_sha256": {
    "docker_compose": {
      "path": "docker-compose.yml",
      "sha256": "$HASH_COMPOSE"
    },
    "security_research_seeder": {
      "path": "database/seeders/SecurityResearchSeeder.php",
      "sha256": "$HASH_SEEDER"
    },
    "testing_environment_config": {
      "path": ".env.testing",
      "sha256": "$HASH_ENV"
    }
  }
}
EOF

echo "[+] Manifest riil berhasil dibekukan ke: $OUTPUT_FILE"
cat "$OUTPUT_FILE"
