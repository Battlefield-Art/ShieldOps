#!/usr/bin/env bash
#
# verify_tls.sh — TLS 1.3 + cipher hardening + cert + headers verification.
#
# Usage:   ./scripts/security/verify_tls.sh [hostname]
# Example: ./scripts/security/verify_tls.sh api.shieldops.io
#
# Exits 0 on full pass, 1 on any failure. Designed to run as part of the
# SOC 2 evidence-collection automation and pentest pre-engagement check.

set -uo pipefail

HOST="${1:-api.shieldops.io}"
PORT="${2:-443}"
PASS=0
FAIL=0

green() { printf "\033[32m✓ %s\033[0m\n" "$*"; PASS=$((PASS+1)); }
red()   { printf "\033[31m✗ %s\033[0m\n" "$*"; FAIL=$((FAIL+1)); }

echo "TLS verification for $HOST:$PORT"
echo "================================"

# 1. TLS 1.3 supported
if echo | openssl s_client -tls1_3 -connect "$HOST:$PORT" -servername "$HOST" </dev/null 2>/dev/null | grep -q "TLSv1.3"; then
    green "TLS 1.3 supported"
else
    red "TLS 1.3 NOT supported"
fi

# 2. TLS 1.0 / 1.1 NOT supported (deprecated)
for version in tls1 tls1_1; do
    if echo | openssl s_client -$version -connect "$HOST:$PORT" -servername "$HOST" </dev/null 2>&1 | grep -q "Cipher.*0000"; then
        green "$version correctly disabled"
    else
        result=$(echo | openssl s_client -$version -connect "$HOST:$PORT" -servername "$HOST" </dev/null 2>&1 | grep -o "Cipher.*" | head -1)
        if [ -z "$result" ] || echo "$result" | grep -q "0000"; then
            green "$version correctly disabled"
        else
            red "$version is enabled (should be disabled): $result"
        fi
    fi
done

# 3. Certificate is valid (not self-signed, not expired)
CERT_INFO=$(echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null)
if echo "$CERT_INFO" | grep -q "issuer="; then
    ISSUER=$(echo "$CERT_INFO" | grep "issuer=" | head -1)
    if echo "$ISSUER" | grep -qi "self-signed"; then
        red "Certificate is self-signed: $ISSUER"
    else
        green "Certificate issuer OK: $ISSUER"
    fi

    NOT_AFTER=$(echo "$CERT_INFO" | grep "notAfter=" | sed 's/notAfter=//')
    EXPIRY_EPOCH=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$NOT_AFTER" +%s 2>/dev/null || date -d "$NOT_AFTER" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    if [ -n "$EXPIRY_EPOCH" ] && [ "$EXPIRY_EPOCH" -gt "$NOW_EPOCH" ]; then
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        if [ "$DAYS_LEFT" -gt 30 ]; then
            green "Certificate valid for $DAYS_LEFT more days"
        else
            red "Certificate expires in $DAYS_LEFT days (renew soon)"
        fi
    else
        red "Certificate is expired or unparseable: $NOT_AFTER"
    fi
else
    red "Could not retrieve certificate info"
fi

# 4. HSTS header present and includes max-age >= 6 months
HSTS=$(curl -sI "https://$HOST/" | grep -i "^strict-transport-security:" | tr -d '\r')
if [ -n "$HSTS" ]; then
    MAX_AGE=$(echo "$HSTS" | grep -oE "max-age=[0-9]+" | cut -d= -f2)
    if [ -n "$MAX_AGE" ] && [ "$MAX_AGE" -ge 15768000 ]; then
        green "HSTS present with max-age >= 6 months ($MAX_AGE)"
    else
        red "HSTS present but max-age too low ($MAX_AGE; need >= 15768000)"
    fi
else
    red "HSTS header missing"
fi

# 5. Other recommended security headers
for header in "x-content-type-options:" "x-frame-options:" "content-security-policy:" "referrer-policy:"; do
    if curl -sI "https://$HOST/" | grep -qi "^$header"; then
        green "Header present: $header"
    else
        red "Header missing: $header"
    fi
done

# 6. No weak ciphers offered
WEAK_CIPHERS=$(nmap --script ssl-enum-ciphers -p "$PORT" "$HOST" 2>/dev/null | grep -E "weak|broken" || true)
if [ -z "$WEAK_CIPHERS" ]; then
    green "No weak ciphers detected (or nmap unavailable)"
else
    red "Weak ciphers detected:"
    echo "$WEAK_CIPHERS"
fi

echo "================================"
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
