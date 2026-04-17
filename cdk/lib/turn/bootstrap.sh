#!/bin/bash
#
# coturn bootstrap for VettID TURN relay.
# Runs on every instance start via cloud-init user-data.
#
# Privacy-first defaults:
# - TURNS only (TLS-wrapped TURN on TCP/5349 and TCP/443)
# - Plain TURN on UDP/3478 + TCP/3478 (required for STUN binding discovery
#   by WebRTC clients; auth still uses HMAC so no anonymous relay)
# - Denies relay to RFC1918 / loopback / link-local peers (no internal scans)
# - Logs to stderr only; CloudWatch agent tails to /var/log/coturn.log
# - No long-term user DB — short-lived HMAC creds per call
#
# Required environment (injected by CDK via Mustache-style substitutions):
#   __REALM__           e.g. turn.vettid.dev
#   __SECRET_ARN__      ARN of the HMAC shared secret in Secrets Manager
#   __REGION__          AWS region
set -euo pipefail
exec > >(tee -a /var/log/vettid-turn-bootstrap.log) 2>&1

REALM="__REALM__"
SECRET_ARN="__SECRET_ARN__"
REGION="__REGION__"

echo "=== VettID TURN bootstrap starting ==="

# --- Packages ---------------------------------------------------------------
dnf -y update
# coturn and certbot are not in AL2023 default repos; pull them from Fedora
# EPEL 9. AL2023 binaries are compatible with EL9 userspace for everything
# coturn needs (OpenSSL, libevent, sqlite).
dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
dnf -y install coturn certbot jq awscli amazon-cloudwatch-agent bind-utils

# --- Public IP --------------------------------------------------------------
# The EIP is attached before cloud-init runs; IMDSv2 gives us the public IPv4.
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
PUBLIC_IP=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/public-ipv4)
echo "Public IP: $PUBLIC_IP"

# --- HMAC shared secret -----------------------------------------------------
# coturn reads auth-secret from the config file. Pull from Secrets Manager on
# every boot so rotation is a matter of updating the secret + bouncing the
# instance.
SECRET=$(aws secretsmanager get-secret-value \
    --secret-id "$SECRET_ARN" \
    --region "$REGION" \
    --query 'SecretString' --output text)
install -m 0600 -o turnserver -g turnserver /dev/null /etc/turnserver/auth-secret
printf "%s" "$SECRET" > /etc/turnserver/auth-secret
chmod 0600 /etc/turnserver/auth-secret
chown turnserver:turnserver /etc/turnserver/auth-secret

# --- TLS cert (Let's Encrypt) -----------------------------------------------
# Certbot in standalone mode runs a one-shot HTTP server on :80 to satisfy the
# ACME HTTP-01 challenge. After cert issuance, we hand off :80 to coturn so it
# can accept TURN-over-TCP on that port as well for restrictive networks.
#
# Race: EIP association, Route53 publication, and cloud-init all happen in
# parallel. We need our hostname's public A record to resolve to PUBLIC_IP on
# a resolver the Let's Encrypt validator can reach, otherwise the HTTP-01
# challenge fails. Poll up to ~5 minutes before giving up; make cert issuance
# non-fatal so a transient DNS miss doesn't wedge the whole instance.
CERT_DIR="/etc/letsencrypt/live/${REALM}"
if [[ ! -f "${CERT_DIR}/fullchain.pem" ]]; then
    echo "Waiting for DNS to advertise $REALM → $PUBLIC_IP ..."
    dns_ok=0
    for i in $(seq 1 30); do
        resolved=$(dig +short "$REALM" @1.1.1.1 | tail -n1 || true)
        if [[ "$resolved" == "$PUBLIC_IP" ]]; then
            echo "DNS ready after ${i} attempts"
            dns_ok=1
            break
        fi
        echo "  attempt $i: got '$resolved', want '$PUBLIC_IP'"
        sleep 10
    done

    if [[ $dns_ok -eq 1 ]]; then
        echo "Requesting cert from Let's Encrypt..."
        if ! certbot certonly --standalone --non-interactive --agree-tos \
            -m "ops@vettid.dev" -d "$REALM" \
            --preferred-challenges http; then
            echo "WARN: certbot failed — coturn will start without TLS. Re-run bootstrap after fixing DNS."
        fi
    else
        echo "WARN: DNS did not converge in time — skipping cert issuance. Re-run bootstrap later."
    fi
else
    echo "Cert already present at $CERT_DIR"
fi

# Let coturn read the certs (if present).
if [[ -f "${CERT_DIR}/fullchain.pem" ]]; then
    chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive
    chmod 0644 "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/privkey.pem" || true
    TLS_READY=1
else
    TLS_READY=0
fi

# --- coturn config ----------------------------------------------------------
# When TLS isn't ready yet we omit the TLS ports entirely; that way coturn
# comes up on plain TURN and we can re-run this bootstrap later to enable
# TURNS without breaking the service in the meantime.
if [[ $TLS_READY -eq 1 ]]; then
    TLS_PORTS_BLOCK=$'tls-listening-port=5349\nalt-tls-listening-port=443'
    TLS_CONFIG_BLOCK=$"cert=${CERT_DIR}/fullchain.pem
pkey=${CERT_DIR}/privkey.pem
no-tlsv1
no-tlsv1_1
cipher-list=\"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS\"
dh-file=/etc/turnserver/dhparam.pem"
else
    TLS_PORTS_BLOCK="# TLS not yet configured — re-run bootstrap once DNS is ready"
    TLS_CONFIG_BLOCK="# (no TLS — plain TURN only)"
fi

cat > /etc/turnserver.conf <<CONF
# VettID TURN relay — managed by bootstrap.sh. Do not hand-edit.

# Listen on all interfaces; external IP tells coturn what to advertise.
listening-ip=0.0.0.0
external-ip=${PUBLIC_IP}

# Standard STUN/TURN ports.
listening-port=3478
${TLS_PORTS_BLOCK}

# Realm + HMAC credential mode.
realm=${REALM}
use-auth-secret
static-auth-secret-file=/etc/turnserver/auth-secret

# Short-lived credentials: we issue these from the enclave parent with ~1h
# TTL. coturn enforces timestamp validity.
stale-nonce=600

# Relay range — coturn picks a UDP port per allocation from this range.
min-port=49152
max-port=65535

# SECURITY: block relay to internal/link-local/loopback addresses so the TURN
# server can't be used to scan private networks.
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.0.2.0-192.0.2.255
denied-peer-ip=192.88.99.0-192.88.99.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=198.51.100.0-198.51.100.255
denied-peer-ip=203.0.113.0-203.0.113.255
denied-peer-ip=240.0.0.0-255.255.255.255
# IPv6 equivalents
denied-peer-ip=::1
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
no-multicast-peers
no-loopback-peers

# TLS config — filled in above based on cert availability.
${TLS_CONFIG_BLOCK}

# Fingerprint messages (standard WebRTC requirement).
fingerprint

# Minimal process state — no CLI, no status console on public interfaces.
no-cli

# Logging: stderr only; minimal fields. CloudWatch agent picks up the file.
log-file=/var/log/coturn.log
no-stdout-log
simple-log
# Don't write user/IP unless debugging an incident.
CONF

# Generate DH params if missing and we're going to use TLS (slow first time,
# ~20s on t3.micro).
if [[ $TLS_READY -eq 1 && ! -f /etc/turnserver/dhparam.pem ]]; then
    echo "Generating DH parameters (one-time)..."
    openssl dhparam -out /etc/turnserver/dhparam.pem 2048
    chown turnserver:turnserver /etc/turnserver/dhparam.pem
fi

# --- Cert auto-renewal ------------------------------------------------------
# certbot provides a systemd timer on most distros, but double-check. Hook a
# coturn hot-reload on successful renewal.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-coturn.sh <<'HOOK'
#!/bin/bash
systemctl reload coturn || systemctl restart coturn
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-coturn.sh

systemctl enable --now certbot-renew.timer 2>/dev/null || \
    systemctl enable --now snap.certbot.renew.timer 2>/dev/null || true

# --- CloudWatch logs --------------------------------------------------------
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<'CWA'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {"file_path": "/var/log/coturn.log",
           "log_group_name": "vettid-turn",
           "log_stream_name": "{instance_id}/coturn"},
          {"file_path": "/var/log/vettid-turn-bootstrap.log",
           "log_group_name": "vettid-turn",
           "log_stream_name": "{instance_id}/bootstrap"}
        ]
      }
    }
  }
}
CWA
systemctl enable --now amazon-cloudwatch-agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config -m ec2 -s \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

# --- Start coturn -----------------------------------------------------------
systemctl enable --now coturn

echo "=== VettID TURN bootstrap complete ==="
systemctl status coturn --no-pager | head -20 || true
