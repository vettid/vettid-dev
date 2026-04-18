#!/bin/bash
#
# coturn bootstrap for VettID TURN relay (Ubuntu 24.04 LTS).
# Runs on every instance start via cloud-init user-data.
#
# Why Ubuntu: AL2023 doesn't ship coturn and EPEL 9 can't install on it
# (requires redhat-release). Ubuntu's main repo has coturn, so we get
# distro-signed packages + automatic unattended-upgrades for security
# patches without maintaining a source build + checksum on every host.
#
# Privacy-first defaults:
# - TURNS (TLS) on 5349 and 443 (via iptables redirect)
# - Plain TURN on UDP/3478 + TCP/3478 for STUN binding + fallback; auth still
#   uses HMAC so no anonymous relay
# - Denies relay to RFC1918 / loopback / link-local peers (no internal scans)
# - CloudWatch agent tails /var/log/coturn.log
# - No long-term user DB — short-lived HMAC creds per call
#
# Required environment (injected by CDK via placeholder substitutions):
#   __REALM__           e.g. turn.vettid.dev
#   __SECRET_ARN__      ARN of the HMAC shared secret in Secrets Manager
#   __REGION__          AWS region
set -euo pipefail
exec > >(tee -a /var/log/vettid-turn-bootstrap.log) 2>&1

REALM="__REALM__"
SECRET_ARN="__SECRET_ARN__"
REGION="__REGION__"

echo "=== VettID TURN bootstrap starting ==="

export DEBIAN_FRONTEND=noninteractive

# --- Packages ---------------------------------------------------------------
apt-get update
apt-get install -y --no-install-recommends \
    coturn certbot \
    jq curl ca-certificates dnsutils \
    iptables-persistent \
    unattended-upgrades
# unattended-upgrades auto-installs security patches (including for coturn)
# without us shipping a new AMI. Default config covers -security sources.

# awscli on Ubuntu 24.04 repos is the v1 in "awscli" or we install v2 directly.
# Keep things simple — pull the v2 bundle from AWS.
if ! command -v aws >/dev/null 2>&1; then
    curl -fsSL -o /tmp/awscliv2.zip "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
    apt-get install -y unzip
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install --update
    rm -rf /tmp/aws /tmp/awscliv2.zip
fi

# CloudWatch agent (not in Ubuntu repos — pull the .deb from Amazon).
if ! command -v amazon-cloudwatch-agent-ctl >/dev/null 2>&1; then
    curl -fsSL -o /tmp/cwagent.deb \
        "https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb"
    dpkg -i /tmp/cwagent.deb
    rm /tmp/cwagent.deb
fi

# --- Public IP --------------------------------------------------------------
# The EIP is attached before cloud-init runs; IMDSv2 gives us the public IPv4.
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
PUBLIC_IP=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/public-ipv4)
echo "Public IP: $PUBLIC_IP"

# --- HMAC shared secret -----------------------------------------------------
# Pull from Secrets Manager on every boot so rotation is a matter of updating
# the secret + bouncing the instance.
SECRET=$(aws secretsmanager get-secret-value \
    --secret-id "$SECRET_ARN" \
    --region "$REGION" \
    --query 'SecretString' --output text)

# Ubuntu's coturn package creates a `turnserver` user/group automatically.
install -d -m 0750 -o turnserver -g turnserver /etc/turnserver
# Pre-create log file with turnserver ownership — coturn (dropping to
# turnserver) can't create /var/log/coturn.log itself.
touch /var/log/coturn.log
chown turnserver:turnserver /var/log/coturn.log
chmod 0640 /var/log/coturn.log

# --- TLS cert (Let's Encrypt) -----------------------------------------------
# Certbot in standalone mode runs a one-shot HTTP server on :80 to satisfy the
# ACME HTTP-01 challenge.
#
# Race: EIP association, Route53 publication, and cloud-init all happen in
# parallel. We need our hostname's public A record to resolve to PUBLIC_IP on
# a resolver the Let's Encrypt validator can reach, otherwise the HTTP-01
# challenge fails. Poll up to ~5 minutes before giving up; make cert issuance
# non-fatal so a transient DNS miss doesn't wedge the whole instance.
CERT_DIR="/etc/letsencrypt/live/${REALM}"
if [[ ! -f "${CERT_DIR}/fullchain.pem" ]]; then
    echo "Waiting for DNS to advertise $REALM -> $PUBLIC_IP ..."
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
            echo "WARN: certbot failed - coturn will start without TLS. Re-run bootstrap after fixing DNS."
        fi
    else
        echo "WARN: DNS did not converge in time - skipping cert issuance. Re-run bootstrap later."
    fi
else
    echo "Cert already present at $CERT_DIR"
fi

if [[ -f "${CERT_DIR}/fullchain.pem" ]]; then
    chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive
    chmod 0644 "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/privkey.pem" || true
    TLS_READY=1
else
    TLS_READY=0
fi

# --- coturn config ----------------------------------------------------------
# When TLS isn't ready yet we omit the TLS ports entirely so coturn still
# comes up on plain TURN; re-run bootstrap later to enable TURNS.
if [[ $TLS_READY -eq 1 ]]; then
    TLS_PORTS_BLOCK='tls-listening-port=5349'
    TLS_CONFIG_BLOCK="cert=${CERT_DIR}/fullchain.pem
pkey=${CERT_DIR}/privkey.pem
no-tlsv1
no-tlsv1_1
cipher-list=\"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS\"
dh-file=/etc/turnserver/dhparam.pem"
else
    TLS_PORTS_BLOCK='# TLS not yet configured - re-run bootstrap once DNS is ready'
    TLS_CONFIG_BLOCK='# (no TLS - plain TURN only)'
fi

# Config file will carry the inlined HMAC secret, so tighten perms.
umask 0037
cat > /etc/turnserver.conf <<CONF
# VettID TURN relay - managed by bootstrap.sh. Do not hand-edit.

# Listen on all interfaces; external IP tells coturn what to advertise.
listening-ip=0.0.0.0
external-ip=${PUBLIC_IP}

# Standard STUN/TURN ports.
listening-port=3478
${TLS_PORTS_BLOCK}

# Realm + HMAC credential mode. Distro coturn (Ubuntu 24.04 = 4.6.2) does not
# recognize static-auth-secret-file; use the inline form.
realm=${REALM}
use-auth-secret
static-auth-secret=${SECRET}

# Short-lived credentials: we issue these from the enclave parent with ~1h
# TTL. coturn enforces timestamp validity.
stale-nonce=600

# Relay range - coturn picks a UDP port per allocation from this range.
min-port=49152
max-port=65535

# SECURITY: block relay to internal/link-local/loopback addresses so the
# TURN server can't be used to scan private networks.
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

# Explicitly allow our own public IP as a valid peer address. Needed when
# two clients both terminate on this same coturn (mixed-relay ICE pair):
# each side's CREATE_PERMISSION carries the OTHER side's relay endpoint -
# which is this server's external-ip - and coturn would otherwise 403 on
# the self-reference.
allowed-peer-ip=${PUBLIC_IP}

# TLS config (may be a placeholder if cert issuance failed).
${TLS_CONFIG_BLOCK}

# Fingerprint messages (standard WebRTC requirement).
fingerprint

# Minimal process state - no CLI, no status console on public interfaces.
no-cli

# Logging: per-session lines, CloudWatch picks up the file.
log-file=/var/log/coturn.log
no-stdout-log
simple-log
CONF
umask 0022
chmod 0640 /etc/turnserver.conf
chown root:turnserver /etc/turnserver.conf

# Enable the Ubuntu coturn service. /etc/default/coturn has a
# TURNSERVER_ENABLED=1 flag that the init script checks.
if [[ -f /etc/default/coturn ]]; then
    sed -i 's/^#*TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/' /etc/default/coturn
    grep -q '^TURNSERVER_ENABLED=1' /etc/default/coturn || \
        echo 'TURNSERVER_ENABLED=1' >> /etc/default/coturn
fi

# Generate DH params if TLS is ready (~20s on t3.micro, one-time).
if [[ $TLS_READY -eq 1 && ! -f /etc/turnserver/dhparam.pem ]]; then
    echo "Generating DH parameters (one-time)..."
    openssl dhparam -out /etc/turnserver/dhparam.pem 2048
    chown turnserver:turnserver /etc/turnserver/dhparam.pem
fi

# --- iptables redirect for port 443 -----------------------------------------
# Restrictive networks (hotel WiFi, corporate) often allow only outbound 443.
# Redirect 443/TCP -> coturn's TURNS listener on 5349. Same cert / SNI.
if [[ $TLS_READY -eq 1 ]]; then
    iptables -t nat -C PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 5349 2>/dev/null || \
        iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 5349 || \
        echo "WARN: iptables rule add failed"
    # iptables-persistent saves to /etc/iptables/rules.v4 on package install;
    # write it explicitly so our rule survives reboot.
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
fi

# --- Cert auto-renewal ------------------------------------------------------
# Ubuntu ships certbot.timer enabled by default; just hook a coturn reload on
# successful renewal.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-coturn.sh <<'HOOK'
#!/bin/bash
systemctl reload coturn || systemctl restart coturn
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-coturn.sh
systemctl enable --now certbot.timer 2>/dev/null || true

# --- CloudWatch logs --------------------------------------------------------
mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
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
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json || true

# --- Start coturn -----------------------------------------------------------
systemctl enable --now coturn

echo "=== VettID TURN bootstrap complete ==="
systemctl status coturn --no-pager | head -20 || true
