#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FIREWALL_SCRIPT="$ROOT_DIR/configs/netfilter-hardening.sh"
TEMP_DIR="$(mktemp -d)"
readonly ROOT_DIR TEMP_DIR
trap 'rm -rf "$TEMP_DIR"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_rule() {
  local rules="$1"
  local expected="$2"
  grep -Fqx -- "$expected" <<< "$rules" || fail "missing firewall rule: $expected"
}

assert_stateful_rule() {
  local rules="$1"
  grep -Eq -- '^-A UER-INPUT -m conntrack --ctstate (ESTABLISHED,RELATED|RELATED,ESTABLISHED) -j ACCEPT$' \
    <<< "$rules" || fail "missing established/related conntrack rule"
}

assert_tcp_allow_rule() {
  local table="$1"
  local source_cidr="$2"
  local destination_port="$3"
  "$table" -C UER-INPUT -p tcp -s "$source_cidr" --dport "$destination_port" \
    -m conntrack --ctstate NEW -j ACCEPT \
    || fail "missing $table TCP allow rule for $source_cidr:$destination_port"
}

expect_failure() {
  local description="$1"
  shift
  if "$@" >"$TEMP_DIR/command.log" 2>&1; then
    fail "expected failure: $description"
  fi
}

export SSH_ADMIN_IPV4_CIDRS="192.0.2.10/32,192.0.2.20/32"
export EDGE_PROXY_IPV4_CIDRS="198.51.100.0/24,203.0.113.0/24"
export SSH_ADMIN_IPV6_CIDRS="2001:db8::10/128,2001:db8::20/128"
export EDGE_PROXY_IPV6_CIDRS="2001:db8:100::/48,2001:db8:200::/48"
export SSH_PORT=2222

command -v iptables >/dev/null || fail "iptables is required"
command -v ip6tables >/dev/null || fail "ip6tables is required"
command -v iptables-save >/dev/null || fail "iptables-save is required"
command -v ip6tables-save >/dev/null || fail "ip6tables-save is required"
[[ "$(id -u)" -eq 0 ]] || fail "integration tests must run as root in an isolated container"

iptables-save > "$TEMP_DIR/ipv4.before"
ip6tables-save > "$TEMP_DIR/ipv6.before"

bash "$FIREWALL_SCRIPT" --check
iptables-save > "$TEMP_DIR/ipv4.after-check"
ip6tables-save > "$TEMP_DIR/ipv6.after-check"
diff -u "$TEMP_DIR/ipv4.before" "$TEMP_DIR/ipv4.after-check"
diff -u "$TEMP_DIR/ipv6.before" "$TEMP_DIR/ipv6.after-check"

expect_failure "malformed IPv4 CIDR" env \
  SSH_ADMIN_IPV4_CIDRS="192.0.2.1/not-a-prefix" \
  bash "$FIREWALL_SCRIPT" --check
expect_failure "multiline CIDR injection" env \
  SSH_ADMIN_IPV4_CIDRS=$'192.0.2.1/32\n-A UER-INPUT -j ACCEPT' \
  bash "$FIREWALL_SCRIPT" --check
expect_failure "invalid SSH port" env SSH_PORT=65536 \
  bash "$FIREWALL_SCRIPT" --check
expect_failure "missing required IPv4 administrator CIDR" env \
  SSH_ADMIN_IPV4_CIDRS= \
  bash "$FIREWALL_SCRIPT" --check

iptables-save > "$TEMP_DIR/ipv4.after-invalid"
ip6tables-save > "$TEMP_DIR/ipv6.after-invalid"
diff -u "$TEMP_DIR/ipv4.before" "$TEMP_DIR/ipv4.after-invalid"
diff -u "$TEMP_DIR/ipv6.before" "$TEMP_DIR/ipv6.after-invalid"

bash "$FIREWALL_SCRIPT"

ipv4_rules="$(iptables -S UER-INPUT)"
assert_rule "$ipv4_rules" "-A UER-INPUT -i lo -j ACCEPT"
assert_stateful_rule "$ipv4_rules"
assert_rule "$ipv4_rules" "-A UER-INPUT -p icmp -j ACCEPT"
assert_rule "$ipv4_rules" "-A UER-INPUT -j DROP"
assert_tcp_allow_rule iptables 192.0.2.10/32 2222
assert_tcp_allow_rule iptables 192.0.2.20/32 2222
assert_tcp_allow_rule iptables 198.51.100.0/24 443
assert_tcp_allow_rule iptables 203.0.113.0/24 443

ipv6_rules="$(ip6tables -S UER-INPUT)"
assert_rule "$ipv6_rules" "-A UER-INPUT -i lo -j ACCEPT"
assert_stateful_rule "$ipv6_rules"
assert_rule "$ipv6_rules" "-A UER-INPUT -p ipv6-icmp -j ACCEPT"
assert_rule "$ipv6_rules" "-A UER-INPUT -j DROP"
assert_tcp_allow_rule ip6tables 2001:db8::10/128 2222
assert_tcp_allow_rule ip6tables 2001:db8::20/128 2222
assert_tcp_allow_rule ip6tables 2001:db8:100::/48 443
assert_tcp_allow_rule ip6tables 2001:db8:200::/48 443

assert_rule "$(iptables -S INPUT)" "-P INPUT DROP"
assert_rule "$(iptables -S FORWARD)" "-P FORWARD DROP"
assert_rule "$(ip6tables -S INPUT)" "-P INPUT DROP"
assert_rule "$(ip6tables -S FORWARD)" "-P FORWARD DROP"

[[ "$(iptables -S INPUT | grep -Fxc -- '-A INPUT -j UER-INPUT')" -eq 1 ]] \
  || fail "IPv4 INPUT must contain exactly one managed-chain hook"
[[ "$(ip6tables -S INPUT | grep -Fxc -- '-A INPUT -j UER-INPUT')" -eq 1 ]] \
  || fail "IPv6 INPUT must contain exactly one managed-chain hook"

bash "$FIREWALL_SCRIPT"
[[ "$(iptables -S INPUT | grep -Fxc -- '-A INPUT -j UER-INPUT')" -eq 1 ]] \
  || fail "reapplying must not duplicate the IPv4 managed-chain hook"
[[ "$(ip6tables -S INPUT | grep -Fxc -- '-A INPUT -j UER-INPUT')" -eq 1 ]] \
  || fail "reapplying must not duplicate the IPv6 managed-chain hook"

printf 'PASS: firewall input validation, check mode, IPv4/IPv6 rules, default policies, and idempotent hooks.\n'
