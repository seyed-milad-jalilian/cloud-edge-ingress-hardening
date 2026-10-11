#!/usr/bin/env bash
set -Eeuo pipefail

readonly CHAIN="UER-INPUT"
SSH_PORT="${SSH_PORT:-22}"

usage() {
  printf 'Usage: sudo %s [--check]\n' "${0##*/}"
  printf 'Required: SSH_ADMIN_IPV4_CIDRS, EDGE_PROXY_IPV4_CIDRS\n'
  printf 'Optional: SSH_ADMIN_IPV6_CIDRS, EDGE_PROXY_IPV6_CIDRS, SSH_PORT\n'
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

check_only=0
if [[ "${1:-}" == "--check" && $# -eq 1 ]]; then
  check_only=1
elif [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

[[ "$(id -u)" -eq 0 ]] || die "run as root (for example, with sudo)"
if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
  die "SSH_PORT must be an integer between 1 and 65535"
fi

for command_name in iptables ip6tables iptables-restore ip6tables-restore mktemp; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

declare -a SSH_ADMIN_IPV4=()
# Referenced by name through the load_cidrs and write_ruleset namerefs.
# shellcheck disable=SC2034
declare -a SSH_ADMIN_IPV6=()
declare -a EDGE_PROXY_IPV4=()
# Referenced by name through the load_cidrs and write_ruleset namerefs.
# shellcheck disable=SC2034
declare -a EDGE_PROXY_IPV6=()

load_cidrs() {
  local variable_name="$1"
  local -n destination="$2"
  local raw_value="${!variable_name:-}"
  local value

  [[ -n "$raw_value" ]] || return 0
  [[ "$raw_value" != *$'\n'* && "$raw_value" != *$'\r'* ]] \
    || die "$variable_name must be a single-line comma-separated CIDR list"
  IFS=',' read -r -a destination <<< "$raw_value"
  for value in "${destination[@]}"; do
    value="${value//[[:space:]]/}"
    [[ -n "$value" ]] || die "$variable_name contains an empty CIDR"
    [[ "$value" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] \
      || die "$variable_name contains an invalid CIDR format"
  done
  destination=("${destination[@]//[[:space:]]/}")
}

load_cidrs SSH_ADMIN_IPV4_CIDRS SSH_ADMIN_IPV4
load_cidrs SSH_ADMIN_IPV6_CIDRS SSH_ADMIN_IPV6
load_cidrs EDGE_PROXY_IPV4_CIDRS EDGE_PROXY_IPV4
load_cidrs EDGE_PROXY_IPV6_CIDRS EDGE_PROXY_IPV6

((${#SSH_ADMIN_IPV4[@]} > 0)) || die "configure SSH_ADMIN_IPV4_CIDRS"
((${#EDGE_PROXY_IPV4[@]} > 0)) || die "configure EDGE_PROXY_IPV4_CIDRS"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_ruleset() {
  local family="$1"
  local output_file="$2"
  local ssh_cidrs_name="$3"
  local edge_cidrs_name="$4"
  local -n ssh_cidrs="$ssh_cidrs_name"
  local -n edge_cidrs="$edge_cidrs_name"
  local protocol="icmp"
  local cidr

  [[ "$family" == "ipv6" ]] && protocol="ipv6-icmp"

  {
    printf '*filter\n:%s - [0:0]\n-F %s\n' "$CHAIN" "$CHAIN"
    printf -- '-A %s -i lo -j ACCEPT\n' "$CHAIN"
    printf -- '-A %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n' "$CHAIN"
    printf -- '-A %s -p %s -j ACCEPT\n' "$CHAIN" "$protocol"
    for cidr in "${ssh_cidrs[@]}"; do
      printf -- '-A %s -p tcp -s %s --dport %s -m conntrack --ctstate NEW -j ACCEPT\n' \
        "$CHAIN" "$cidr" "$SSH_PORT"
    done
    for cidr in "${edge_cidrs[@]}"; do
      printf -- '-A %s -p tcp -s %s --dport 443 -m conntrack --ctstate NEW -j ACCEPT\n' \
        "$CHAIN" "$cidr"
    done
    printf -- '-A %s -j DROP\nCOMMIT\n' "$CHAIN"
  } > "$output_file"
}

write_ruleset ipv4 "$tmp_dir/ipv4.rules" SSH_ADMIN_IPV4 EDGE_PROXY_IPV4
write_ruleset ipv6 "$tmp_dir/ipv6.rules" SSH_ADMIN_IPV6 EDGE_PROXY_IPV6

iptables-restore --noflush --test < "$tmp_dir/ipv4.rules" \
  || die "IPv4 ruleset validation failed; no firewall rules were changed"
ip6tables-restore --noflush --test < "$tmp_dir/ipv6.rules" \
  || die "IPv6 ruleset validation failed; no firewall rules were changed"

if (( check_only )); then
  printf 'IPv4 and IPv6 firewall rulesets are valid; no firewall rules were changed.\n'
  exit 0
fi

ensure_chain() {
  local command_name="$1"
  if ! "$command_name" -S "$CHAIN" >/dev/null 2>&1; then
    "$command_name" -N "$CHAIN"
  fi
}

ensure_input_hook() {
  local command_name="$1"
  while "$command_name" -C INPUT -j "$CHAIN" >/dev/null 2>&1; do
    "$command_name" -D INPUT -j "$CHAIN"
  done
  "$command_name" -I INPUT 1 -j "$CHAIN"
}

ensure_chain iptables
ensure_chain ip6tables
iptables-restore --noflush < "$tmp_dir/ipv4.rules"
ip6tables-restore --noflush < "$tmp_dir/ipv6.rules"
ensure_input_hook iptables
ensure_input_hook ip6tables
iptables -P INPUT DROP
ip6tables -P INPUT DROP
iptables -P FORWARD DROP
ip6tables -P FORWARD DROP

printf 'IPv4 and IPv6 ingress firewall rules applied using chain %s.\n' "$CHAIN"
