# Cloud Edge Routing and Host Hardening

An infrastructure reference project for protecting an Ubuntu origin host behind a Cloudflare reverse proxy on Oracle Cloud Infrastructure (OCI). It documents the intended traffic flow and provides a configurable, dual-stack Netfilter baseline and Linux network-tuning profile.

> **Scope:** This repository provides host-level configuration and an operational runbook. It does not provision OCI resources, install an application or origin certificate, configure Cloudflare, or implement routing/NAT rules. The diagram describes the intended deployment, not evidence of a live deployment.

## Architecture

![Reference architecture](assets/edge-network-traffic.svg)

The OCI network security group (or security list) and the host firewall should enforce the same ingress boundary: SSH only from administrator CIDRs, and TCP 443 only from Cloudflare's currently published proxy ranges. Do not expose the origin directly to arbitrary Internet sources. Keep the OCI rules and host rules in sync when source ranges change.

The firewall script installs an idempotent `UER-INPUT` chain before other `INPUT` rules, permits loopback and established connections, allows SSH and HTTPS only from configured source CIDRs, and drops other inbound traffic. It handles IPv4 and IPv6 independently and sets both `INPUT` and `FORWARD` policies to `DROP`. Outbound traffic is left to the existing system policy. This repository does not add forwarding or NAT allow rules. The sysctl profile enables kernel forwarding, but that alone does not make this host a router.

## Repository contents

| Path | Purpose |
| --- | --- |
| `configs/netfilter-hardening.sh` | Configurable IPv4/IPv6 host firewall baseline |
| `configs/sysctl-tuning.conf` | Linux forwarding, BBR, TCP resilience, and buffer settings |
| `assets/edge-network-traffic.svg` | Architecture illustration |
| `.github/workflows/validate.yml` | Bash syntax and ShellCheck checks |

## Requirements

- Ubuntu/Linux with Bash, `iptables`, `ip6tables`, and their `*-restore` commands.
- Root access and out-of-band console access before applying firewall changes.
- Explicit IPv4 CIDR allow-lists for administrator SSH sources and Cloudflare proxy sources.
- If IPv6 is enabled for the host, configure the corresponding IPv6 CIDR allow-lists too. Leaving an IPv6 allow-list empty blocks SSH/HTTPS over IPv6.

The script does not download Cloudflare ranges or infer administrator addresses. Obtain current ranges from Cloudflare's official IP address documentation and review them before applying. Never use `0.0.0.0/0` or `::/0` for the SSH allow-list.

## Deployment runbook

### 1. Configure OCI ingress

In the host's OCI network security group/security list, allow TCP 22 only from administrator CIDRs and TCP 443 only from Cloudflare's published proxy CIDRs. Add corresponding IPv6 rules only when IPv6 is intentionally enabled. Do not open UDP 443 unless the selected origin service specifically requires it.

### 2. Back up the current firewall and sysctl configuration

Keep an active SSH session and OCI serial-console/recovery access throughout the change. Store backups outside the repository:

```bash
sudo sh -c 'iptables-save > /root/iptables.before'
sudo sh -c 'ip6tables-save > /root/ip6tables.before'
if sudo test -e /etc/sysctl.d/90-edge-routing.conf; then
  sudo cp -a /etc/sysctl.d/90-edge-routing.conf /root/90-edge-routing.conf.before
fi
sudo sh -c '
for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.core.default_qdisc \
  net.ipv4.tcp_congestion_control net.ipv4.tcp_fastopen net.ipv4.tcp_keepalive_time \
  net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.core.rmem_max net.core.wmem_max \
  net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog; do
  printf "%s = %s\n" "$key" "$(sysctl -n "$key")"
done > /root/edge-routing-sysctl.before
'
```

If `/etc/sysctl.d/90-edge-routing.conf` already exists, back it up separately before replacing it.

### 3. Validate and apply the firewall

Set the allow-lists for the actual host; the example values below are deliberately placeholders and must be replaced:

```bash
export SSH_ADMIN_IPV4_CIDRS="198.51.100.25/32"
export EDGE_PROXY_IPV4_CIDRS="203.0.113.0/24"
# Optional; set these to approved IPv6 CIDRs when IPv6 ingress is enabled:
export SSH_ADMIN_IPV6_CIDRS=""
export EDGE_PROXY_IPV6_CIDRS=""

sudo --preserve-env=SSH_ADMIN_IPV4_CIDRS,SSH_ADMIN_IPV6_CIDRS,EDGE_PROXY_IPV4_CIDRS,EDGE_PROXY_IPV6_CIDRS \
  bash configs/netfilter-hardening.sh --check
sudo --preserve-env=SSH_ADMIN_IPV4_CIDRS,SSH_ADMIN_IPV6_CIDRS,EDGE_PROXY_IPV4_CIDRS,EDGE_PROXY_IPV6_CIDRS \
  bash configs/netfilter-hardening.sh
```

Use real CIDRs before deployment. The `--check` mode validates both generated rulesets without changing firewall rules. The apply mode preserves unrelated filter-table chains, attaches its managed chain at the start of `INPUT`, and sets IPv4/IPv6 `INPUT` and `FORWARD` policies to `DROP`. It intentionally blocks other inbound services and forwarded traffic unless permitted by the managed chain or earlier rules. Review existing firewall managers, allow rules, and forwarding requirements before applying; do not run alongside another tool that owns these policies.

### 4. Apply and verify kernel settings

```bash
sudo install -m 0644 configs/sysctl-tuning.conf /etc/sysctl.d/90-edge-routing.conf
sudo sysctl --system
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc
sudo iptables -S UER-INPUT
sudo ip6tables -S UER-INPUT
```

Confirm SSH remains available from an approved address in a second session before closing the original session. Verify TCP 443 is reachable through Cloudflare and not directly from an unapproved source. Confirm the application itself is listening and has a valid origin TLS configuration; these are deployment prerequisites, not configured by this repository.

BBR must be available in the running kernel. If `sysctl --system` reports that a setting is unsupported, do not assume the tuning was applied; check the kernel and distribution support before proceeding.

### 5. Recovery and rollback

Use the OCI serial console or another out-of-band access path if SSH is lost. Restore firewall snapshots with:

```bash
sudo iptables-restore < /root/iptables.before
sudo ip6tables-restore < /root/ip6tables.before
```

Restore the prior sysctl profile if one existed; otherwise remove the profile installed by this project. Then reload the system settings and restore the captured runtime values:

```bash
if sudo test -e /root/90-edge-routing.conf.before; then
  sudo cp -a /root/90-edge-routing.conf.before /etc/sysctl.d/90-edge-routing.conf
else
  sudo rm -f /etc/sysctl.d/90-edge-routing.conf
fi
sudo sysctl --system
sudo sysctl -p /root/edge-routing-sysctl.before
```

Re-check effective values after rollback.

## Local validation

```bash
bash -n configs/netfilter-hardening.sh
shellcheck -s bash configs/netfilter-hardening.sh
```

The GitHub Actions workflow runs these checks on pushes and pull requests. It validates shell syntax and lint only; it does not apply configuration, emulate a live firewall, or validate an OCI deployment.

## Resume alignment

The current repository supports claims about designing a reference architecture, writing host-hardening and kernel-tuning configurations, documenting operations, and adding automated Bash validation/ShellCheck CI. It does **not** demonstrate a live OCI deployment, actual traffic validation, Cloudflare/TLS configuration, or a recovery exercise. Do not claim those until they have been performed and recorded in the real environment.

If the work so far is repository-only, a defensible résumé version is:

**Cloud Edge Infrastructure & Network Hardening**<br>
**Independent Cloud Engineering Project | OCI reference architecture | Italy | Jan 2026 – Feb 2026**

- Designed a reference edge-ingress architecture for an Ubuntu origin behind Cloudflare on OCI.
- Developed a configurable dual-stack Netfilter baseline with stateful filtering, CIDR-restricted SSH/HTTPS, and default-deny inbound and forwarded traffic.
- Prepared Linux sysctl tuning for IPv4/IPv6 forwarding, TCP BBR, and TCP resilience settings.
- Documented prerequisites, deployment, verification, recovery, and rollback procedures.
- Added GitHub Actions checks for Bash syntax and ShellCheck linting.

Keep “deployed” and “validated on live OCI instances” out unless that work has actually been completed; the workflow also needs a successful run before describing its checks as passing.

## License

MIT. See [`LICENSE`](LICENSE).

---

Architected and maintained by [Milad](https://github.com/seyed-milad-jalilian).
