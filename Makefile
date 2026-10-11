.PHONY: lint check test

SHELLCHECK ?= shellcheck
DOCKER ?= docker

lint:
	$(SHELLCHECK) --shell=bash --severity=style configs/netfilter-hardening.sh tests/integration.sh

check:
	bash -n configs/netfilter-hardening.sh tests/integration.sh

test:
	$(DOCKER) run --rm --cap-add=NET_ADMIN \
		--sysctl net.ipv6.conf.all.disable_ipv6=0 \
		--volume "$(CURDIR):/workspace:ro" \
		--workdir /workspace \
		ubuntu:24.04 \
		bash -euc 'apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install --yes iptables; bash tests/integration.sh'
