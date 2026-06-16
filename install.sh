#!/bin/sh
# rsansible installer.
#
#   curl -fsSL https://raw.githubusercontent.com/serialexp/rsansible/main/install.sh | sh
#
# Downloads the latest release tarball for your platform, verifies its
# checksum, and installs the `rsansible` controller plus the
# `rsansible-agent` binary into ~/.local/bin (override with
# RSANSIBLE_INSTALL_DIR).
#
# Environment overrides:
#   RSANSIBLE_VERSION       pin a specific tag (e.g. v0.1.0). Default: latest.
#   RSANSIBLE_INSTALL_DIR   install destination. Default: ~/.local/bin.
#
# POSIX sh — no bash-isms, no jq, no GitHub API token required.

set -eu

REPO="serialexp/rsansible"
GITHUB="https://github.com"

# ---- pretty output ---------------------------------------------------------

# Colours only when stderr is a terminal.
if [ -t 2 ]; then
	BOLD="$(printf '\033[1m')"; RED="$(printf '\033[31m')"
	GREEN="$(printf '\033[32m')"; YELLOW="$(printf '\033[33m')"
	RESET="$(printf '\033[0m')"
else
	BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

info()  { printf '%s\n' "${BOLD}rsansible${RESET}: $*" >&2; }
warn()  { printf '%s\n' "${YELLOW}warning${RESET}: $*" >&2; }
err()   { printf '%s\n' "${RED}error${RESET}: $*" >&2; }
die()   { err "$@"; exit 1; }

# ---- prerequisites ---------------------------------------------------------

# Pick a downloader: curl preferred, wget fallback.
if command -v curl >/dev/null 2>&1; then
	DL="curl"
elif command -v wget >/dev/null 2>&1; then
	DL="wget"
else
	die "need either curl or wget on PATH"
fi

# fetch <url> <dest-file>  — download a URL to a file, following redirects.
fetch() {
	if [ "$DL" = "curl" ]; then
		curl -fsSL "$1" -o "$2"
	else
		wget -qO "$2" "$1"
	fi
}

# resolve_redirect <url>  — print the final URL after following redirects,
# without downloading the body. Used to discover the latest release tag.
resolve_redirect() {
	if [ "$DL" = "curl" ]; then
		curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"
	else
		# wget prints "Location:" lines for each hop on stderr with -S.
		wget -S --spider --max-redirect=10 "$1" 2>&1 \
			| awk 'tolower($1) == "location:" { print $2 }' \
			| tail -n 1
	fi
}

# ---- platform detection ----------------------------------------------------

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
	Linux)  os_part="unknown-linux-musl" ;;
	Darwin) os_part="apple-darwin" ;;
	*) die "unsupported OS '$os'. Build from source: ${GITHUB}/${REPO}" ;;
esac

case "$arch" in
	x86_64 | amd64)        arch_part="x86_64" ;;
	aarch64 | arm64)       arch_part="aarch64" ;;
	*) die "unsupported architecture '$arch'. Build from source: ${GITHUB}/${REPO}" ;;
esac

TARGET="${arch_part}-${os_part}"

# v1 ships three triples only. Reject the gaps explicitly (e.g. Intel mac)
# rather than 404 on a tarball that was never built.
case "$TARGET" in
	x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | aarch64-apple-darwin) ;;
	*)
		die "no prebuilt binary for ${TARGET} yet. Supported: \
x86_64-unknown-linux-musl, aarch64-unknown-linux-musl, aarch64-apple-darwin. \
Build from source: ${GITHUB}/${REPO}"
		;;
esac

# ---- version resolution ----------------------------------------------------

if [ "${RSANSIBLE_VERSION:-}" != "" ]; then
	TAG="$RSANSIBLE_VERSION"
	case "$TAG" in v*) ;; *) TAG="v$TAG" ;; esac
	info "installing pinned version ${BOLD}${TAG}${RESET}"
else
	info "resolving latest release..."
	# /releases/latest redirects to /releases/tag/<tag>; grab the tail.
	latest_url="$(resolve_redirect "${GITHUB}/${REPO}/releases/latest")"
	TAG="${latest_url##*/}"
	[ "${TAG#v}" != "$TAG" ] || die "could not resolve latest release tag \
(got '${TAG}'). Pin one with RSANSIBLE_VERSION=vX.Y.Z."
	info "latest is ${BOLD}${TAG}${RESET}"
fi

VERSION="${TAG#v}"
BASENAME="rsansible-${VERSION}-${TARGET}"
TARBALL="${BASENAME}.tar.gz"
BASE_URL="${GITHUB}/${REPO}/releases/download/${TAG}"

# ---- download + verify -----------------------------------------------------

TMP="$(mktemp -d "${TMPDIR:-/tmp}/rsansible-install.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM

info "downloading ${TARBALL}"
fetch "${BASE_URL}/${TARBALL}" "${TMP}/${TARBALL}" \
	|| die "download failed: ${BASE_URL}/${TARBALL}"

# Checksum verification. The release publishes a per-tarball .sha256 file.
if fetch "${BASE_URL}/${TARBALL}.sha256" "${TMP}/${TARBALL}.sha256" 2>/dev/null; then
	info "verifying checksum"
	expected="$(awk '{print $1}' "${TMP}/${TARBALL}.sha256")"
	if command -v sha256sum >/dev/null 2>&1; then
		actual="$(sha256sum "${TMP}/${TARBALL}" | awk '{print $1}')"
	elif command -v shasum >/dev/null 2>&1; then
		actual="$(shasum -a 256 "${TMP}/${TARBALL}" | awk '{print $1}')"
	else
		actual=""
		warn "no sha256sum/shasum available; skipping checksum verification"
	fi
	if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
		die "checksum mismatch for ${TARBALL}
  expected: ${expected}
  actual:   ${actual}"
	fi
else
	warn "no checksum file published for ${TARBALL}; skipping verification"
fi

# ---- extract + install -----------------------------------------------------

tar -xzf "${TMP}/${TARBALL}" -C "$TMP"
SRC="${TMP}/${BASENAME}"
[ -f "${SRC}/rsansible" ] || die "tarball missing 'rsansible' binary"
[ -f "${SRC}/rsansible-agent" ] || die "tarball missing 'rsansible-agent' binary"

INSTALL_DIR="${RSANSIBLE_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

install_bin() {
	# install(1) isn't guaranteed everywhere; cp + chmod is portable.
	cp "$1" "$2.tmp.$$"
	chmod 0755 "$2.tmp.$$"
	mv "$2.tmp.$$" "$2"
}

install_bin "${SRC}/rsansible" "${INSTALL_DIR}/rsansible"
install_bin "${SRC}/rsansible-agent" "${INSTALL_DIR}/rsansible-agent"

AGENT_PATH="${INSTALL_DIR}/rsansible-agent"

# ---- report ----------------------------------------------------------------

info "${GREEN}installed${RESET} rsansible ${VERSION} (${TARGET}) to ${INSTALL_DIR}"
info "  controller: ${INSTALL_DIR}/rsansible"
info "  agent:      ${AGENT_PATH}  (x86_64 musl — pushed to Linux targets)"

# PATH hint.
case ":${PATH}:" in
	*":${INSTALL_DIR}:"*) ;;
	*)
		warn "${INSTALL_DIR} is not on your PATH. Add it, e.g.:"
		printf '%s\n' "    export PATH=\"${INSTALL_DIR}:\$PATH\"" >&2
		;;
esac

cat >&2 <<EOF

Try a run (the agent path is required via -a):

    rsansible run \\
      -i inventory.yml \\
      -a ${AGENT_PATH} \\
      site.yml

Docs: ${GITHUB}/${REPO}
EOF
