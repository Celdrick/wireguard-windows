#!/usr/bin/env bash
# Cross-build WireGuard-GM for Windows: wireguard.exe + matching wintun.dll.
#
# Requires:
#   - github.com/emmansun/gmsm at ../gmsm
#   - golang.zx2c4.com/wireguard at ../wireguard-go (GM fork)
#
# Usage:
#   bash scripts/build-release.sh
#   TARGETS=windows-amd64 bash scripts/build-release.sh
#   VERSION=0.2.0-gm DIST=./dist bash scripts/build-release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${DIST:-$ROOT/dist}"
VERSION="${VERSION:-0.1.0-gm}"
TARGETS="${TARGETS:-windows-amd64 windows-arm64 windows-386}"
WINTUN_URL="${WINTUN_URL:-https://www.wintun.net/builds/wintun-0.14.1.zip}"
WINTUN_SHA256="${WINTUN_SHA256:-07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51}"

if [[ ! -f "$ROOT/../gmsm/go.mod" ]]; then
	echo "ERROR: expected gmsm at ../gmsm; clone https://github.com/emmansun/gmsm.git there" >&2
	exit 1
fi
if [[ ! -f "$ROOT/../wireguard-go/go.mod" ]]; then
	echo "ERROR: expected wireguard-go at ../wireguard-go; clone https://github.com/Celdrick/wireguard-go.git there" >&2
	exit 1
fi

mkdir -p "$DIST" "$ROOT/.distfiles"
cd "$ROOT"

wintun_zip="$ROOT/.distfiles/wintun.zip"
if [[ ! -f "$wintun_zip" ]]; then
	echo "==> downloading wintun..."
	curl -L#o "$wintun_zip.unverified" "$WINTUN_URL"
	echo "${WINTUN_SHA256}  $wintun_zip.unverified" | sha256sum -c
	mv "$wintun_zip.unverified" "$wintun_zip"
fi
if [[ ! -d "$ROOT/.deps/wintun/bin" ]]; then
	mkdir -p "$ROOT/.deps"
	rm -rf "$ROOT/.deps/wintun"
	if command -v bsdtar >/dev/null 2>&1; then
		bsdtar -C "$ROOT/.deps" -xf "$wintun_zip"
	elif command -v unzip >/dev/null 2>&1; then
		unzip -q -d "$ROOT/.deps" "$wintun_zip"
	else
		python3 -m zipfile -e "$wintun_zip" "$ROOT/.deps"
	fi
fi

wintun_dir() {
	case "$1" in
	amd64) echo amd64 ;;
	arm64) echo arm64 ;;
	386) echo x86 ;;
	*)
		echo "ERROR: no wintun.dll mapping for arch $1" >&2
		return 1
		;;
	esac
}

build_one() {
	local spec=$1
	local os=${spec%-*}
	local arch=${spec#*-}

	if [[ "$os" != "windows" ]]; then
		echo "ERROR: wireguard-windows only builds for windows (got $spec)" >&2
		exit 1
	fi

	local out="$DIST/windows-${arch}"
	mkdir -p "$out"

	echo "==> building windows/${arch}..."
	env CGO_ENABLED=0 GOOS=windows GOARCH="$arch" \
		go build -trimpath -ldflags "-H windowsgui -s -w" -buildvcs=false \
		-o "$out/wireguard.exe" ./

	# resources_<arch>.syso committed in-tree embeds the manifest (lxn/walk
	# requires the Common Controls v6 dependency) plus icons and version info.
	# Without it the UI process starts, fails window creation, and silently
	# retries forever. Fail the build here rather than shipping a broken exe.
	if ! grep -aq Common-Controls "$out/wireguard.exe"; then
		echo "ERROR: $out/wireguard.exe has no embedded manifest" >&2
		echo "       expected resources_${arch}.syso in the repo root to be linked automatically" >&2
		exit 1
	fi

	local wt_arch
	wt_arch="$(wintun_dir "$arch")"
	cp "$ROOT/.deps/wintun/bin/${wt_arch}/wintun.dll" "$out/wintun.dll"

	local tarball="$DIST/wireguard-windows-gm-${VERSION}-windows-${arch}.tar.gz"
	tar -C "$out" -czf "$tarball" wireguard.exe wintun.dll
	echo "    -> $tarball"
}

for spec in $TARGETS; do
	build_one "$spec"
done

echo ""
echo "Builds written to $DIST/"
