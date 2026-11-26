#!/usr/bin/env bash
# Builds the release archives of one version from a clean checkout into dist/VERSION:
# controller packages for Windows, macOS and Linux, runtime packages for Linux, and SHA256SUMS.
# No VPN config, key, state file, journal or credential goes into a package; every archive is
# checked against its exact member list before it is hashed.

set -euo pipefail

VERSION="${1:?Usage: build-release.sh VERSION}"

# Pre-release identifiers are non-empty and dot-separated (no trailing dot, which Windows drops).
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
    echo "Invalid release version" >&2
    exit 1
fi

# Checked first, so that a missing tool stops nothing half built.
for tool in git go tar gzip zip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "Missing required tool: sha256sum or shasum" >&2
    exit 1
fi

# Inherited archiver settings could drop or add members; macOS tar could add AppleDouble files.
unset TAR_OPTIONS ZIPOPT ZIP GZIP
export COPYFILE_DISABLE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"

if [[ -L "$ROOT/dist" ]]; then
    echo "dist must not be a symbolic link" >&2
    exit 1
fi

if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]]; then
    echo "Build releases from a clean checkout" >&2
    exit 1
fi

mkdir -p "$ROOT/dist"

OUT="$ROOT/dist/$VERSION"

# mkdir without -p reserves the version atomically: a second build of it stops here.
if ! mkdir "$OUT" 2>/dev/null; then
    echo "Release output already exists: $OUT" >&2
    exit 1
fi

STAGING=""
COMPLETE=0

cleanup() {
    if [[ -n "$STAGING" ]]; then
        rm -rf "$STAGING"
    fi

    # A failed build leaves no partial release behind.
    if [[ "$COMPLETE" != 1 ]]; then
        rm -rf "$OUT"
    fi
}
trap cleanup EXIT

STAGING="$(mktemp -d)"

GNU_TAR=0
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    GNU_TAR=1
fi

COMMON_FILES="LICENSE README.md RELEASE-INFO.txt docs/ARCHITECTURE.md docs/DEV-LINUX-VM.md docs/PRIVILEGED-HELPER.md"

# verify_archive ARCHIVE BINARY... requires exactly the common files and the binaries (and, in a
# zip, the docs/ entry; tarballs list no directory), and for a tarball executable binaries and
# uid and gid 0 in every header.
verify_archive() {
    local archive="$1"
    shift

    local expected actual

    if [[ "$archive" == *.zip ]]; then
        expected="$(printf '%s\n' $COMMON_FILES docs/ "$@" | sort)"
        actual="$(zip -sf "$archive" | sed -n 's/^  //p' | sort)"
    else
        expected="$(printf '%s\n' $COMMON_FILES "$@" | sort)"
        actual="$(tar -tzf "$archive" | sort)"

        # Numeric, so that a name cannot stand in for another uid or gid.
        local listing
        listing="$(tar --numeric-owner -tvzf "$archive")"

        for binary in "$@"; do
            if ! grep -E "^-rwxr-xr-x .* $binary\$" <<<"$listing" >/dev/null; then
                echo "Not executable in $archive: $binary" >&2
                exit 1
            fi
        done

        # GNU tar lists "uid/gid" in the second field, BSD tar lists them third and fourth.
        local foreign
        foreign="$(awk '!($2 == "0/0" || ($3 == "0" && $4 == "0"))' <<<"$listing")"

        if [[ -n "$foreign" ]]; then
            echo "Unexpected owner in $archive" >&2
            exit 1
        fi
    fi

    if [[ "$actual" != "$expected" ]]; then
        echo "Unexpected members in $archive:" >&2
        diff <(echo "$expected") <(echo "$actual") >&2 || true
        exit 1
    fi
}

build_package() {
    local role="$1"
    local os="$2"
    local arch="$3"
    local module="$4"

    shift 4

    local name="egresslab-${role}-${os}-${arch}"
    local dir="$STAGING/$name"
    local ext=""
    local binaries=()

    if [[ "$os" == "windows" ]]; then
        ext=".exe"
    fi

    mkdir -p "$dir"

    for cmd in "$@"; do
        echo "Building $cmd for $os/$arch"

        (
            cd "$ROOT/$module"

            GOOS="$os" \
            GOARCH="$arch" \
            CGO_ENABLED=0 \
            go build \
                -trimpath \
                -buildvcs=true \
                -o "$dir/$cmd$ext" \
                "./cmd/$cmd"
        )

        binaries+=("$cmd$ext")
    done

    printf 'version=%s\ncommit=%s\nrole=%s\ngoos=%s\ngoarch=%s\n' \
        "$VERSION" "$COMMIT" "$role" "$os" "$arch" \
        > "$dir/RELEASE-INFO.txt"

    cp "$ROOT/LICENSE" "$dir/"
    cp "$ROOT/README.md" "$dir/"

    # The README's guide links, readable offline.
    mkdir -p "$dir/docs"

    cp "$ROOT/docs/DEV-LINUX-VM.md" "$dir/docs/"
    cp "$ROOT/docs/ARCHITECTURE.md" "$dir/docs/"
    cp "$ROOT/docs/PRIVILEGED-HELPER.md" "$dir/docs/"

    if [[ "$os" == "windows" ]]; then
        # -X leaves out the builder's uid and gid.
        (
            cd "$dir"
            zip -qrX "$OUT/$name.zip" ./*
        )
    else
        local tarball="$STAGING/$name.tar"

        if [[ "$GNU_TAR" == 1 ]]; then
            # Modes set here, not taken from the filesystem: a Windows mount may show no execute bit.
            tar -C "$dir" --owner=0 --group=0 --numeric-owner --mode=0644 \
                -cf "$tarball" $COMMON_FILES
            tar -C "$dir" --owner=0 --group=0 --numeric-owner --mode=0755 \
                -rf "$tarball" "${binaries[@]}"
        else
            chmod 0644 "$dir"/LICENSE "$dir"/README.md "$dir"/RELEASE-INFO.txt "$dir"/docs/*
            chmod 0755 "$dir/docs" "${binaries[@]/#/$dir/}"
            tar -C "$dir" --uid 0 --gid 0 --uname root --gname root \
                -cf "$tarball" $COMMON_FILES "${binaries[@]}"
        fi

        gzip -n -c "$tarball" > "$OUT/$name.tar.gz"
    fi

    if [[ "$os" == "windows" ]]; then
        verify_archive "$OUT/$name.zip" "${binaries[@]}"
    else
        verify_archive "$OUT/$name.tar.gz" "${binaries[@]}"
    fi
}

for os in windows darwin linux; do
    for arch in amd64 arm64; do
        build_package \
            controller "$os" "$arch" \
            services/controller \
            egresslab-controller \
            egresslab-controller-lab
    done
done

for arch in amd64 arm64; do
    build_package \
        runtime linux "$arch" \
        services/network-agent \
        egresslab-agent \
        egresslab-helper \
        egresslab-helperctl \
        egresslab-probe \
        egresslab-proxy-dial \
        egresslab-lab-recover
done

(
    cd "$OUT"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum ./*.zip ./*.tar.gz > SHA256SUMS
    else
        shasum -a 256 ./*.zip ./*.tar.gz > SHA256SUMS
    fi
)

COMPLETE=1

echo "Release packages built: $OUT"
