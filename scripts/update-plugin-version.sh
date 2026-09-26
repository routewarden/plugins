#!/usr/bin/env bash
# scripts/update-plugin-version.sh
# RouteWarden Plugin Release Version Synchronization Script
#
# Usage:
#   ./scripts/update-plugin-version.sh                           # Display all current plugin versions
#   ./scripts/update-plugin-version.sh <plugin-name> <version>   # Updates a specific plugin's version
#   ./scripts/update-plugin-version.sh --all <version>           # Updates all plugins to specified version
#   ./scripts/update-plugin-version.sh --check                   # Verifies all plugins have valid SemVer
#
# Examples:
#   ./scripts/update-plugin-version.sh postgres 1.1.0
#   ./scripts/update-plugin-version.sh redis v1.0.1
#   ./scripts/update-plugin-version.sh --all 1.0.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Helper for cross-platform in-place sed (macOS BSD sed vs Linux GNU sed)
sed_inplace() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' -E "$@"
  else
    sed -i -E "$@"
  fi
}

get_plugin_version() {
  local manifest="$1"
  grep -E '^[[:space:]]*version:' "$manifest" | head -n1 | sed -E 's/^[[:space:]]*version:[[:space:]]*["'\'']?([^"'\'']+)["'\'']?.*/\1/' || echo ""
}

get_manifest_version() {
  local manifest="$1"
  grep -E '^[[:space:]]*manifest_version:' "$manifest" | head -n1 | sed -E 's/^[[:space:]]*manifest_version:[[:space:]]*["'\'']?([^"'\'']+)["'\'']?.*/\1/' || echo ""
}

# 1. Inspect / Check mode
if [ $# -eq 0 ] || [ "${1:-}" = "--check" ] || [ "${1:-}" = "-c" ] || [ "${1:-}" = "--list" ]; then
  echo "🔍 RouteWarden Plugin Versions:"
  echo ""
  printf "%-16s %-14s %-16s %s\n" "PLUGIN" "VERSION" "MANIFEST_VER" "STATUS"
  printf "%-16s %-14s %-16s %s\n" "------" "-------" "------------" "------"

  INVALID_COUNT=0
  for dir in "${ROOT_DIR}"/*/; do
    manifest="${dir}plugin.yaml"
    if [ ! -f "$manifest" ]; then
      manifest="${dir}plugin.yml"
    fi
    if [ -f "$manifest" ]; then
      pname="$(basename "$dir")"
      ver=$(get_plugin_version "$manifest")
      mver=$(get_manifest_version "$manifest")

      if [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
        printf "%-16s %-14s %-16s %s\n" "$pname" "$ver" "$mver" "✓ Valid"
      else
        printf "%-16s %-14s %-16s %s\n" "$pname" "${ver:-missing}" "$mver" "❌ Invalid SemVer"
        INVALID_COUNT=$((INVALID_COUNT + 1))
      fi
    fi
  done

  echo ""
  if [ $INVALID_COUNT -gt 0 ]; then
    echo "❌ Error: $INVALID_COUNT plugin(s) have missing or invalid SemVer versions."
    exit 1
  else
    echo "✓ All plugin versions are valid SemVer."
    exit 0
  fi
fi

# 2. Parse arguments
TARGET_PLUGIN=""
RAW_VERSION=""

if [ "$1" = "--all" ] || [ "$1" = "-a" ]; then
  if [ $# -lt 2 ]; then
    echo "❌ Error: Missing version argument for --all."
    echo "Usage: $0 --all <version>"
    exit 1
  fi
  TARGET_PLUGIN="--all"
  RAW_VERSION="$2"
else
  if [ $# -lt 2 ]; then
    echo "❌ Error: Missing arguments."
    echo "Usage:"
    echo "  $0 <plugin-name> <version>"
    echo "  $0 --all <version>"
    exit 1
  fi
  TARGET_PLUGIN="$1"
  RAW_VERSION="$2"
fi

# Strip leading 'v'
VERSION="${RAW_VERSION#v}"

# Validate SemVer pattern
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "❌ Error: Invalid semantic version format: '$RAW_VERSION'"
  echo "Expected format: MAJOR.MINOR.PATCH (e.g. 1.0.0, 1.2.0, 2.0.0-rc.1)"
  exit 1
fi

update_version() {
  local pdir="$1"
  local manifest="${pdir}/plugin.yaml"
  if [ ! -f "$manifest" ]; then
    manifest="${pdir}/plugin.yml"
  fi

  if [ ! -f "$manifest" ]; then
    return
  fi

  local pname
  pname="$(basename "$pdir")"
  local old_ver
  old_ver=$(get_plugin_version "$manifest")

  # Update version: without matching manifest_version:
  sed_inplace "s|^([[:space:]]*version:[[:space:]]*).*|\1\"${VERSION}\"|g" "$manifest"

  echo "  ✓ [${pname}] ${old_ver} -> ${VERSION}"
}

if [ "$TARGET_PLUGIN" = "--all" ]; then
  echo "🔄 Updating all plugins to version: ${VERSION}"
  COUNT=0
  for dir in "${ROOT_DIR}"/*/; do
    if [ -d "$dir" ] && [ "$(basename "$dir")" != ".github" ] && [ "$(basename "$dir")" != "scripts" ]; then
      update_version "$dir"
      COUNT=$((COUNT + 1))
    fi
  done
  echo ""
  echo "✨ Successfully updated ${COUNT} plugin(s) to version \"${VERSION}\"!"
else
  pdir="${ROOT_DIR}/${TARGET_PLUGIN}"
  if [ ! -d "$pdir" ]; then
    echo "❌ Error: Plugin directory '${TARGET_PLUGIN}' not found in ${ROOT_DIR}"
    exit 1
  fi
  echo "🔄 Updating plugin '${TARGET_PLUGIN}' version to: ${VERSION}"
  update_version "$pdir"
  echo ""
  echo "✨ Successfully updated '${TARGET_PLUGIN}' to version \"${VERSION}\"!"
fi

echo "👉 Next steps:"
echo "   git diff"
echo "   git commit -am 'chore: bump ${TARGET_PLUGIN} version to ${VERSION}'"
