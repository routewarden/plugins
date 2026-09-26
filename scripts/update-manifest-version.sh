#!/usr/bin/env bash
# scripts/update-manifest-version.sh
# RouteWarden Plugins Manifest Version Synchronization Script
#
# Usage:
#   ./scripts/update-manifest-version.sh                     # Check and display current manifest versions
#   ./scripts/update-manifest-version.sh 1.0.0               # Updates manifest_version across all plugins
#   ./scripts/update-manifest-version.sh 1.0.0 postgres      # Updates manifest_version for specific plugin
#   ./scripts/update-manifest-version.sh --check             # CI check: ensures all plugins have valid manifest_version
#
# Examples:
#   ./scripts/update-manifest-version.sh 1.0.0
#   ./scripts/update-manifest-version.sh v1.0.0
#   ./scripts/update-manifest-version.sh 1.1.0 redis

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

# 1. Inspect mode if no arguments or --check is provided
if [ $# -eq 0 ] || [ "${1:-}" = "--check" ] || [ "${1:-}" = "-c" ]; then
  echo "🔍 Checking RouteWarden plugin manifest versions..."
  echo ""
  printf "%-16s %-12s %-16s %s\n" "PLUGIN" "VERSION" "MANIFEST_VER" "STATUS"
  printf "%-16s %-12s %-16s %s\n" "------" "-------" "------------" "------"

  MISSING=0
  for dir in "${ROOT_DIR}"/*/; do
    manifest="${dir}plugin.yaml"
    if [ ! -f "$manifest" ]; then
      manifest="${dir}plugin.yml"
    fi
    if [ -f "$manifest" ]; then
      pname="$(basename "$dir")"
      ver=$(grep -E '^[[:space:]]*version:' "$manifest" | head -n1 | sed -E 's/^[[:space:]]*version:[[:space:]]*["'\'']?([^"'\'']+)["'\'']?.*/\1/' || echo "")
      mver=$(grep -E '^[[:space:]]*manifest_version:' "$manifest" | head -n1 | sed -E 's/^[[:space:]]*manifest_version:[[:space:]]*["'\'']?([^"'\'']+)["'\'']?.*/\1/' || echo "")

      if [ -n "$mver" ]; then
        printf "%-16s %-12s %-16s %s\n" "$pname" "$ver" "$mver" "✓ Valid"
      else
        printf "%-16s %-12s %-16s %s\n" "$pname" "$ver" "(missing)" "❌ Missing"
        MISSING=$((MISSING + 1))
      fi
    fi
  done

  echo ""
  if [ $MISSING -gt 0 ]; then
    echo "❌ Error: $MISSING plugin(s) missing 'manifest_version' declaration."
    echo "Run '$0 <version>' to synchronize all plugins."
    exit 1
  else
    echo "✓ All plugin manifests have valid 'manifest_version' declarations."
    exit 0
  fi
fi

RAW_VERSION="$1"
TARGET_PLUGIN="${2:-}"

# Strip optional leading 'v'
VERSION="${RAW_VERSION#v}"

# Validate SemVer pattern (e.g. 1.0.0, 1.2.3, 1.0.0-rc.1)
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "❌ Error: Invalid semantic version format: '$RAW_VERSION'"
  echo "Expected format: MAJOR.MINOR.PATCH (e.g. 1.0.0, 1.1.0)"
  exit 1
fi

echo "🔄 Updating plugin manifest version to: ${VERSION}"

UPDATED_COUNT=0

update_plugin_manifest() {
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

  if grep -q -E '^[[:space:]]*manifest_version:' "$manifest"; then
    # Replace existing manifest_version
    sed_inplace "s|^([[:space:]]*manifest_version:[[:space:]]*).*|\1\"${VERSION}\"|g" "$manifest"
  else
    # Insert manifest_version right after version:
    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' -E "/^[[:space:]]*version:/a\\
manifest_version: \"${VERSION}\"
" "$manifest"
    else
      sed -i -E "/^[[:space:]]*version:/a manifest_version: \"${VERSION}\"" "$manifest"
    fi
  fi

  echo "  ✓ [${pname}] updated manifest_version -> \"${VERSION}\""
  UPDATED_COUNT=$((UPDATED_COUNT + 1))
}

if [ -n "$TARGET_PLUGIN" ]; then
  pdir="${ROOT_DIR}/${TARGET_PLUGIN}"
  if [ ! -d "$pdir" ]; then
    echo "❌ Error: Plugin directory '${TARGET_PLUGIN}' not found in ${ROOT_DIR}"
    exit 1
  fi
  update_plugin_manifest "$pdir"
else
  for dir in "${ROOT_DIR}"/*/; do
    if [ -d "$dir" ] && [ "$(basename "$dir")" != ".github" ] && [ "$(basename "$dir")" != "scripts" ]; then
      update_plugin_manifest "$dir"
    fi
  done
fi

echo ""
echo "✨ Successfully updated manifest_version to \"${VERSION}\" across ${UPDATED_COUNT} plugin(s)!"
echo "👉 Next steps:"
echo "   git diff"
echo "   git commit -am 'chore: update manifest version to ${VERSION}'"
