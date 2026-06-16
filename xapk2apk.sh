#!/usr/bin/env bash
# xapk2apk.sh - convert an .xapk (or .apks/.apkm) bundle into a single standard, installable .apk
#
# Deps:
#   - unzip, java
#   - APKEditor.jar   (https://github.com/REAndroid/APKEditor/releases)  -> merges split APKs
#   - apksigner + a keystore (Android SDK build-tools)                    -> signs the merged APK
#
# Env overrides:
#   APKEDITOR   path to APKEditor.jar              (default: ./APKEditor.jar)
#   KEYSTORE    path to a signing keystore         (default: ~/.android/debug.keystore)
#   KS_PASS     keystore/key password              (default: android  -> the debug keystore default)
#   KS_ALIAS    key alias                          (default: androiddebugkey)
#
# Usage: ./xapk2apk.sh input.xapk [output.apk]

set -euo pipefail

IN="${1:?usage: xapk2apk.sh input.xapk [output.apk]}"
OUT="${2:-${IN%.*}.apk}"

APKEDITOR="${APKEDITOR:-./APKEditor.jar}"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"
KS_PASS="${KS_PASS:-android}"
KS_ALIAS="${KS_ALIAS:-androiddebugkey}"

[ -f "$IN" ] || { echo "error: '$IN' not found" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo ">> unpacking $IN"
unzip -q "$IN" -d "$work"

# Collect every APK inside the bundle (base + splits)
mapfile -t apks < <(find "$work" -maxdepth 2 -name '*.apk' | sort)
echo ">> found ${#apks[@]} apk(s)"

if [ "${#apks[@]}" -eq 0 ]; then
  echo "error: no .apk inside the bundle" >&2; exit 1
fi

if [ "${#apks[@]}" -eq 1 ]; then
  # Single base APK — nothing to merge, just copy it out.
  echo ">> single base apk, copying out"
  cp "${apks[0]}" "$OUT"
  echo ">> done: $OUT (already signed by original author)"
  exit 0
fi

# Multiple splits -> merge into one universal APK with APKEditor
[ -f "$APKEDITOR" ] || { echo "error: APKEditor.jar not found at '$APKEDITOR' (set \$APKEDITOR)" >&2; exit 1; }

merged="$work/merged.apk"
echo ">> merging ${#apks[@]} splits with APKEditor"
java -jar "$APKEDITOR" m -i "$work" -o "$merged"

# Merged APK is unsigned -> sign it so it can be installed
if command -v apksigner >/dev/null 2>&1 && [ -f "$KEYSTORE" ]; then
  echo ">> signing with $KEYSTORE"
  apksigner sign \
    --ks "$KEYSTORE" \
    --ks-pass "pass:$KS_PASS" \
    --ks-key-alias "$KS_ALIAS" \
    --out "$OUT" "$merged"
  apksigner verify "$OUT" && echo ">> signature OK"
else
  echo "!! apksigner or keystore missing — emitting UNSIGNED apk (won't install until signed)" >&2
  cp "$merged" "$OUT"
fi

echo ">> done: $OUT"
