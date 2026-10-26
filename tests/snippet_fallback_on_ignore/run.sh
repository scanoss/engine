#!/usr/bin/env bash
#
# Regression test: snippet fallback when a full-file match is fully ignored.
#
# When a file produces a full-file (MATCH_FILE) result but every candidate
# component is removed by the ignore list (-b), the match used to collapse to
# "none". The engine now discards that result and automatically retries once as
# a snippet scan over the same file, honoring the same ignore/include lists, so
# a legitimate snippet match can still surface.
#
# The test is data-driven so it does not hard-code KB contents:
#   1. Derive a real full-file hash from a snippet match against main.c.wfp.
#   2. Build a WFP whose file= hash triggers that full-file match, carrying the
#      same snippet hashes.
#   3. Peel the full-file components (ignore them one by one) until the result
#      would collapse to "none".
#   4. With all of them ignored, assert the result is a SNIPPET match, not none.
#
# Needs an OSS knowledge base; if none is reachable (or the scenario cannot be
# built from the KB) it SKIPS (exit 0) so it never breaks KB-less CI images.
#
#   SCANOSS_BIN  path to the engine binary   (default: ../../scanoss)
#   SCANOSS_KB   KB/database name for -n     (default: ossv2)
#
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${SCANOSS_BIN:-$HERE/../../scanoss}"
KB="${SCANOSS_KB:-ossv2}"
WFP_SRC="$HERE/../snippet_multicomponent/main.c.wfp"

if [ ! -x "$BIN" ]; then
	echo "SKIP: engine binary not found at $BIN (set SCANOSS_BIN)"
	exit 0
fi
if [ ! -f "$WFP_SRC" ]; then
	echo "SKIP: input WFP not found at $WFP_SRC"
	exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ignore_json <purl...> -> path to a -b SBOM.json ignoring the given purls.
ignore_json() {
	local out="$TMP/ignore.json" first=1 p
	{
		printf '{"components":['
		for p in "$@"; do
			[ $first -eq 1 ] || printf ','
			printf '{"purl":"%s"}' "$p"; first=0
		done
		printf ']}'
	} > "$out"
	echo "$out"
}

match_id()   { printf '%s' "$1" | grep -oE '"id": "[a-z]+"' | head -1 | grep -oE '[a-z]+"$' | tr -d '"'; }
first_purl() { printf '%s' "$1" | grep -o '"purl": \[[^]]*\]' | head -1 | grep -o 'pkg:[^"]*' | head -1; }

# 1. Find a real KB full-file hash via a snippet match on the source WFP.
PROBE="$("$BIN" -n "$KB" -w "$WFP_SRC" 2>/dev/null)"
FHASH="$(printf '%s' "$PROBE" | grep -oE '"file_hash": "[0-9a-f]+"' | head -1 | grep -oE '[0-9a-f]+' | tail -1)"
if [ -z "$FHASH" ]; then
	echo "SKIP: KB '$KB' produced no snippet match to derive a full-file hash"
	exit 0
fi

# 2. Build a WFP whose file= hash is that KB file (full-file match), padded to
#    32 hex chars; the engine reads the leading oss_file.key_ln*2 chars.
FHASH_PAD="$(printf '%-32s' "$FHASH" | tr ' ' '0')"
WFP="$TMP/fullfile.wfp"
{ echo "file=${FHASH_PAD},9999,test.c"; tail -n +2 "$WFP_SRC"; } > "$WFP"

# Confirm it is actually a full-file match, otherwise the scenario does not apply.
BASE="$("$BIN" -n "$KB" -w "$WFP" 2>/dev/null)"
if [ "$(match_id "$BASE")" != "file" ]; then
	echo "SKIP: derived WFP did not produce a full-file match in KB '$KB'"
	exit 0
fi

# 3. Peel the full-file components until the match would collapse to none.
IGN=()
COLLAPSED=0
for _ in 1 2 3 4 5 6 7 8; do
	if [ ${#IGN[@]} -eq 0 ]; then
		OUT="$BASE"
	else
		OUT="$("$BIN" -n "$KB" -b "$(ignore_json "${IGN[@]}")" -w "$WFP" 2>/dev/null)"
	fi
	ID="$(match_id "$OUT")"
	[ "$ID" != "file" ] && { COLLAPSED=1; break; }   # no more file components
	P="$(first_purl "$OUT")"
	[ -z "$P" ] && break
	IGN+=("$P")
done

if [ "$COLLAPSED" -ne 1 ] || [ ${#IGN[@]} -eq 0 ]; then
	echo "SKIP: could not reduce the full-file match to a single ignorable component set"
	exit 0
fi

echo "INFO: full-file components ignored: ${IGN[*]}"

# 4. With every full-file purl ignored, the result must fall back to a snippet
#    match instead of collapsing to "none".
OUT="$("$BIN" -n "$KB" -b "$(ignore_json "${IGN[@]}")" -w "$WFP" 2>/dev/null)"
ID="$(match_id "$OUT")"

if [ "$ID" = "snippet" ]; then
	echo "PASS: fully-ignored full-file match falls back to a snippet scan"
	exit 0
fi
echo "FAIL: expected a snippet fallback, got id='$ID' (regression: #120 full-file fallback)"
exit 1
