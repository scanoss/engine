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
#   1. Pick a real full-file hash: the one behind a snippet match against
#      main.c.wfp, or a known low-copy KB file if that one cannot be peeled.
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

# 1. Candidate full-file hashes: first the KB file behind the snippet match on
#    the source WFP, then known files with few copies in the KB (a heavily
#    vendored file such as curl's can have dozens of components to peel).
#    661e423d... is src/vulnerability.c from pkg:github/scanoss/engine.
PROBE="$("$BIN" -n "$KB" -w "$WFP_SRC" 2>/dev/null)"
FHASH="$(printf '%s' "$PROBE" | grep -oE '"file_hash": "[0-9a-f]+"' | head -1 | grep -oE '[0-9a-f]+' | tail -1)"
if [ -z "$FHASH" ]; then
	echo "SKIP: KB '$KB' produced no snippet match (KB missing or not loaded)"
	exit 0
fi
CANDIDATES=("$FHASH" 661e423d19593de5e10db93add61c5c5)

WFP="$TMP/fullfile.wfp"
COLLAPSED=0
for CAND in "${CANDIDATES[@]}"; do
	# 2. Build a WFP whose file= hash is that KB file (full-file match), padded to
	#    32 hex chars, carrying the source snippet hashes; the engine reads the
	#    leading oss_file.key_ln*2 chars.
	FHASH_PAD="$(printf '%-32s' "$CAND" | tr ' ' '0')"
	{ echo "file=${FHASH_PAD},9999,test.c"; tail -n +2 "$WFP_SRC"; } > "$WFP"

	# Confirm it is actually a full-file match, otherwise try the next candidate.
	BASE="$("$BIN" -n "$KB" -w "$WFP" 2>/dev/null)"
	[ "$(match_id "$BASE")" != "file" ] && continue

	# 3. Peel the full-file components until the match would collapse to none.
	IGN=()
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
	[ "$COLLAPSED" -eq 1 ] && [ ${#IGN[@]} -gt 0 ] && break
	COLLAPSED=0
done

if [ "$COLLAPSED" -ne 1 ]; then
	echo "SKIP: no candidate full-file match could be reduced to an ignorable component set in KB '$KB'"
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
