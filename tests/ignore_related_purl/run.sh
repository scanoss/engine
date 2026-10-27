#!/usr/bin/env bash
#
# Regression test: ignoring a related PURL (-b) must suppress the component.
#
# Guards issue #120: the ignore list (-b SBOM.json) was only compared against
# the single primary purl stored in the url record (field 6). A project may be
# published under several purls (e.g. a github repo also indexed as a golang/
# nuget/conda package); those sibling identities are only materialised later by
# fetch_related_purls(). So ignoring a purl that happened to be a *related* purl
# had no effect: the match survived under its primary identity and the ignored
# purl resurfaced in the reported "purl" array.
#
# The fix (component_list_remove_ignored / component_ignored_by_purl) drops a
# component when ANY of its purls -- primary OR related -- is in the ignore list.
#
# This test is data-driven so it does not hard-code KB contents: it peels the
# top candidates of a region until a component exposing >= 2 purls surfaces,
# then asks the engine to ignore one of that component's *related* purls and
# asserts the whole component disappears. It needs an OSS knowledge base; if
# none is reachable (or no multi-purl component is found) it SKIPS (exit 0) so
# it never breaks CI images that ship without KB data.
#
#   SCANOSS_BIN  path to the engine binary   (default: ../../scanoss)
#   SCANOSS_KB   KB/database name for -n     (default: ossv2)
#
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${SCANOSS_BIN:-$HERE/../../scanoss}"
KB="${SCANOSS_KB:-ossv2}"
WFP="$HERE/../snippet_multicomponent/main.c.wfp"

if [ ! -x "$BIN" ]; then
	echo "SKIP: engine binary not found at $BIN (set SCANOSS_BIN)"
	exit 0
fi
if [ ! -f "$WFP" ]; then
	echo "SKIP: input WFP not found at $WFP"
	exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# scan [purl ...] -> prints engine JSON for the WFP, ignoring the given purls.
scan() {
	local ign="$TMP/ignore.json" first=1 p
	{
		printf '{"components":['
		for p in "$@"; do
			[ $first -eq 1 ] || printf ','
			printf '{"purl":"%s"}' "$p"
			first=0
		done
		printf ']}'
	} > "$ign"
	if [ "$#" -eq 0 ]; then
		"$BIN" -n "$KB" -w "$WFP" 2>/dev/null
	else
		"$BIN" -n "$KB" -b "$ign" -w "$WFP" 2>/dev/null
	fi
}

# first_multi_purl_array <json> -> the first "purl":[...] array holding >= 2 purls.
first_multi_purl_array() {
	printf '%s' "$1" | grep -o '"purl": \[[^]]*\]' | grep ',' | head -1
}

# first_primary_purl <json> -> the primary purl (purls[0]) of the first component.
first_primary_purl() {
	printf '%s' "$1" | grep -o '"purl": \[[^]]*\]' | head -1 | grep -o 'pkg:[^"]*' | head -1
}

# Probe: make sure the KB answers at all, otherwise skip rather than fail.
PROBE="$(scan)"
if ! printf '%s' "$PROBE" | grep -q '"id": "snippet"'; then
	echo "SKIP: KB '$KB' produced no snippet match (KB missing or not loaded)"
	exit 0
fi

# Peel the top candidate of the region until a component with >= 2 purls shows up.
IGN=()
ARR=""
for _ in 1 2 3 4 5 6 7 8; do
	OUT="$(scan "${IGN[@]}")"
	ARR="$(first_multi_purl_array "$OUT")"
	[ -n "$ARR" ] && break
	P="$(first_primary_purl "$OUT")"
	[ -z "$P" ] && break           # no more matches to peel
	IGN+=("$P")
done

if [ -z "$ARR" ]; then
	echo "SKIP: no reachable component with related purls in KB '$KB' (cannot exercise #120)"
	exit 0
fi

# The array is "pkg:A","pkg:B",... -- primary is the first, related ones follow.
mapfile -t PURLS < <(printf '%s' "$ARR" | grep -o 'pkg:[^"]*')
PRIMARY="${PURLS[0]}"
RELATED="${PURLS[-1]}"            # a sibling purl, only present via fetch_related_purls

if [ "$RELATED" = "$PRIMARY" ]; then
	echo "SKIP: could not isolate a related purl distinct from the primary"
	exit 0
fi

echo "INFO: component primary=$PRIMARY  related=$RELATED (ignoring the related one)"

# Ignoring the RELATED purl must drop the whole component. Pre-fix this had no
# effect because only the primary purl (field 6) was ever checked.
OUT_TEST="$(scan "${IGN[@]}" "$RELATED")"

FAILED=0
if printf '%s' "$OUT_TEST" | grep -qF "$RELATED"; then
	echo "FAIL: ignored related purl still present in output: $RELATED"
	FAILED=1
fi
if printf '%s' "$OUT_TEST" | grep -qF "$PRIMARY"; then
	echo "FAIL: component not suppressed; its primary purl still present: $PRIMARY"
	FAILED=1
fi

if [ "$FAILED" -eq 0 ]; then
	echo "PASS: ignoring a related purl suppresses the component (#120)"
	exit 0
fi
echo "FAIL: related-purl ignore regression (#120)"
exit 1
