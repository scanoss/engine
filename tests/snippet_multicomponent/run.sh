#!/usr/bin/env bash
#
# Regression test: multi-component snippet scan (-M / --max-snippets).
#
# Guards two bugs that made a single file concatenating code from several
# components collapse to a single candidate (and segfault with -M >= 2):
#
#   1. match_data_copy() dropped scan_ower/lines_matched -> print_json_match()
#      dereferenced a NULL scan_ower (segfault, src/report.c).
#   2. biggest_snippet() added every candidate to matches_list_array[0] instead
#      of the per-region list, so only one block survived (src/snippet_selection.c).
#
# The input is main.c.wfp: a WFP of a file that concatenates blocks from
# nginx / tomcat / curl / httpd / postgres (see the header table in the PR).
#
# This test needs an OSS knowledge base. If none is reachable it SKIPS (exit 0)
# so it does not break CI images that ship without KB data.
#
#   SCANOSS_BIN  path to the engine binary   (default: ../../scanoss)
#   SCANOSS_KB   KB/database name for -n     (default: ossv2)
#
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${SCANOSS_BIN:-$HERE/../../scanoss}"
KB="${SCANOSS_KB:-ossv2}"
WFP_C="$HERE/main.c.wfp"

if [ ! -x "$BIN" ]; then
	echo "SKIP: engine binary not found at $BIN (set SCANOSS_BIN)"
	exit 0
fi

# Derive java/py WFPs (identical content, only the file name/extension differs).
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
WFP_JAVA="$TMP/main.java.wfp"
WFP_PY="$TMP/main.py.wfp"
sed 's/,main\.c$/,main.java/' "$WFP_C" > "$WFP_JAVA"
sed 's/,main\.c$/,main.py/'   "$WFP_C" > "$WFP_PY"

# Probe: make sure the KB actually answers; otherwise skip rather than fail.
PROBE="$("$BIN" -n "$KB" -w "$WFP_C" 2>/dev/null)"
if [ $? -ne 0 ] || ! printf '%s' "$PROBE" | grep -q '"id": "snippet"'; then
	echo "SKIP: KB '$KB' produced no snippet match (KB missing or not loaded)"
	exit 0
fi

FAILED=0

# run <label> <expected-exit> <wfp> [extra engine args...]
# Captures stdout and exit code into globals OUT / RC.
run() {
	local label="$1"; shift
	local want_rc="$1"; shift
	local wfp="$1"; shift
	OUT="$("$BIN" -n "$KB" -M 9 "$@" -w "$wfp" 2>/dev/null)"
	RC=$?
	if [ "$RC" -ne "$want_rc" ]; then
		echo "FAIL [$label]: exit $RC (expected $want_rc)  <-- segfault/crash regression?"
		FAILED=1
		return 1
	fi
	return 0
}

# assert_has <label> <substring...>: every substring must appear in OUT.
assert_has() {
	local label="$1"; shift
	local s
	for s in "$@"; do
		if ! printf '%s' "$OUT" | grep -qF "$s"; then
			echo "FAIL [$label]: expected to find: $s"
			FAILED=1
		fi
	done
}

# assert_lacks <label> <substring...>: no substring may appear in OUT.
assert_lacks() {
	local label="$1"; shift
	local s
	for s in "$@"; do
		if printf '%s' "$OUT" | grep -qF "$s"; then
			echo "FAIL [$label]: did NOT expect to find: $s"
			FAILED=1
		fi
	done
}

# assert_order <label> <first> <second>: <first> must appear before <second>
# (relevance ordering: the block covering the most lines is match_index 0).
assert_order() {
	local label="$1" first="$2" second="$3"
	local pf ps
	pf=$(printf '%s' "$OUT" | grep -boF "$first"  | head -1 | cut -d: -f1)
	ps=$(printf '%s' "$OUT" | grep -boF "$second" | head -1 | cut -d: -f1)
	if [ -z "$pf" ] || [ -z "$ps" ] || [ "$pf" -ge "$ps" ]; then
		echo "FAIL [$label]: expected '$first' before '$second'"
		FAILED=1
	fi
}

# --- Minimum acceptable results (must pass) -------------------------------

# 1) main.c, honoring extension -> curl (203-250) + httpd (255-278), no C-less noise.
if run "main.c" 0 "$WFP_C"; then
	assert_has   "main.c" '"lines": "203-250"' 'lib/asyn-ares.c' \
	                       '"lines": "255-278"' 'modules/http/http_request.c'
	# curl covers more lines than httpd -> curl must be the principal match.
	assert_order "main.c" '"lines": "203-250"' '"lines": "255-278"'
	# tomcat is a .java file: must be discarded when honoring the .c extension.
	assert_lacks "main.c" 'AbstractEndpoint.java'
fi

# 2) main.c --ignore-file-ext -> tomcat (114-196) + curl (203-250) + httpd (255-278).
if run "main.c --ignore-file-ext" 0 "$WFP_C" --ignore-file-ext; then
	assert_has   "main.c --ignore-file-ext" \
	             '"lines": "114-196"' 'AbstractEndpoint.java' \
	             '"lines": "203-250"' 'lib/asyn-ares.c' \
	             '"lines": "255-278"' 'modules/http/http_request.c'
	# Ordered by covered lines: tomcat (26%) > curl (15%) > httpd (7%).
	assert_order "main.c --ignore-file-ext" '"lines": "114-196"' '"lines": "203-250"'
	assert_order "main.c --ignore-file-ext" '"lines": "203-250"' '"lines": "255-278"'
fi

# 3) main.java, honoring extension -> only tomcat, nothing from the C blocks.
if run "main.java" 0 "$WFP_JAVA"; then
	assert_has   "main.java" '"lines": "114-196"' 'AbstractEndpoint.java'
	assert_lacks "main.java" 'lib/asyn-ares.c' 'modules/http/http_request.c'
fi

# 4) main.py, honoring extension -> no match (none of these blocks are Python).
if run "main.py" 0 "$WFP_PY"; then
	assert_lacks "main.py" '"id": "snippet"'
fi

# 5) snippet-scan endpoint (-S, the /scan/snippets path). It must expose every
#    non-overlapping region as its own group WITHOUT requiring -M, since the
#    engine-wide default is 1 (which used to collapse everything into group 0).
SOUT="$("$BIN" -n "$KB" -S - < "$WFP_C" 2>/dev/null)"
SRC=$?
if [ "$SRC" -ne 0 ]; then
	echo "FAIL [snippet-scan -S]: exit $SRC (expected 0)"
	FAILED=1
else
	GROUPS=$(printf '%s' "$SOUT" | grep -o '"group_index"' | wc -l | tr -d ' ')
	if [ "$GROUPS" -lt 3 ]; then
		echo "FAIL [snippet-scan -S]: $GROUPS group(s), expected >= 3 (default collapsed to 1?)"
		FAILED=1
	fi
	for s in '"input_line_ranges":"114-196"' '"input_line_ranges":"203-250"' '"input_line_ranges":"255-278"'; do
		if ! printf '%s' "$SOUT" | grep -qF "$s"; then
			echo "FAIL [snippet-scan -S]: expected region $s"
			FAILED=1
		fi
	done
fi

# --- Objective / pending (informational only, never fails the suite) ------
# nginx (input 6-110) and postgres (input 281-295) are not returned yet; this
# needs the per-sector candidate selection in biggest_snippet to be revisited.
if run "ideal-pending" 0 "$WFP_C" --ignore-file-ext; then
	for want in '"lines": "6-110"' '"lines": "281-295"'; do
		printf '%s' "$OUT" | grep -qF "$want" \
			&& echo "NOTE: ideal block now present: $want (consider promoting to a hard assert)" \
			|| echo "PENDING: ideal block still missing: $want (nginx/postgres, see PR point 3)"
	done
fi

if [ "$FAILED" -eq 0 ]; then
	echo "PASS: snippet multi-component regression"
	exit 0
fi
echo "FAIL: snippet multi-component regression"
exit 1
