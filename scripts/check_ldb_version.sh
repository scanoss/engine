#!/bin/bash
###
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2018-2025 SCANOSS.COM
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
###
#
# Build time validation of the installed LDB.
#
# The requirement is read from inc/ldb_compat.h, the same header the run time
# check (src/ldb_compat.c) compiles against, so the two can never disagree.
#
# Two independent sources are validated, because the engine links libldb
# dynamically and they can disagree on the same machine:
#
#   1. The ldb.h the compiler resolves for `#include <ldb.h>`, expanded by the
#      preprocessor itself. This is literally what the engine compiles against,
#      which makes it a far more faithful source than `ldb -v`: the shell binary
#      found on PATH is a separate artifact that may come from another install,
#      from another release line, or not be installed at all, while the build
#      would still happily use /usr/include/ldb.h and link -lldb.
#
#   2. The libldb.so the linker actually resolves, probed by building and
#      running a two line program against it. A stale library earlier in the
#      loader search path (a leftover /usr/local/lib/libldb.so shadowing
#      /usr/lib/libldb.so, say) produces a binary that compiles cleanly and then
#      fails the run time check on the very machine that built it.
#
# `ldb -v` is consulted too, but only as a non fatal hint: it is neither
# compiled against nor linked in.
#
# Usage: check_ldb_version.sh [path/to/inc/ldb_compat.h]
#

set -u

COMPAT_HEADER="${1:-inc/ldb_compat.h}"
CC_BIN="${CC:-gcc}"
CPPFLAGS="${CPPFLAGS:-}"

if [ ! -f "$COMPAT_HEADER" ] ; then
  echo "ERROR: cannot read $COMPAT_HEADER, unable to determine the required LDB version." >&2
  exit 1
fi

# Read a `#define NAME VALUE` (quoted or not) out of the compat header
compat_define() {
  sed -n "s/^[[:space:]]*#define[[:space:]]\+$1[[:space:]]\+\"\{0,1\}\([^\"[:space:]]*\)\"\{0,1\}.*/\1/p" \
    "$COMPAT_HEADER" | head -1
}

REQ_MAJOR=$(compat_define LDB_REQUIRED_VERSION_MAJOR)
REQ_MINOR=$(compat_define LDB_REQUIRED_VERSION_MINOR)
REQ_PATCH=$(compat_define LDB_REQUIRED_VERSION_PATCH)
REQ_LINE=$(compat_define LDB_REQUIRED_RELEASE_LINE)

if [ -z "$REQ_MAJOR" ] || [ -z "$REQ_MINOR" ] || [ -z "$REQ_PATCH" ] || [ -z "$REQ_LINE" ] ; then
  echo "ERROR: could not parse the LDB requirement out of $COMPAT_HEADER." >&2
  exit 1
fi

REQUIRED="${REQ_MAJOR}.${REQ_MINOR}.${REQ_PATCH}-${REQ_LINE}"
REQUIRED_WEIGHT=$(( REQ_MAJOR * 1000000 + REQ_MINOR * 1000 + REQ_PATCH ))

INSTALL_HINT="  git clone -b ${REQ_LINE} https://github.com/scanoss/ldb && cd ldb && make all && sudo make install"

# Split MAJOR[.MINOR[.PATCH]][-SUFFIX] into its components
parse_version() {
  local v="${1#ldb-}"
  local base="${v%%-*}"
  local suffix=""
  case "$v" in *-*) suffix="${v#*-}" ;; esac
  local major="${base%%.*}"
  local rest="${base#*.}"
  local minor=0 patch=0
  if [ "$rest" != "$base" ] ; then
    minor="${rest%%.*}"
    local rest2="${rest#*.}"
    [ "$rest2" != "$rest" ] && patch="${rest2%%.*}"
  fi
  case "$major$minor$patch" in
    ''|*[!0-9]*) return 1 ;;
  esac
  printf '%s %s %s %s\n' "$major" "$minor" "$patch" "$suffix"
  return 0
}

# validate_version <version> <origin description>
# Exits with a message the user can act on if <version> does not meet the
# requirement declared in inc/ldb_compat.h.
validate_version() {
  local found="$1" origin="$2" parsed
  local major minor patch line weight

  if ! parsed=$(parse_version "$found") ; then
    cat >&2 <<EOM

ERROR: could not parse the LDB version reported by ${origin}: "${found}".
       Expected MAJOR.MINOR.PATCH-${REQ_LINE}, for example ${REQUIRED}.

EOM
    exit 1
  fi

  # shellcheck disable=SC2086
  set -- $parsed
  major="$1" ; minor="$2" ; patch="$3" ; line="${4:-}"

  # Semantic version comparison, component by component. Not `bc`, which
  # compares decimals and so ranks 4.10 below 4.2, and not a string compare,
  # which ranks 5.10.0 below 5.9.0.
  weight=$(( major * 1000000 + minor * 1000 + patch ))

  if [ "$weight" -lt "$REQUIRED_WEIGHT" ] ; then
    cat >&2 <<EOM

ERROR: ${origin} is LDB version ${found}, which is too old.
       The SCANOSS engine requires LDB ${REQUIRED} or later.

       Update LDB from the '${REQ_LINE}' branch of https://github.com/scanoss/ldb:
${INSTALL_HINT}

EOM
    exit 1
  fi

  if [ "$line" != "$REQ_LINE" ] ; then
    local line_desc
    if [ -z "$line" ] ; then
      line_desc="the MD5-only release line"
    else
      line_desc="the '${line}' release line"
    fi
    cat >&2 <<EOM

ERROR: ${origin} is LDB version ${found}, from ${line_desc}.
       The SCANOSS engine requires the '${REQ_LINE}' release line of LDB (${REQUIRED} or later).
       The version number is high enough, but the release line is wrong: this build
       of LDB does not implement the CRC64 table layout and API this engine expects.

       Install LDB from the '${REQ_LINE}' branch of https://github.com/scanoss/ldb:
${INSTALL_HINT}

EOM
    exit 1
  fi
}

# --- 1. The header the engine compiles against ------------------------------

probe_src=$(mktemp --suffix=.c) || exit 1
probe_bin="${probe_src%.c}.bin"
trap 'rm -f "$probe_src" "$probe_bin"' EXIT

printf '#include <ldb.h>\nLDB_COMPAT_PROBE LDB_VERSION\n' > "$probe_src"

preprocessed=$($CC_BIN $CPPFLAGS -E "$probe_src" 2>/dev/null)
if [ -z "$preprocessed" ] ; then
  cat >&2 <<EOM

ERROR: <ldb.h> not found. The SCANOSS engine compiles and links against LDB.
       Install LDB ${REQUIRED} or later from the '${REQ_LINE}' branch of
       https://github.com/scanoss/ldb:
${INSTALL_HINT}

EOM
  exit 1
fi

LDB_HEADER=$(printf '%s\n' "$preprocessed" | \
  sed -n 's/^#[[:space:]]*[0-9]\{1,\}[[:space:]]*"\([^"]*ldb\.h\)".*/\1/p' | head -1)
LDB_HEADER="${LDB_HEADER:-<ldb.h>}"

# Re-run with -P: without it, the line markers gcc emits around the expansion
# split "LDB_COMPAT_PROBE" and the version string onto different lines.
HEADER_VERSION=$($CC_BIN $CPPFLAGS -E -P "$probe_src" 2>/dev/null | tr '\n' ' ' | \
  sed -n 's/.*LDB_COMPAT_PROBE[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)

if [ -z "$HEADER_VERSION" ] ; then
  cat >&2 <<EOM

ERROR: ${LDB_HEADER} does not define LDB_VERSION, so the installed LDB cannot be
       identified. This header predates LDB 4.x and is far too old.
       Install LDB ${REQUIRED} or later from the '${REQ_LINE}' branch of
       https://github.com/scanoss/ldb:
${INSTALL_HINT}

EOM
  exit 1
fi

validate_version "$HEADER_VERSION" "the header being compiled against (${LDB_HEADER})"

# --- 2. The shared library the linker resolves ------------------------------

printf '#include <stdio.h>\n#include <ldb.h>\nint main(void){char *v=NULL;ldb_version(&v);printf("%%s\\n",v?v:"");return 0;}\n' > "$probe_src"

if $CC_BIN $CPPFLAGS "$probe_src" -o "$probe_bin" -lldb -lm -lpthread -ldl >/dev/null 2>&1 ; then
  LINKED_VERSION=$("$probe_bin" 2>/dev/null | head -1 | tr -d '\n')
  LINKED_PATH=$(ldd "$probe_bin" 2>/dev/null | sed -n 's/.*libldb\.so[^=]*=> \([^ ]*\).*/\1/p' | head -1)
  LINKED_PATH="${LINKED_PATH:-the libldb.so resolved by the loader}"

  if [ -z "$LINKED_VERSION" ] ; then
    echo "WARNING: could not read a version out of ${LINKED_PATH}; relying on ${LDB_HEADER} alone." >&2
  else
    if [ "$LINKED_VERSION" != "$HEADER_VERSION" ] ; then
      cat >&2 <<EOM

WARNING: mixed LDB installation.
         Header  ${LDB_HEADER} declares ${HEADER_VERSION}
         Library ${LINKED_PATH} reports ${LINKED_VERSION}
         The engine compiles against the first and runs against the second.

EOM
    fi
    validate_version "$LINKED_VERSION" "the library the linker resolves (${LINKED_PATH})"
  fi
else
  echo "WARNING: could not link a probe against -lldb; the shared library check was skipped." >&2
fi

# --- 3. The shell binary on PATH (hint only) --------------------------------

if command -v ldb >/dev/null 2>&1 ; then
  SHELL_VERSION=$(ldb -v 2>/dev/null | head -1 | tr -d '\n')
  SHELL_VERSION="${SHELL_VERSION#ldb-}"
  if [ -n "$SHELL_VERSION" ] && [ "$SHELL_VERSION" != "$HEADER_VERSION" ] ; then
    echo "WARNING: the 'ldb' binary on PATH ($(command -v ldb)) reports ${SHELL_VERSION}, but the engine builds against ${HEADER_VERSION}." >&2
  fi
fi

echo "LDB ${HEADER_VERSION} found (requires ${REQUIRED} or later) - OK"
exit 0
