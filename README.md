# SCANOSS Open Source Engine

THE FIRST OPEN SOURCE ENGINE BUILT FOR DEVELOPERS

SCANOSS is an open, configurable OSS engine that was built specifically for developers, empowering them to confidently produce compliant code from the moment they begin writing, while delivering greater license and usage visibility for the broader DevOps team and supply chain partners.

With its open architecture that is easy to integrate into existing processes and toolchains, SCANOSS transforms software bill of materials (SBOM) creation from ‘write now, audit later’ to an always-on analysis of live code.

By freeing developers to focus on writing great, compliant code that they and their team can completely trust, applications are finished earlier, quality is consistently higher, and development costs are dramatically lower.

---

## ⚠️ Release line: CRC64-compatible (6.x)

**This branch (`crc64`) holds the CRC64-compatible release line of the SCANOSS engine, starting at v6.0.0-crc64.**

The engine is maintained as two parallel release lines:

| Release line | Branch | Engine versions | Tag format | Requires LDB |
|---|---|---|---|---|
| Traditional | `main` | 5.x | `v5.5.1` | 4.x (`main` branch of scanoss/ldb) |
| CRC64-compatible | `crc64` | 6.x and later | `v6.0.0-crc64` | 5.x-crc64 (`crc64` branch of scanoss/ldb) |

Releases of this line carry a mandatory `-crc64` suffix, since both lines are tagged in the same repository. `scanoss -v`
reports it too, so a binary always identifies the line it came from.

### LDB compatibility

> **Engine 6.x requires LDB 5.0.0-crc64 or later, from the [`crc64` branch of scanoss/ldb](https://github.com/scanoss/ldb/tree/crc64).**
>
> Engine 5.x and earlier go with the traditional LDB line (4.x, `main` branch). The two combinations are not interchangeable in
> either direction.

This constraint applies in both hash modes: it comes from the LDB on-disk table layout and the library API surface, not from the
choice of CRC64 vs MD5. An MD5 knowledge base is still perfectly usable with engine 6.x, as long as it was built with LDB 5.x-crc64.

The requirement is enforced twice, because libldb is linked dynamically and the LDB present at build time is not necessarily the
one loaded at run time:

* at build time, by `scripts/check_ldb_version.sh`, which validates both the `ldb.h` the compiler resolves and the `libldb.so`
  the linker resolves, and aborts `make` if either falls short;
* at run time, by `ldb_compat_check()`, which validates the loaded library before any table is opened.

Both derive the minimum from a single source of truth, [`inc/ldb_compat.h`](inc/ldb_compat.h).

---

# Setup 
The Scanoss engine requires a Knowledge database installed for retrieving results. Scanoss use the SCANOSS LDB (Linked-list database) as a shared library. LDB Source code and installation guide can be found on https://github.com/scanoss/ldb
The knowledge database is incrementally built using the SCANOSS mining tool (minr). It source code and installation guide can be found on https://github.com/scanoss/minr

# Prerequisites
- LDB shared library, **5.0.0-crc64 or later**, built from the `crc64` branch. Installation instructions: [LDB README (crc64 branch)](https://github.com/scanoss/ldb/blob/crc64/README.md).
- libgcrypt-dev
# Installation

The SCANOSS Engine is a command-line tool used for comparing a file or directory against the SCANOSS Knowledgebase. The source code can be downloaded and compiled as follows:

```
git clone -b crc64 https://github.com/scanoss/ldb
cd ldb && make all && sudo make install && cd ..

git clone -b crc64 https://github.com/scanoss/engine
cd engine
make
sudo make install
cd ..
scanoss -v
```

If you want to try scanoss without install it, the execute this command in bash:
```
export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
```

The last command should show the installed version of the SCANOSS Engine.

# Usage

This program performs an OSS inventory for the given TARGET comparing against the ScanOSS LDB Knowledgebase. Results are printed in STDOUT in JSON format.
You can create your own knowledgebase with the minr command, available at https://github.com/scanoss/minr

Syntax: scanoss [parameters] [TARGET]

## Configuration Options

### Basic Configuration
* `-w, --wfp` - Process TARGET as a .wfp file, regardless of its actual extension
* `-H, --hpsm` - Enable High Precision Snippet Match mode (requires 'libhpsm.so' in the system)
* `-M, --max-snippets NUM` - Search for up to NUM different components in each file (maximum: 9)
* `-N, --max-components NUM` - Set maximum number of components (default: 5)
* `-T, --tolerance NUM` - Set snippet scanning tolerance percentage (default: 0.1)
* `-r, --rank NUM` - Set maximum component rank accepted (default: 11)
* `--max-files NUM` - Set maximum number of files to fetch during matching (default: 12000)
* `--min-snippet-hits NUM` - Set minimum snippet ID hits for a match (default: 3, disables auto-adjust)
* `--min-snippet-lines NUM` - Set minimum matched lines for a range (default: 10, disables auto-adjust)
* `--range-tolerance NUM` - Set max non-matched lines tolerated in a range (default: 5)
* `--ignore-file-ext` - Ignore file extension during snippet matching (default: honor extension)

### SBOM and Filtering
* `-s, --sbom FILE` - Include assets from a JSON SBOM file (CycloneDX/SPDX2.2 format) in identification
* `-b, --blacklist FILE` - Exclude matches from assets listed in JSON SBOM file (CycloneDX/SPDX2.2 format)
* `--force-snippet` - Force snippet scanning (no full file matching). Takes no argument
* `-c, --component HINT` - Add a component HINT to guide scan results

### Attribution and Licenses
* `-a, --attribution FILE` - Show attribution notices for the provided SBOM.json file
* `-k, --key KEY` - Show contents of the specified KEY file from MZ sources archive
* `--max-file-content-size MB` - Set maximum file content size in MB printed by `-k` (default: 50)
* `-l, --license LICENSE` - Display OSADL metadata for the given SPDX license ID
* `-L, --full-license` - Enable full license report
* `-F, --flags FLAGS` - Set engine scanning flags (see Engine Flags section below)

### Knowledgebase Queries
* `-P, --purl MD5` - Return the purls related to the given file MD5, with their url hashes and source paths (JSON)
* `-C, --url-hash MD5` - Return the details of the component(s) identified by the given url hash, or a comma-separated list (JSON)
* `-p, --project URL_HASH` - Reconstruct a project's file structure: list the md5 and path of each project file (requires the pivot table; the url hash may be MD5 or CRC64)
* `-S, --snippet-scan WFP` - Snippet-only scan of a single-file WFP block, returning candidate file_md5s and their line ranges. Use `-S -` to read the WFP from stdin

### General Options
* `-t, --test` - Run engine performance tests
* `-v, --version` - Show version information and exit
* `-n, --name NAME` - Set database name (default: oss)
* `-h, --help` - Display help information and exit
* `-d, --debug` - Store debugging information to disk (/tmp)
* `-q, --quiet` - Suppress JSON output (show only debugging info via STDERR)

## Environment Variables

* `SCANOSS_MATCHMAP_MAX` - Set the snippet scanning match map size (default: 10000)
* `SCANOSS_FILE_CONTENTS_URL` - Define the API URL endpoint for sources. Source URL won't be reported if not defined

## Engine Scanning Flags

Configure the scanning engine using flags with the `-F/--flags` parameter. These settings can also be specified in `/etc/scanoss_flags.cfg`

| Flag  | Setting                                               |
|-------|-------------------------------------------------------|
|    1  | Disable snippet matching (default: enabled)           |
|    2  | Enable snippet_ids (default: disabled)                |
|    4  | Disable dependencies (default: enabled)               |
|    8  | Disable licenses (default: enabled)                   |
|   16  | Disable copyrights (default: enabled)                 |
|   32  | Disable vulnerabilities (default: enabled)            |
|   64  | Disable quality (default: enabled)                    |
|  128  | Disable cryptography (default: enabled)               |
|  256  | Disable best match only (default: enabled)            |
|  512  | Hide identified files (default: disabled)             |
| 1024  | Enable download_url (default: disabled)               |
| 2048  | Enable "use path hint" logic (default: disabled)      |
| 4096  | Disable extended server stats (default: enabled)      |
| 8192  | Disable health layer (default: enabled)               |
| 16384 | Enable high accuracy, slower scan (default: disabled) |

### Examples:
```bash
# Scan DIRECTORY without license and dependency data
scanoss -F 12 DIRECTORY
scanoss --flags 12 DIRECTORY

# Scan TARGET including SBOM assets
scanoss --sbom my_sbom.json TARGET

# Scan with custom snippet matching parameters
scanoss --min-snippet-hits 5 --min-snippet-lines 15 TARGET

# Scan with custom range tolerance
scanoss --range-tolerance 10 TARGET

# Ignore file extensions during matching
scanoss --ignore-file-ext TARGET
```

# File matching logic

The scanning engine attempts to match files with the following criteria:

## Is the file matching an entire package (matching directly the archive downloaded from the URL)?

This produces an identifycation (id) of type "url"

## Otherwise, is the file matching an entire known file?

This produces an identification (id) of type "file"

## Otherwise, snippet comparison is executed comparing snippet hashes

This produces an identification (id) of type "snippet"

## If none of the above,

This produces an identification (id) of type "none"

# File ranking algorithm

Often, the SCANOSS engine finds files that are present in different components and versions, which triggers a series of functions to determine the best match. These functions are detailed below:

## Component hint retrieval

The scanning client can optionally pass a a component hint (context). The context is the name of the last component detected. This context will influence results and the scanning engine will favour the files belonging to a component matching the provided context.

## First component released

If no hint is provided, the SCANOSS engine will look for the oldest component in the KB which matches the scanned file. In case of a tie between two components with the same release date, other available information will be used to select the best match.

## Distinct component selection

A matched file is frequently present in several components and versions at once. The engine keeps a small, fixed-size list of candidate components (3 by default) for each match, which is the list reported when best-match-only is disabled (`-F 256`). To avoid a single component monopolising that list with multiple versions of itself, candidates are deduplicated by their main purl: when a new candidate shares the purl of one already in the list, only the preferred one is kept (using the same ranking criteria described above, i.e. favouring the oldest release), and the freed slots are made available to genuinely different components. As a result the list reflects distinct components rather than repeated versions of the same one.

## SBOM Ingestion

The user can use the "-s'' optional argument plus a sbom.json. The engine will prioritize the declared components during the analysis. If a file can not be matched against any declared component, then the logic previously explained will be applied.

# License

The Scanoss Open Source Engine is released under the GPL 2.0 license. Please check the LICENSE file for more information.

Copyright (C) 2018-2020 SCANOSS.COM

