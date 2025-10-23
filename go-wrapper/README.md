# Go Wrapper for SCANOSS Snippet Scanner

This wrapper allows using the SCANOSS engine's snippet scanning functionality from Go code via CGO.

## Project Structure

```
go-wrapper/
├── snippets_wrapper.h      # C wrapper header
├── snippets_wrapper.c      # C wrapper implementation
├── wfp_scanner.go         # WFP scanner with Go CGO bindings
├── test_main.go           # Simple test example
├── Makefile               # Static library compilation
└── README.md              # This documentation
```

## Compilation

### 1. Compile the static library

```bash
cd go-wrapper
make clean
make
```

This will generate `libsnippets_wrapper.a` containing all necessary engine code.

### 2. Verify compilation

```bash
ls -la libsnippets_wrapper.a
```

### 3. Test example

```bash
make test
```

Or manually:

```bash
go build -o wfp_scanner example/wfp_scanner.go
```

## Usage

### WFP Scanner

The `wfp_scanner` tool scans WFP (Winnowing FingerPrint) files against the SCANOSS database:

```bash
# Basic usage
./wfp_scanner example/test.wfp

# With custom database name
./wfp_scanner -oss-db-name=custom_db example/test.wfp

# Enable debug output
./wfp_scanner -q example/test.wfp

# Show help
./wfp_scanner --help
```

#### Command-line Options

- `-oss-db-name`: OSS database name (default: "oss")
- `-q`: Enable debug output (default: false)

#### WFP File Format

```
file=<md5>,<total_lines>,<file_path>
<line_number>=<hash1>,<hash2>,...
```

Example:
```
file=e27b911d391391f94a862ebbe40ddcc0,1652,path/to/file.c
1=63e9a57f
3=e6f64278
6=aa323afd,31466ee5,87dece99
```

### Using the Wrapper in Go Code

```go
package main

// #cgo CFLAGS: -I. -I../inc -I../external/inc
// #cgo LDFLAGS: ${SRCDIR}/libsnippets_wrapper.a -lldb -lssl -lcrypto -lz -lm -lpthread
// #include "snippets_wrapper.h"
// #include <stdlib.h>
import "C"
import (
    "unsafe"
)

func main() {
    // Initialize wrapper with database name and debug mode
    cDbName := C.CString("oss")
    defer C.free(unsafe.Pointer(cDbName))
    C.snippets_wrapper_init(cDbName, C.bool(false))
    defer C.snippets_wrapper_cleanup()

    // Prepare input data
    cInput := C.wrapper_scan_input_t{}
    // ... set up input fields

    // Call scan function
    cResult := C.snippets_wrapper_scan(&cInput)
    defer C.snippets_wrapper_free_result(cResult)

    // Process results
    // ...
}
```

## Data Types

### C Structures

#### `wrapper_scan_input_t`
- `md5`: 16-byte MD5 hash of the file
- `file_path`: File path string
- `hashes`: Array of WFP hashes (uint32_t*)
- `lines`: Array of corresponding line numbers (uint32_t*)
- `hash_count`: Number of hashes
- `total_lines`: Total lines in file

#### `wrapper_scan_result_t`
- `match_type`: Match type (WRAPPER_MATCH_NONE, WRAPPER_MATCH_FILE, WRAPPER_MATCH_SNIPPET, WRAPPER_MATCH_BINARY)
- `error_msg`: Error message string (if any)
- `matches`: Array of match information
- `match_count`: Number of matches found

#### `wrapper_match_info_t`
- `file_md5_hex`: MD5 of matched file (hex string)
- `hits`: Number of matching hits
- `range_count`: Number of matching ranges
- `range_from`: Array of range start positions
- `range_to`: Array of range end positions
- `oss_line`: Array of corresponding OSS file line numbers

## API Functions

### `snippets_wrapper_init(const char *oss_db_name, bool enable_debug)`
Initializes the wrapper and loads the LDB database.

**Parameters:**
- `oss_db_name`: Name of the OSS database (e.g., "oss")
- `enable_debug`: Enable debug logging via scanlog

**Note:** Must be called before any scanning operations.

### `snippets_wrapper_scan(wrapper_scan_input_t *input)`
Scans the provided WFP data against the database.

**Parameters:**
- `input`: Pointer to input data structure

**Returns:**
- Pointer to result structure (must be freed with `snippets_wrapper_free_result`)

### `snippets_wrapper_free_result(wrapper_scan_result_t *result)`
Frees memory allocated for scan results.

**Parameters:**
- `result`: Pointer to result structure to free

### `snippets_wrapper_cleanup()`
Cleanup function (currently no-op as LDB handles cleanup automatically).

## Dependencies

The library requires the following system libraries:
- LDB (SCANOSS database library)
- OpenSSL (libssl, libcrypto)
- zlib
- pthread

On Ubuntu/Debian:
```bash
sudo apt-get install libssl-dev zlib1g-dev
```

## Debug Mode

When debug mode is enabled with the `-q` flag:
- C code uses `scanlog()` for debug output with microsecond timestamps
- Go code prints debug messages to stderr
- Useful for troubleshooting and performance analysis

Example debug output:
```
1759355140418426 snippets_wrapper_init START
1759355140418448 About to call ldb_read_cfg for: oss/wfp
1759355140418494 ldb_read_cfg returned, keys=1
[GO DEBUG] About to call C.snippets_wrapper_scan
[GO DEBUG] hash_count=12, total_lines=763
```

## Important Notes

1. **Initialization**: Always call `snippets_wrapper_init()` before using scan functions
2. **Cleanup**: Use `defer` for proper resource cleanup
3. **Memory Management**: C memory must be allocated for hash and line arrays
4. **Static Linking**: The wrapper uses static linking with `libsnippets_wrapper.a`
5. **Thread Safety**: The library is not thread-safe by default
6. **Database Path**: Ensure the LDB database exists at the specified path

## Examples

See `wfp_scanner.go` for a complete working example that:
- Parses WFP files
- Allocates C memory properly
- Handles results and prints matches
- Includes proper error handling
