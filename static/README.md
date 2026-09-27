# Static Analyser Tool (binary-level)

The static binary analyser detects potential Linux system calls in **x86-64 ELF binaries**, including statically and dynamically linked applications. It combines ELF symbol information, disassembly and backward value tracking, then follows calls into shared libraries. Capstone provides the disassembler and LIEF provides ELF parsing.

The analyser aims to overestimate the system calls an application may use, but its heuristics can also miss calls. A detected syscall is not necessarily executed, and an undetected syscall is not proof that it is unused.

This README describes the code at `431f2a6` (21 September 2026). The [changelog](#changelog-since-the-july-2023-tfe-submission) summarises changes since the version submitted as the TFE (final-year thesis), commit `29c6afb68bfb997bf31dc1ca198dd100e7c7d079` of 12 July 2023.

## Requirements

- Python 3 on Linux, with an x86-64 ELF application to analyse.
- The packages in [requirements.txt](requirements.txt): `capstone==5.0.9`, `lief==1.0.0`, `r2pipe==1.9.8` and `setuptools==84.0.0`. The file also pins the package installer to `pip==26.2.1`.
- For dynamically linked applications, access to the corresponding shared libraries. The analyser uses `ldd` to locate dependencies, with a fallback search through `LD_LIBRARY_PATH` and its configured library directories.
- Optional system tool: `radare2`, for the dynamic resolver-discovery step of `--analyse-linker`. Install it separately; `requirements.txt` installs its Python interface, `r2pipe`, but not the `radare2` executable.

From this directory (`static/`):

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Getting started

```bash
python3 static_analyser.py --app /path/to/application
python3 static_analyser.py --help
```

By default, the tool prints detected syscalls as `name : number`. Verbose output, CSV output, file logging and linker analysis are disabled. Warnings and errors are enabled.

To write only CSV results to standard output, while retaining errors on standard error:

```bash
python3 static_analyser.py --app /path/to/application \
    --custom-syscalls-map ./syscalls_map \
    --csv=true --display=false --verbose=false \
    --show-nb-syscalls=false --show-warnings=false > syscalls.csv
```

The CSV begins with `# syscall, used`, followed by one row per entry in the syscall map, formatted as `<syscall_name,Y|N>` (for example, `read,Y`). These are names, not syscall numbers. `Y` means the syscall was detected; `N` means it was not detected. No CSV file is created automatically: use shell redirection as above.

To display the count without verbose output:

```bash
python3 static_analyser.py --app /path/to/application \
    --display=false --show-nb-syscalls=true
```

To prioritise a directory containing the application's libraries, including an alternative, unstripped libc or loader:

```bash
python3 static_analyser.py --app /path/to/application \
    --library-path /path/to/libraries
```

Results depend on the binary, the libraries selected for analysis, the syscall map and the options used. Relative library paths are resolved from the working directory; run from the appropriate directory or provide suitable library search paths.

### Command-line options

Boolean options accept `true`/`false` (also `yes`/`no`, `t`/`f`, `y`/`n` and `1`/`0`). A boolean option without a value enables it. Supply an explicit integer to `--max-backtrack-insns`.

| Option | Default | Purpose |
| --- | --- | --- |
| `--app`, `-a` | Required | Path to the application. |
| `--custom-syscalls-map`, `-s` | Bundled `syscalls_map` | Select the syscall number/name table. |
| `--max-backtrack-insns`, `-b` | `20` | Maximum number of preceding instructions considered during backtracking. |
| `--library-path`, `-p` | None | Prepend a library directory to the search path, including for the loader. |

Display and logging:

| Option | Default | Purpose |
| --- | --- | --- |
| `--verbose`, `-v` | `false` | Print analysis progress and details. |
| `--show-warnings`, `-w` | `true` | Print warnings to standard output. |
| `--show-errors`, `-e` | `true` | Print errors and critical warnings to standard error. |
| `--display`, `-d` | `true` | Print the detected syscall names and numbers. |
| `--show-nb-syscalls`, `-n` | Follows `--verbose` | Print the total number of detected syscalls. |
| `--csv`, `-c` | `false` | Print the syscall map with `Y`/`N` detection results. |
| `--log`, `-l` | `false` | Write analysis logs to files. |
| `--log-to-stdout`, `-L` | `false` | Enable logging and send logs to standard output. |

File logging creates or clears `backtrack.log`, `lib_functions.log` and, while `utils.DEBUG` is enabled, `debug.log` in `../logs/`, relative to the working directory.

Analysis options:

| Option | Default | Purpose |
| --- | --- | --- |
| `--skip-data`, `-k` | `false` | Let Capstone skip data encountered in code; this may misinterpret subsequent bytes. |
| `--all-imported-functions`, `-i` | `true` | Analyse every imported function of the main ELF, even if no call to it was identified. |
| `--search-function-pointers`, `-f` | `true` | Treat candidate values in instructions as potential function pointers. |
| `--search_raw_data`, `-r` | `false` | Read raw values from the binary when relocation information cannot resolve a memory reference. |
| `--analyse-linker`, `-A` | `false` | Analyse the loader entry function and, where lazy binding is used, its PLT resolver. |
| `--user-input`, `-u` | `Y` | Handle proposed fallbacks: `A` asks, `Y` accepts, `N` rejects. |
| `--backtrack-potential-values`, `-B` | `false` | Backtrack additional candidate values; can be significantly slower. |
| `--backtrack-memory`, `-m` | `false` | Track writes to memory locations. |
| `--backtrack-stack`, `-S` | `true` | Track writes to stack locations. |

**Changed short options since the TFE:** the backtracking instruction limit is now `-b`; `-B` enables backtracking of potential values. Skip-data is now `-k`; `-s` selects a syscall map.

### Syscall map

The default [syscalls_map](syscalls_map) is loaded relative to the analyser's own directory, independently of the working directory. It is a bundled snapshot, last updated in July 2024; it is not generated from the running kernel. Select a suitable table explicitly with `--custom-syscalls-map` when comparing results across systems. Omitting this option prints a warning that the default map is being used.

The parser accepts a whitespace-separated two-column number/name table (in either order), or the Linux syscall-table layout `<number> <abi> <name> <entry point>`. It locates the first syscall using number `0` (`read` in the multi-column layout), then reads subsequent rows using those columns. Blank lines and `#` comments are ignored.

### Linker analysis

`--analyse-linker=true` adds analysis of the loader's entry function and, if lazy binding is detected, its relocation resolver. To discover the resolver address, the optional `r2pipe`/`radare2` path **starts the application under a debugger and runs to its entry point**. This option therefore includes a dynamic step. If discovery fails, the analyser can propose a known resolver name for supported loaders; `--user-input` controls whether that fallback is accepted. Stripped loaders may lack the symbols needed to resolve it.

## Architecture

The implementation has **eight core Python modules**, plus the syscall map and test tools. Loader analysis, including resolver discovery, is implemented in `library_analyser.py`.

| Module | Responsibility |
| --- | --- |
| [static_analyser.py](static_analyser.py) | Parse options, initialise the syscall map, construct the analysers, collect results and format output. |
| [code_analyser.py](code_analyser.py) | `CodeAnalyser`: disassemble executable sections with Capstone, detect `syscall` instructions and calls to the `syscall()` wrapper, follow calls and candidate function pointers, recover arguments to runtime-loading functions. |
| [library_analyser.py](library_analyser.py) | `LibraryUsageAnalyser`, `Library` and `LibFunction`: locate dependencies, resolve PLT/GOT targets and named functions, recursively analyse library functions, coordinate pending `dlsym` resolutions and optionally analyse the loader. |
| [elf_analyser.py](elf_analyser.py) | `ELFAnalyser` and `ELFBinary`: validate and parse ELF files with LIEF; inspect symbols, sections, strings, relocations and function boundaries. |
| [asm_code_utils.py](asm_code_utils.py) | `Address` and assembly helpers: resolve operands and call destinations, compute address expressions, backtrack register, memory and stack values. |
| [syscalls.py](syscalls.py) | Load the number-to-name syscall map and provide wrapper aliases. |
| [utils.py](utils.py) | Shared options and defaults, logging, diagnostics and small conversion/arithmetic helpers. |
| [custom_exception.py](custom_exception.py) | `StaticAnalyserException`, with a critical/non-critical error distinction. |

Analysis starts with syscall wrapper names found in ELF symbols. `CodeAnalyser` then scans the main binary's executable sections (PLT entries are handled through function resolution), adds syscalls discovered by backtracking, and delegates library calls to `LibraryUsageAnalyser`. Each analysed library has its own `CodeAnalyser` and `ELFAnalyser`; shared caches prevent repeatedly analysing the same function. Pending `dlsym`/`dlvsym` names are retried across the main binary and its libraries until no further progress is possible.

[![Current architecture of the static analyser](images/code_structure.svg)](images/code_structure.svg)

Diagram: [editable draw.io source](images/code_structure.drawio) · [SVG](images/code_structure.svg) · [PDF](images/code_structure.drawio.pdf). Edit the `.drawio` source in draw.io/diagrams.net and export SVG/PDF after changes. The adjacent saved HTML page and its `_files` directory are historical browser captures, not the diagram source.

## Limitations

The analyser cannot guarantee the absence of false negatives, even though several heuristics favour overestimation.

- **Environment and runtime loading.** Library discovery reflects the environment used for analysis, including `LD_LIBRARY_PATH` and the dependencies reported by `ldd`. Changes to `LD_LIBRARY_PATH`, `LD_PRELOAD` or the available libraries at execution time can change which code runs and which syscalls it uses. The same applies to libraries selected by `dlopen`; computed library or symbol names that cannot be recovered statically may leave targets unresolved.
- **Limited backtracking.** The analyser walks backwards through preceding instructions without exploring alternative control-flow paths or propagating values between functions. It can therefore miss alternative syscall IDs or IDs set in another function. Backtracking also stops at the configured instruction limit (20 by default) or a known function boundary; if the boundary is unknown, it can fall back to the section start. Multi-step construction of register values is not fully supported, and writes smaller than 16 bits use an approximation with a warning.
- **Disassembly and missing metadata.** Mixed code and data, stripped symbols, or missing function-boundary information can cause instructions to be missed or misinterpreted. Symbol and unwind information such as `.eh_frame` help identify functions, but recovery after an undecodable region depends on finding another known function or symbol. Enabling `--skip-data` does not guarantee correct recovery.
- **Obfuscation and packing.** Obfuscated binaries can hide call targets and make disassembly unreliable. Packed binaries may only expose their actual program code after unpacking at runtime; the analyser does not unpack them or reconstruct runtime-generated code.
- **Overestimation.** The analyser scans executable sections of the main binary and the bodies of discovered library functions without proving that every instruction is reachable. It can include syscalls in branches that the application never takes, for example library branches requiring argument values that are never passed. Analysing all imports and treating candidate values as function pointers can add unused functions or spurious targets. Conversely, an indirect call whose target cannot be resolved can still be missed.
- **Partial results.** Unavailable libraries and loader-specific behaviour can reduce coverage. Some recoverable errors allow analysis to continue with partial results, so a successful exit status alone does not establish complete coverage.
- **Shared process state.** Only one independent analysis per Python process is supported: library and analysed-function caches are shared between instances. Run the CLI separately for each application.

## Tests and benchmarks

Run the Python regression suite from `static/` after installing the requirements:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

The suite covers ELF boundaries and reads, backtracking, PLT/GOT resolution, runtime symbol loading, library discovery, CLI output/errors and performance-sensitive lookups.

[test_suite/](test_suite/) contains C/assembly examples and libc functional tests. Its [benchmark.sh](test_suite/benchmark.sh) builds them with `-O0`, `-O1`, `-O2`, `-O3`, `-Os` and `-Og`, and compares static results with `strace`/`ltrace`. Inspect the available commands from that directory:

```bash
cd test_suite
bash benchmark.sh -h
```

Building/running the benchmarks requires GCC, Make, the development libraries used by the Makefiles (including libcrypt), and `strace`/`ltrace` for dynamic traces. The benchmark script rebuilds binaries and replaces its result files. It enables several analysis options that differ from the CLI defaults, including linker analysis, skip-data and raw-data lookup. Historical measurements in `tests/data/` and `test_suite/results*` reflect their original binaries, libraries and machines; they are not a portable accuracy or performance guarantee.

## Changelog since the July 2023 TFE submission

Scope: changes to the static analyser and its tests after `29c6afb68bfb997bf31dc1ca198dd100e7c7d079` (12 July 2023), through `431f2a6` (21 September 2026). Entries group related commits by capability rather than listing every intermediate experiment or results-only commit. The original version already supported syscall instruction backtracking, symbol-based detection and recursively following library calls through PLT/GOT.

### September 2023: runtime loading and broader call discovery

- Added argument recovery and library/function discovery for `dlopen`, `dlsym` and `dlmopen`, including library paths and `dlopen(NULL, ...)` handling (`2e28c6d`, `84bcd4d`, `546caea`).
- Added indirect call and function-pointer discovery, RIP-relative operands and `lea` handling (`281e067`, `27cba6a`, `a22a74a`).
- Extended analysis to called functions outside `.text`, and added recovery at the next known function when data interrupts disassembly (`6a7ab1d`, `d5598b8`).
- Added call-site handling of the libc `syscall()` wrapper and optional analysis of all imports in the main executable (`8a6bf4b`, `0f5591a`).
- Introduced `ELFBinary`, separated direct dependencies from additional libraries reported by `ldd`, and corrected duplicate analysis of functions with aliases (`ebf7e82`, `3df7c97`, `c55f958`).
- Replaced the hardcoded syscall dictionary with a loadable map, refreshed the bundled table, and centralised defaults in `utils.py` (`0548a82`, `fa9b195`).

### October-November 2023: assembly helpers and regression benchmarks

- Added `dlvsym` recognition and processing of runtime symbol lookups originating in libraries, including lookups encountered before the required library is discovered (`2fd94b4`, `74999c9`, `c1d2526`).
- Expanded function-pointer detection to candidate immediate and memory operands, and made pointer discovery and raw-data lookup configurable (`1d1a46d`, `cbe5115`, `d5e2dd9`).
- Introduced `asm_code_utils.py` and the `ELFAnalyser` class; consolidated address computation and value backtracking, including register/address expressions and backtracking limits (`f4b9081`, `af70ba0`, `e223307`).
- Improved handling of binaries without shared libraries, unnamed/aliased functions, invalid instruction ranges and errors; added a separate error-display option (`923a2d4`, `a6c054f`, `f60c3cf`).
- Added the C/assembly and libc benchmark suite, optimisation-level builds and comparisons with dynamic traces (`259c11e`, `92629fb`, `132e55f`).

### December 2023-June 2024: loader analysis

- Added resolution of library calls that do not go through PLT (`6f5cf26`).
- Added loader entry-function analysis, then developed resolver discovery using a debugger with a known-name fallback (`1e07f39`, `7f80eb7`, `f700275`). Earlier experimental resolver-discovery approaches were superseded.
- Added linker-analysis and fallback-interaction options, and detection of whether lazy binding requires the PLT resolver (`2444e42`, `cec7277`).
- Adapted the code to LIEF API changes, including symbol-version handling (`21da399`, `92eee86`). Removed the TFE's Capstone 4.0.2 / LIEF 0.13.0 version pins and added `setuptools` to the requirements (`a546364`).

### July-September 2024: executable sections, memory and stack tracking

- Extended the main-binary scan from `.text` to all executable sections, with separate handling of PLT entries; corrected `.rodata` lookup (`cc3c1a1`).
- Improved recognition of jump-based function calls, external function pointers and dependencies recorded with relative paths (`8c442a6`, `5ef319f`, `d4629c1`, `0c80813`).
- Updated the syscall table and adapted the code to LIEF 0.15 (`8ca229e`, `1b6e70c`).
- Added memory and stack backtracking and constrained main-binary backtracking to known function boundaries, with follow-up corrections (`00a1499`, `2960b6e`, `b35bf01`, `59b0452`, `3493164`).
- Extended move-instruction recognition and improved function-boundary recovery for stripped loaders (`776d9b2`, `26140f2`).
- Made fallback interaction non-interactive by default, added a preferred library directory and independent syscall-count output (`430a70f`, `96b4d01`, `ab3563e`).
- Expanded benchmark cases for function pointers and stack values and separated program output from trace output (`48d2172`, `a92c9c1`, `ac931f3`).

### 2025: disassembly recovery

- When recovering after interrupted disassembly, use the earliest available next-function or next-symbol address, since either source can provide the better boundary (`e65498a`, 24 January). The April commit only added development notes (`9c84baf`).

### September 2026: correctness, diagnostics and performance

- Fixed ELF section containment, raw-memory read widths, invalid string/ELF handling, exact backtracking limits and restoration of backtracking state after errors. Added section-boundary fallback when a function start is unknown (`576ba89`).
- Fixed runtime-loading recovery, iteration while libraries are being registered, empty library-path entries, independent module imports and propagation of CLI failure status. Added the initial Python regression suite (`576ba89`).
- Clarified implementation documentation and remaining limitations (`5e3ca62`).
- Reworked pending `dlsym` resolution into repeated passes across the main binary and libraries, preserving unresolved names until library discovery stops making progress and respecting each binary's library scope (`431f2a6`).
- Corrected signed moves (`movsx`/`movsxd`), stack/memory write detection, register aliases, partial-write diagnostics, recovery after an invalid first instruction, and PLT/GOT decoding, including signed displacements and both PLT sections (`431f2a6`).
- Hardened library lookup and registration, GNU linker-script parsing, missing-`ldd` fallback, versioned lookup fallback, unknown function sizes and prioritised loader paths (`431f2a6`).
- Made syscall-map loading atomic and failures recoverable, located the default map relative to the script, corrected a wrapper alias, and ensured file logging creates its directory and clears the relevant files (`431f2a6`).
- Added a cached, sorted function-address index and reused decoded instruction details in backtracking, with regression coverage for these optimisations (`431f2a6`).
- Expanded the Python suite to 70 tests across general, review, runtime-resolution and performance regressions (`431f2a6`). Historical benchmark results were also refreshed during this period; they should be interpreted in their original environment.

For the full history and implementation diff, from this directory:

```bash
git log --date=short --oneline 29c6afb68bfb997bf31dc1ca198dd100e7c7d079..431f2a6 -- .
git diff 29c6afb68bfb997bf31dc1ca198dd100e7c7d079 431f2a6 -- .
```
