# PAPA

A native C++20 port of Mandiant's [CAPA](https://github.com/mandiant/capa).

The motivation is simple - CAPA's analysis is great, but it's slow. 
PAPA keeps CAPA's rule semantics and report format, but it's much faster!

## Advantages

- **Full CAPA rule syntax** - every feature, statement, subscope, and
  `count(...)` range, including `or fewer` / `or more`, plus COM class and
  interface lookups.
- **Byte-identical text report** and a **JSON report** that is
  field-compatible with `capa.exe --json`, so any tool that already consumes
  CAPA reports works unchanged.
- **No runtime** - a single native executable!
- **100% capability parity** - 0 FPs and 0 FNss across a
  42-binary x86/x64 corpus.
- **Much faster : )** - roughly 7x on small to medium binaries.
- **Minimal dependencies** - only Zydis for disassembly, miniz for zlib decompression (needed for FLIRT) & doctest for unit
  testing.

## How it works

The pipeline mirrors CAPA's, porting vivisect's analysis wherever parity demands
it:

1. **PE parsing** - a bounds-checked parser reads headers, sections, imports
   (including delay and by-ordinal imports), exports, TLS callbacks, and base
   relocations.
2. **CFG recovery** - functions are seeded from the entry point, exports, TLS
   callbacks, and the x64 `.pdata` table, then extended by recursive descent.
   Switch tables, no-return calls, tail calls, and vivisect's shared-block model
   were all ported faithfully.
3. **Emulation-driven discovery** - a security-bounded port of vivisect's Intel
   emulator (i386 and amd64) recovers functions reachable only through
   relocation pointers, including stripped 32-bit binaries with no `.pdata`. It
   is abstract interpretation only: it never executes native code, never
   dereferences an emulated value as a host pointer, and is bounded against
   crafted input.
4. **Disassembly** - Zydis decodes each reachable byte. PAPA tags every operand
   (`kImm`, `kImmMem`, `kPcRel`, `kRipRel`, `kReg`, `kRegMem`, `kSib`) to match
   vivisect's semantics so rules match identically.
5. **FLIRT** - a faithful port of CAPA's `viv_utils.flirt` pipeline reads the
   embedded IDASGN signatures and marks statically-linked library code, so rules
   don't fire inside the CRT.
6. **Feature extraction** - per-scope extractors emit the same features CAPA
   produces: `api`, `mnemonic`, `number`, `offset`, `bytes`, `string`,
   `operand[i].number`, plus characteristics (`nzxor`, `peb access`, `loop`,
   `tight loop`, `stack string`, etc).
7. **Rule matching** - a `Statement` tree is evaluated against a `FeatureSet`.
   Each rule runs a boolean fast path first. Matches inject
   `MatchedRule` entries so later rules can reference them via `match:`.

## Performance

Measured against `capa.exe 9.4.0` with the matching `capa-rules-9.4.0` ruleset on
the same machine (`--json`, output redirected).

| Sample        | Size    | PAPA  | CAPA  | Speedup |
|---------------|---------|-------|-------|---------|
| `calc.exe`    | ~27 KB  | 1.6 s | 11 s  | ~7x     |
| `notepad.exe` | ~200 KB | 7 s   | 48 s  | ~7x     |
| `7z.exe`      | ~549 KB | 29 s  | 219 s | ~8x     |
| `capa.exe`    | ~7 MB   | 268 s | 275 s | ~1x     |

PAPA is ~7-8x faster on small to medium binaries!

## Structure

Headers live under `include/papa/` and are mirrored 1:1 by implementation files
under `src/`.

```text
include/papa/
  constants.h           shared numeric and string constants
  engine.h              Statement tree, Result, match()
  exceptions.h          PapaError, ErrorKind, Expected alias
  loader.h              Metadata, sample hashes, collect_metadata
  main_driver.h         CLI Args, parse_args, run, exit codes
  version.h             version banner

  capabilities/
    common.h            find_file_capabilities, has_static_limitation
    static_.h           per-scope find_*_capabilities orchestrators

  features/
    address.h           Address variant (absolute, RVA, file offset, ...)
    basic_block.h       BasicBlock tag feature
    common.h            String, Substring, Regex, Bytes, Number, Os, ...
    feature.h           Feature base, FeatureSet with tag indices
    file.h              Import, Export, Section, FunctionName
    insn.h              Api, Mnemonic, Property, OperandNumber, ...
    extractors/
      base_extractor.h  StaticFeatureExtractor abstract interface
      helpers.h         generate_symbols, normalize_dll_name
      pefile.h          file-scope extractors (imports, exports, ...)
      pefile_extractor.h PefileFeatureExtractor concrete backend
      strings.h         ASCII + UTF-16LE string scanner
      papa_native/
        backend.h       PapaNativeBackend (image + CFG + imports)
        basic_block.h   tight_loop, stack_string
        cfg.h           Function, BasicBlock, Cfg::recover
        disassembler.h  Zydis wrapper with operand classification
        extractor.h     PapaNativeStaticExtractor concrete backend
        function.h      function-scope characteristics
        global_.h       Os, Arch, Format extraction
        indirect_calls.h backward-slice register resolution
        insn.h          per-instruction extractors
        jump_tables.h   x86 / x64 switch-table resolution
        noreturn.h      vivisect no-return analysis port
        library_signatures.h thunk classifier + embedded FLIRT set
        flirt/          faithful viv_utils.flirt port:
          flirt_reader.h     decompress and parse the signature trees
          flirt_matcher.h    pattern + tail-CRC16 + tail-byte matching
          flirt_classifier.h reference validation and name assignment
        emu/            security-bounded vivisect Intel emulator (i386 + amd64):
          registers.h        RegisterFile with meta-register encoding
          memory.h           SandboxMemory (read-only backing + capped overlay)
          intel_emulator.h   operand layer + execute_opcode
          workspace_emulator.h runFunction driver over a bounded work-queue
          watcher.h          emucode behavioral filter (looks_good)
          taints.h           sentinels for unknown state
          emu_discovery.h    relocation-pointer candidate discovery

  pe/
    pe_image.h          ParsedSection, ParsedImport, relocations(), PeImage
    pe_parser.h         PeParser::parse / parse_file
    pe_structs.h        IMAGE_* POD structs
    ordinal_names.h     ws2_32 / oleaut32 ordinal-to-name lookup

  render/
    json.h              CAPA-schema JSON renderer
    result_document.h   ResultDocument, MatchNode, build_document
    spec.h              ATT&CK / MBC spec parsing (text + JSON)
    table.h             decoupled, rich-identical table engine
    text.h              default / verbose / vverbose text renderer

  rules/
    com_lookup.h        ComEntry, lookup_com (CLSID + IID tables)
    optimizer.h         reorders statement children by selectivity
    parser.h            RuleParser
    rule.h              Rule, RuleMeta, Scopes
    ruleset.h           RuleSet (subscope extraction + topo sort)
    scope.h             Scope enum

  util/
    expected.h          std::expected shim
    hash.h              SHA-256, SHA-1, MD5
    hashing.h           hash mixing helpers (FNV-1a, mix64)
    json_writer.h       streaming JSON emitter
    string_utils.h      trim, ascii / UTF-16 printable, escape
    yaml.h              YAML subset parser (block-style only)
```

```text
src/                    implementation files, mirrors include/papa/
tests/
  unit/                 doctest suite
  integration/
    run_parity.py       diffs PAPA vs capa.exe rule-match sets
    parity_tool.py      multi-binary corpus parity driver
tools/papa/             CLI entry (papa_main.cpp)
third_party/            Zydis (vendored) and doctest (single header)
```

## Build

```bash
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel
```

The CLI lands at `build/tools/papa/Release/papa.exe`.

## Testing

```bash
ctest --test-dir build -C Release
```

Point `PAPA_TEST_FIXTURES` at a folder of sample PEs to enable the
fixture-backed cases - without it they skip cleanly and the suite still passes.

In addition to its unit tests, PAPA was also tested against a corpus of 42 PE files:
```
7z.exe
attrib_x64.exe
attrib_x86.exe
bcrypt_x64.dll
calc.exe
capa.exe
certutil_x64.exe
certutil_x86.exe
cff_explorer.exe
chrome.exe
cmd_x64.exe
cmd_x86.exe
everything.exe
find_x86.exe
gzip_mingw.exe
hostname_x64.exe
hostname_x86.exe
ipconfig_x64.exe
ipconfig_x86.exe
msedge.exe
netapi32_x64.dll
netapi32_x86.dll
netstat_x64.exe
netstat_x86.exe
notepad.exe
ping_x64.exe
ping_x86.exe
powercfg_x64.exe
reg_x64.exe
reg_x86.exe
robocopy_x64.exe
robocopy_x86.exe
schtasks_x64.exe
schtasks_x86.exe
sc_x64.exe
sc_x86.exe
systeminfo_x64.exe
tasklist_x64.exe
where_x64.exe
where_x86.exe
73,728 whoami_x64.exe
whoami_x86.exe
```
PAPA reaches 100% recall and 100% precision on the 42-binary validation corpus, so there are no
known false positives or false negatives on tested samples.

Perfect match-set parity on an *arbitrary* binary is currently not promised, so an unseen sample can still diverge a bit. 
In practice, precision and recall should stay ~100%.
