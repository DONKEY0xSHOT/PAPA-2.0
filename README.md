# PAPA

A native C++20 port of Mandiant's [CAPA](https://github.com/mandiant/capa). 

The motivation is simple - CAPA's analysis is excellent, but it's slow. PAPA keeps CAPA's rule semantics and report format, but it's is much faster!

## Advantages

- **Full CAPA rule syntax**
- **Compatible JSON Output**
- **No runtime** - A single native executable!
- **Much better performance : )**
- **Minimal dependencies** - only Zydis for disassembly and doctest for unit testing

## How it works

The pipeline mirrors CAPA's:

1. **PE parsing** - the parser reads headers,
   sections, imports, exports, delay imports, and TLS callbacks.
2. **CFG recovery** - Function entries are seeded from the PE entry point,
   exports, TLS callbacks, and the x64 `.pdata` exception directory.
   Recursive descent extends each function until a return or an unconditional
   branch.
3. **Disassembly** - Zydis decodes each reachable byte. 
1. PAPA wraps each decoded instruction with operand
   classifications (`kImm`, `kImmMem`, `kPcRel`, `kRipRel`, `kReg`,
   `kRegMem`, `kSib`) compatible with vivisect's semantics so CAPA rules
   match identically.
4. **Feature extraction** - Per-scope extractors emit the same features
   CAPA produces: `api`, `mnemonic`, `number`, `offset`, `bytes`, `string`,
   `operand[i].number`, plus characteristics (`nzxor`, `peb access`,
   `loop`, `tight loop`, `stack string`, etc).
5. **Rule matching** - A `Statement` tree is evaluated against a `FeatureSet`.
   Each rule first runs through a boolean fast path that skips result-tree
   allocations; only on success does it run the full evaluator that the
   renderer needs. Successful matches inject `MatchedRule` entries so later
   rules can reference them via `match:`.

## Structure
Headers live under `include/papa/` and are mirrored 1:1 by implementation
files under `src/`.

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

  pe/
    pe_image.h          ParsedSection, ParsedImport, PeImage
    pe_parser.h         PeParser::parse / parse_file
    pe_structs.h        IMAGE_* POD structs

  render/
    json.h              CAPA-schema JSON renderer
    result_document.h   ResultDocument, build_document
    text.h              default / verbose / vverbose text renderer

  rules/
    com_lookup.h        ComEntry, lookup_com (CLSID + IID tables)
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
src/                    implementation files. mirrors include/papa/
tests/
  unit/                 doctest suite
  integration/
    run_parity.py       diffs PAPA vs capa.exe rule-match sets
tools/papa/             CLI entry (papa_main.cpp)
third_party/            Zydis (vendored) and doctest (single header)
docs/                   BUILD.md, USAGE.md, ARCHITECTURE.md
```

## Performance

Measured against `capa.exe 9.4.0` with the matching `capa-rules-9.4.0`
ruleset on the same machine.

| Sample        | Size   | PAPA | CAPA | Speedup |
|---------------|--------|------|------|---------|
| `notepad.exe` | 200 KB | 7 s  | 51 s | ~7x     |

The speedup is significant mostly on small to medium binaries because CAPA
pays a fixed cost for Python interpreter startup, vivisect's
import-time analysis, and per-scope Python overhead. PAPA's startup is
roughly constant. On very large binaries the per-instruction cost
dominates and the two converge : )

## Limitations

A small number of rules diverge from CAPA's matches, falling into two
categories. Both are quantifiable and bounded.

- **False positives, ~2-3 per medium binary.** PAPA matches rules at
  CRT helper functions (TLS init, heap setup) where CAPA suppresses them
  via FLIRT signatures. PAPA does not yet have FLIRT, so these helpers are
  treated as user code.
- **False negatives, ~2-3 per medium binary.** A small set of functions
  vivisect recovers using heuristics that PAPA's
  recursive-descent plus pdata seeding does not yet replicate.

Concretely, on `notepad.exe` PAPA achieves 94.6% recall and 100%
precision. On `chrome.exe` recall stays around 90% and precision around 92 to 97%. Since CAPA is designed for initial triage, the remaining gap is well within useful range and the vast majority of rules behave identically!

## TODO

- **FLIRT signature support** - It would solve most of the false positives (CRT helpers would be
  suppressed) and the false-negative gap (more accurate function
  boundaries via FLIRT-recognized prologues).
- **Broader regex compatibility** - for rules whose patterns use Python `re`
  features `std::regex` rejects.