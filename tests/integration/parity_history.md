# PAPA vs capa.exe 9.4.0 — parity history

Per-binary recall / precision and false-negative (FN) / false-positive (FP)
counts after each major change on `flirt-cfg-parity`, measured with
`tests/integration/parity_tool.py report` against the cached capa --json
references. "—" = not measured at that point (e.g. msedge timed out before the
perf fix).

## Complete parity (2026-06-26, forty-two binaries, capability-only)

The corpus expanded to forty-two binaries (the eighteen below plus System32 x64
and SysWOW64 x86 command-line tools: attrib, certutil, cmd, hostname, ipconfig,
netstat, powercfg, reg, robocopy, schtasks, sc, systeminfo, whoami, and others).
**Every binary reaches 100% recall and 100% precision, 0 FP / 0 FN** — complete
capability parity across the whole corpus, 589 unit cases green. Reproduce with
`_vivscratch/parity_sweep.py <keys...>` (lib-filtered) or `parity_tool.py report`.

The last three diffs were closed this milestone, each a faithful vivisect port:

| Diff (binary)                                | Mechanism / commit                                                                                                |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `compute adler32 checksum` FN (certutil_x64) | x64 emucode RIP-relative `lea`-target candidate (`7f56efc`)                                                       |
| `resume thread` FN (cmd_x64)                 | XMM/SSE + `cmov` + bit-test/rotate/xchg emulator opcodes so the reloc-pointer stub validates as code (`b03d48e`)   |
| `terminate process` FP (certutil_x64)        | `.pdata` v2-unwind break (`a433103`) + shared-block keep-continuations (`2028280`) + per-tree FLIRT priming (`bdcb94d`) |

The terminate-process FP needed all three coupled commits: per-tree FLIRT marks
the mainCRTStartup entry a library function (as capa does), the v2-break stops
over-seeding its tail, and the shared-block fix keeps the capability functions
sharing the entry's region (calc 0x140001600) as their own non-library functions
so they are still extracted. A prior single-piece attempt netted zero parity and
was reverted; the three together hold across the full corpus.

## Validation corpus (2026-06-19, eighteen binaries, capability-only)

Validation expanded from the seven fixtures to an eighteen-binary corpus: the
seven plus eleven native PEs from System32 (x64), SysWOW64 (x86), and Program
Files (7-Zip x64, a MinGW gzip), staged under `corpus/` with cached capa
references in `corpus/cache/`. Reproduce with `parity_tool.py report --papa ...
--rules ... --fixtures corpus --cache corpus/cache --keys <key=filename> ...`.

| Binary group (corpus keys)                                  | At 100/100 |
|-------------------------------------------------------------|:----------:|
| 7 fixtures (notepad calc chrome msedge cff_explorer capa everything) | yes |
| sys_where sys_ping sys_tasklist sys_bcrypt sys_netapi (x64)  | yes |
| wow_where wow_ping wow_find wow_netapi (x86)                 | yes |
| pf_gzip (MinGW x64)                                          | yes |
| pf_7z (x64)                                                  | yes |

Aggregate: all eighteen at 100% recall and 100% precision, 0 FP / 0 FN. The
expansion surfaced new capa-fidelity gaps, all closed by faithful ports:

- FLIRT tail bytes are now enforced at `kMaxPatternLength + crc_len + offset`
  (commit `c84566b`). The prior "not enforced" note was the offset bug in
  disguise (the offset is relative to the end of the pattern+CRC region, not
  absolute). Closed ping initialize-Winsock / send-ICMP / get-routing-table and
  bcrypt get-system-information FNs and the netapi create-or-open-file FP.
- Offset extraction now matches capa's i386 operand handling (commit `d210fcd`):
  `offset(0)` for a bare `[reg]`, the stack/frame exclusion keyed on
  `sib_encoded` not the operand kind, a no-base SIB displacement as an absolute
  (offset 0, e.g. `gs:[0x60]`), and the `add`-only struct-offset hint. Closed
  resolve-function-by-parsing-PE-exports (wow_where, wow_ping), get-ntdll-base
  (wow_netapi), and get-kernel32-base (bcrypt), and the get-ntdll / get-kernel32
  FPs the `offset(0)` emission first exposed on bcrypt and netapi.

The last gap, `pf_7z` `hash data with CRC32` @0x45f224, is now closed (the
eighteenth at 100/100). capa recovers that function (and a cluster of tiny
neighbors) in a region with no `.pdata` through a relocation pointer. vivisect
runs its pointers pass on every binary and, because amd64 populates no
function-entry signature tree, decides whether a pointer target is code purely
by emulation -- so closing this faithfully required extending PAPA's i386
discovery emulator to amd64 (64-bit register file with the RMETA_LOW32
zero-extend rule, rip-relative and 64-bit addressing, 8-byte stack and
push/pop/call/ret, amd64 taintregs, and faithful 64-bit shift/mul/div), then
running the reloc-pointer pass for x64-with-`.pdata` as well. Re-verified across
all eighteen binaries: no regression (the eleven previously-perfect x64 binaries
stay 100/100, the five x86 binaries are untouched). The prior note here -- that
the pointers pass was "emulator-free" and could simply be un-gated -- was wrong:
amd64 has no prologue signature tree, so the classification is emulation-only.

## Validation corpus (2026-06-20, forty-two binaries, capability-only)

The corpus grew again to forty-two binaries (the eighteen above plus more
System32 x64 and SysWOW64 x86 utilities). Of the diffs found, three were closed
faithfully against vivisect ground truth (run vivisect directly on the sample
for authoritative function and basic-block boundaries):

- `certutil_x86` get-number-of-processors false negative (`35a343e`): a
  feature-extraction fix, number suppression had over-suppressed `sub esp`.
- `ipconfig_x86` get-MAC false positive (`10426c8`): papa fell through an `int3`
  pad into the next function. Fallthrough now honors vivisect's full `IF_NOFALL`
  set, so function 0x4039fe ends where vivisect ends it.
- `robocopy_x86` get-process-heap-force-flags false positive (`50eb0f3`): papa
  kept a shared SEH funclet (0x413baf) as one basic block, while vivisect splits
  it at 0x413bb5 because a sibling function branches there. A final pass splits
  basic blocks at cross-function branch targets.

Result: forty of forty-two clean, no false positives among them. Two deep diffs
remain deferred:

- `certutil_x64` terminate-process false positive: papa marks the CRT entry
  0x14011a9d0 (mainCRTStartup) as application code because the embedded signature
  set, matched as one tree, makes mainCRTStartup ambiguous with a reference-free
  atlmfc signature (?AfxAbort). capa registers one FLIRT analyzer per `.sig` file
  and matches them in order, which resolves the ambiguity. Matching per signature
  file faithfully closes that gap, but it then unmasks an x64 CFG over-fold (papa
  folds capability functions like calc 0x140001600 into adjacent CRT entries that
  become library), and the natural fix for that (keep every absorbed `.pdata`
  continuation, the way vivisect keeps every `.pdata` begin) over-keeps in the
  certutil pattern: vivisect folds certutil 0x14011a760 but keeps calc 0x140001600,
  both `.pdata` begins reached only by a jump, because its `.pdata`-begin-to-function
  decision is order-dependent internal attribution papa does not replicate. The
  two changes net to no parity change, so they were reverted pending a faithful
  port of vivisect's function-discovery ordering.
- `certutil_x64` compute-adler32-checksum and `cmd_x64` resume-thread false
  negatives: x64 functions vivisect recovers through emulation-discovery passes
  papa does not yet run for x64 (the same class as the 7z CRC32 case).

## Current state (after the get-number-of-processors fix `0b5968a`, capability-only)

Parity is measured over CAPABILITY rules only: capa `meta.lib` rules are excluded
(capa matches them and emits them in `--json` but never lists them as capabilities
in its report). Counting them inflated recall by the nine always-shared lib rules.

| Binary        | Recall | Precision | FN | FP |
|---------------|-------:|----------:|---:|---:|
| notepad.exe   |  100%  |   100%    |  0 |  0 |
| calc.exe      |  100%  |   100%    |  0 |  0 |
| chrome.exe    |  100%  |   100%    |  0 |  0 |
| msedge.exe    |  100%  |   100%    |  0 |  0 |
| CFF Explorer.exe | 100% | 100%   |  0 |  0 |
| capa.exe      |  100%  |   100%    |  0 |  0 |
| Everything.exe (32-bit) | 100% | 100% |  0 |  0 |

Aggregate: all seven binaries at 100% recall AND 100% precision, with no false
positives or false negatives: complete capability parity. The last false positive,
a spurious msedge `get number of processors` match @0x14009a8d0, was closed
(`0b5968a`) by restricting the lea-displacement number to non-SIB operands. It had
been long assumed to be a deep CFG block-coverage over-reach, but papa and capa
recover nearly the same function there (527 vs 510 features) and the cause was a
feature-extraction over-emission: a `lea rcx, [r12 + 0xB8]` displacement surfaced
as `number(0xB8)`, which capa emits only for the non-SIB `i386RegMemOper` form.
The Everything 32-bit binary, which began the
project at 58.3% / 29 FNs, reached 100% through the discovery passes (M10 emulator,
C1+C2 reloc-driven pointers, C3 switch resolution) and a feature-extraction phase
that closed the last six false negatives: number-width masking (inspect section
memory permissions, persist via Run registry key), ws2_32/oleaut32 ordinal
resolution via vivisect's ordlookup (get local IPv4 addresses), api features for
calls to FLIRT-named local library functions (create thread), FLIRT references
validated only against local library functions and not imports (allocate thread
local storage, which also closed CFF Explorer's query-environment-variable FN as a
side effect), and jump-table case absorption into the dispatching function (check
for unmoving mouse cursor).

Post-100% fidelity work has held parity exactly. The faithful vivisect-pipeline
passes added after parity was reached, the no-return (noret) pass in particular
(exit/abort import-call fallthrough suppression plus the leaf-analysis fixpoint
that marks whole functions no-return), change no rule match on any of the seven
fixtures. They prune phantom blocks a binary otherwise decodes past an exit/abort
call and complete the discovery pipeline's fidelity without moving the numbers.
The msedge get-number-of-processors FP was confirmed not a no-return case (it was
later closed as a SIB-lea number over-emission, see above). The pass-order pass
(C5) then moved noret to run
last over the complete recovered function set on both the x64 and 32-bit paths,
matching vivisect's per-function noret module: re-measured parity is byte-for-byte
identical, so applying faithful noret to the 32-bit Everything recovery is
confirmed regression-free.

The Everything.exe row read 59.4% / FN 28 from M2 onward, but that value was
carried forward without re-measurement (it has no .pdata, so the x64-only M3
and the nzxor M4 were assumed no-ops). A full M5 re-measure shows 58.0% / FN 29.
Isolation runs confirm the 1-rule delta is NOT from the M4 nzxor change nor the
M5 SIB change (both measured identical with and without). It predates them on a
deferred 32-bit binary, so it is recorded, not chased.

## Recall (%) over milestones

| Binary        | M0 start | M1 IAT+CFG | M2 num/off | M3 chunks | M4 nzxor | M5 SIB | M6 jmptbl | M7 xsec | M8 flirt | M9 tailcall |
|---------------|---------:|-----------:|-----------:|----------:|---------:|-------:|----------:|--------:|---------:|------------:|
| notepad.exe   |   100    |    100     |    100     |   100     |   100    |  100   |   100     |  100    |   100    |    100      |
| calc.exe      |   100    |    100     |    100     |   100     |   100    |  100   |   100     |  100    |   100    |    100      |
| chrome.exe    |  92.3    |   97.8     |   98.9     |  98.9     |  98.9    |  98.9  |  98.9     |  100    |   100    |    100      |
| msedge.exe    |  (tmo)   |   97.1     |   99.0     |  99.0     |  99.0    |  99.0  |  99.0     |  99.0   |  99.0    |    100      |
| CFF Explorer  |  86.2    |    86.2    |   91.4     |  91.4     |  93.1    |  93.1  |  93.1     |  93.1   |  96.6    |   98.3      |
| capa.exe      |  92.3    |    92.3    |   94.9     |  94.9     |  94.9    |  94.9  |  100      |  100    |   100    |    100      |
| Everything    |  58.0    |   58.0     |   59.4     |    —      |    —     |  58.0  |  58.0     |  58.0   |  58.0    |   58.0      |

## FN / FP counts over milestones

| Binary     | M0 (FN/FP) | M1 (FN/FP) | M2 (FN/FP) | M3 (FN/FP) | M4 (FN/FP) | M5 (FN/FP) | M6 (FN/FP) | M7 (FN/FP) | M8 (FN/FP) | M9 (FN/FP) |
|------------|-----------:|-----------:|-----------:|-----------:|-----------:|-----------:|-----------:|-----------:|-----------:|-----------:|
| chrome     |    7 / 2   |    2 / 1   |    1 / 1   |    1 / 1   |    1 / 1   |    1 / 0   |    1 / 0   |    0 / 0   |    0 / 0   |    0 / 0   |
| msedge     |  (timeout) |    3 / 0   |    1 / 1   |    1 / 1   |    1 / 1   |    1 / 1   |    1 / 1   |    1 / 1   |    1 / 1   |    0 / 1   |
| CFF Explorer |  8 / 0   |    8 / 0   |    5 / 0   |    5 / 0   |    4 / 0   |    4 / 0   |    4 / 0   |    4 / 0   |    2 / 0   |    1 / 0   |
| capa       |    3 / 1   |    3 / 1   |    2 / 1   |    2 / 0   |    2 / 0   |    2 / 0   |    0 / 0   |    0 / 0   |    0 / 0   |    0 / 0   |
| Everything |   29 / 0   |   29 / 0   |   28 / 0   |     —      |     —      |   29 / 0   |   29 / 0   |   29 / 0   |   29 / 0   |   29 / 0   |

## Milestones

- **M0 start** — session baseline (FLIRT already real + working from a prior
  session; notepad already 100/100).
- **M1 IAT + CFG** — `baaa8f5` capa-schema feature_counts; `3d8bc8a` resolve
  imports via thunks (`jmp [rip+slot]`) and register-indirect cross-BB;
  `3eccb43` stop CFG recovery at another function's entry. Perf fix made msedge
  measurable (was >900s).
- **M2 num/off** — `246c711` match capa number/offset extraction exactly: keep
  rsp offsets, gate the lea-as-number path, mask immediates to the operation
  width. Closes MD5/SHA1/adler32 and resolve-PE-exports/patch-cmdline; removes
  the get-number-of-processors and check-for-software-breakpoints FPs.
- **M3 chunks** — `2cee8e3` skip chained-unwind (`UNW_FLAG_CHAININFO`) pdata
  chunks as function seeds. Closes capa `encode ADD/XOR/SUB` FP (capa precision
  97.4% -> 100%). Note: it does NOT pull a chunk's *features* into the primary
  unless control flow reaches it, so msedge `authenticate HMAC` (cold-chunk
  immediates) remains a FN until full unwind-chain merging is added.
- **M4 nzxor** — `24bcb6f` `is_security_cookie` now matches capa: it suppresses
  "xor reg, imm" early in the entry block (operand[1] being a non-stack register
  is the only hard reject). Closes cff `encrypt data using RC4 PRGA` (papa
  counted 2 nzxor vs capa's 1; cff recall 91.4% -> 93.1%, FN 5 -> 4) with no
  nzxor-count regressions elsewhere.
- **M5 SIB** — `0c8fb4f` classify a SIB-encoded absolute (no base, no index, but
  a SIB byte) as kSib not kImmMem, threading Zydis HAS_SIB into `classify`. That
  matches vivisect's i386SibOper-vs-i386ImmMemOper split, so "mov rax, gs:[0x30]"
  yields an offset instead of number(0x30). Closes chrome
  `get process heap force flags` FP (chrome precision 98.9% -> 100%, FP 1 -> 0).
  `6097af7` also corrects a stale chrome MiniDumpWriteDump test VA surfaced once
  the suite ran with fixtures.
- **M6 jump tables** — `872569f` recover switch-case bodies via MSVC x64 jump
  tables. Recursive descent stopped at an indirect `jmp reg`, so a function's
  switch cases were never recovered. New `jump_tables.cpp` recognizes the
  dominant MSVC x64 idiom (cmp/ja bound, `lea base,[rip+B]`,
  `mov off,[base+i*4+T]`, `add tgt,base`, `jmp tgt`), reads the 32-bit offset
  table, and seeds the case targets, confined to the dispatching function's
  pdata range. On capa.exe the function at 0x14000ab90 went from 76 to 1589
  recovered instructions (movzx 0 -> 65), closing both `compress data via ZLIB
  inflate or deflate` (two fixed-Huffman `bytes` features) and `resolve function
  by parsing PE exports` (offsets 0x3C/0x88 + export-dir offsets). capa recall
  94.9% -> 100%, FN 2 -> 0. `2f2b6d8` adds Bytes-feature dumping to the diag. No
  other binary changed: the resolver fires only on the exact register-indirect
  idiom and stays within pdata bounds (verified by full 7-binary re-measure).
  The 32-bit `jmp [reg*4+table]` form is not matched, so Everything.exe is
  unchanged at 58.0% / FN 29.
- **M7 cross-section** — `26f2455` emit cross-section flow for indirect
  memory-pointer calls. papa's extract_cross_section_flow only handled direct
  branches, so an indirect `call qword ptr [rip+disp]` through a non-import data
  pointer produced nothing. It now resolves the operand's data slot (rip slot =
  va+len+disp for kRipRel, abs = disp for kImmMem), skips IAT-import slots, and
  compares the call-site section to the slot section -- matching capa's
  extract_insn_cross_section_cflow, which compares against the vivisect-reported
  slot (BR_DEREF), not the dereferenced pointer. Closes chrome `execute
  shellcode via indirect call` @0x14003cfc0 (cross-section at the
  `call [rip+0x265d9f]` sites 0x14003da3b/0x14003da58, slot in .rdata vs call
  site in .text). chrome recall 98.9% -> 100%, FN 1 -> 0. Full 7-binary
  re-measure: no other binary changed, so the broader emission caused no
  cascade FP (the slot-not-pointer comparison is what kept it parity-faithful).
- **M8 full FLIRT port** — `368ff23` stop enforcing module tail bytes for the
  match, `e61f67d` aggregate matches across trees, `9ca6d73` classify via
  reference validation (Layer 3 wiring), `85d758a` the FLIRT match diagnostic.
  Replaces the boolean pattern+CRC detector with a faithful port of
  viv_utils.flirt.match_function_flirt_signatures: a pattern+CRC candidate is
  accepted only when each referenced function resolves (via xref, recursively)
  to a library function of the named identity, conflicting names reject as
  ambiguous, and a match also names its non-zero-offset siblings. A decoupled
  FlirtBackendContext implements the abstract FunctionContext over the
  CFG/imports/image. Two fidelity fixes, each verified against viv/lancelot
  source: (a) module tail bytes are NOT enforced for the library decision (they
  only disambiguate the name), and (b) the assigned name is the module's offset-0
  symbol of ANY kind, public or local, matching get_match_name. CFF 93.1 -> 96.6
  (FN 4 -> 2): reference validation un-marks the capability functions the
  pattern-only matcher over-suppressed. Fix (b) also closes the transient
  Everything "parse PE header" FP that the public-only interim produced by
  dropping the static helper `_check_managed_app` (a local-only name). Full
  7-binary re-measure: every other binary unchanged. The lone remaining CFF FN,
  terminate process @0x1401b05d8, is a CFG-fidelity divergence not a FLIRT bug:
  papa's recursive descent links the tiny `_exit` stub to `doexit`, so the
  faithful reference resolves and papa marks it library, while vivisect/capa keep
  it analyzable (capa emits no `_exit` anywhere). Next: CFG fidelity.
- **M9 tail-call discrimination** — `204e23b` determine real function entries as
  the PE entry, exports, TLS callbacks, and call targets, and fold a .pdata begin
  reached only by intra-procedural flow (jump, branch, or fallthrough, never
  called) into the function that reaches it. papa had seeded a function at every
  .pdata begin and stopped recovery there (`3eccb43`), so a function the compiler
  split across several .pdata RUNTIME_FUNCTION entries was broken into pieces and
  a function-scope rule could not see features vivisect/CAPA attribute to one
  function. The whole-image orchestration moved into a reader-driven
  `recover_seeded` (unit-tested with a span reader: absorb, keep-when-called,
  transitive chain); the reaching function is re-recovered across the softened
  boundaries so its CFG and loops stay correct. Closes msedge authenticate-HMAC
  (numbers 0x36/0x5c lived in jump-only continuations of 0x140309711, which now
  spans 0x14030695f..0x140309835 as one non-contiguous function) AND, as a side
  effect, CFF terminate-process (the `_exit` stub @0x1401b05d8, the M8 residual):
  the stub is jump-only-reached, so it folds into its caller rather than standing
  as a separate FLIRT-suppressed function. msedge 99.0 -> 100, CFF 96.6 -> 98.3.
  Full 7-binary re-measure: the four perfect binaries unchanged and no new FP, so
  the indirect-only over-absorb risk did not materialize.
- **M10 discovery emulator (pointers + emucode)** — `c4e9577` and the fifteen
  preceding `feat(emu)` commits. A faithful, security-bounded port of vivisect
  1.3.1's i386 emulator (the version capa 9.4.0 pins; reference cloned to
  `reference/vivisect`) recovers functions that the entry point's direct-call
  closure never reaches in a binary with no `.pdata`. The module
  (`papa_native/emu/`) reproduces envi's RegisterFile, the exact `bits.py` flag
  arithmetic, a bounds-checked SandboxMemory, ~45 i386 instruction handlers, the
  taint registry, the `runFunction` work-queue, and the emucode watcher, each
  built TDD-first (498 unit cases). `Cfg::recover` now runs a pointers + emucode
  pass in the no-`.pdata` branch (before the prologue gap-scan, matching
  vivisect's pointers-before-funcentries order): it scans the data sections for
  pointers into code and seeds each target whose emulated body behaves like a
  function (the watcher's `looks_good`: reaches a ret via varied, non-privileged,
  non-garbage instructions with no single mnemonic dominating). On Everything the
  pass validated 313 of 537 uncovered pointer targets and closed four genuine
  capability false negatives (functions reachable only through pointer tables)
  at 100% precision, with no new false positive. NOTE on the metric: parity is
  measured over CAPABILITY rules only, excluding capa `meta.lib` rules (capa
  matches them and emits them in --json but never lists them as capabilities).
  Earlier M10 notes quoted 58.0 -> 63.8 WITH lib rules included, which inflated
  recall by nine always-shared lib rules; the capability-only figure is
  35 / 60 = 58.3 at 100% precision (the four closed FNs are all real
  capabilities). The pass is gated
  to `.pdata`-less images, so the six x64 binaries are byte-identical (calc and
  notepad re-measured 100/100 to confirm the gate). The emulator validates 92.6%
  of Everything's already-recovered functions as `looks_good`, confirming the
  opcode coverage runs real 32-bit code to a ret. Twenty-five FNs remain
  (indirect-only targets needing emulated branch resolution during recovery, plus
  feature-extraction gaps); the emulator is abstract-interpretation only and
  DoS-bounded, so a crafted PE cannot drive native execution or unbounded work.
- **C1+C2 reloc-driven pointers pass (Option C phase 1)** — `19d5b72` parse the
  base-relocation directory in `pe/` (faithful port of vivisect `PE.parseRelocations`,
  retaining every entry including type-0 ABSOLUTE padding); `173d4a0` rewrite
  `find_pointer_candidates` to be reloc-driven and section-agnostic. vivisect's
  relocations.py follows every HIGHLOW/DIR64 base relocation as a stored pointer,
  regardless of where the site sits. The prior data-only scan never read `.text`,
  so absolute pointers stored at relocation sites inside code (callbacks, vtables,
  disconnected function islands) were invisible. On Everything the socket/networking
  island is reached only by three such `.text`-resident reloc pointers, after which
  the existing direct-call closure recovers the rest of the cluster. Everything
  capability-only recall 58.3 -> 86.7% (52/60), precision 100%, 0 FP, closing 17
  false-negative rules (FN 25 -> 8). Gated to no-`.pdata` images, so the six x64
  binaries are untouched (calc and notepad re-measured 100/100; the rest protected
  by the same structural gate). Full unit suite 507 cases / 17909 assertions green.
- **C3 per-function emulation + switch resolution (Option C phases 3a-3c)** —
  `6985bd9` add the `apicall` monitor hook (resolved call targets); `1778e85` the
  per-function calling pass (vivisect i386/calling.py + impemu AnalysisMonitor:
  emulate each recovered function and seed the targets its indirect calls resolve
  to); `2e40e6d` resolve the x86 memory-indirect indexed jump table. The calling
  pass is parity-neutral on Everything (per-function emulation starts with tainted
  entry registers, so register-indirect calls resolve to taints and computed
  targets are already covered) but is a faithful, regression-safe part of the
  pipeline. The switch resolver is the win: the truncated functions stop at
  `jmp dword ptr [index*4 + table]` (a constant-address table), which static
  descent could not follow. Reading the table reunites the switch cases into the
  dispatching function, completing bodies that were cut short. Everything recall
  86.7 -> 90.0% (54/60) at 100% precision, 0 FP, closing the authenticate-HMAC and
  check-for-software-breakpoints false negatives. The switch resolver is in the
  shared recovery path but inert on x64 (a 32-bit table displacement cannot
  address x64 memory), confirmed unchanged on calc, notepad, and chrome. Full unit
  suite 515 cases / 17932 assertions green. The remaining 6 Everything FNs are all
  feature-extraction or library-classification gaps in recovered functions.
- **Feature-extraction phase (Everything to 100%)** — closed the last six FNs,
  all in functions PAPA already recovered, each a faithful source-grounded fix.
  `2e0744d` masks an imm-only number to the image pointer width on x86 (push
  0x80000002 was kept sign-extended), closing inspect-section-memory-permissions
  and persist-via-Run-registry-key. `3126465` ports vivisect's ordlookup ordinal
  database so ws2_32/oleaut32 ordinal imports resolve to names, closing
  get-local-IPv4-addresses (api: getsockname for ordinal #6). `54d3d02` emits api
  features for a direct call to a FLIRT-named local library function (plus the
  underscore-stripped form), closing create-thread (api: _beginthreadex). `7651a85`
  makes FLIRT validate a named reference only against a local matched library
  function, not an import (faithful to viv_utils.flirt), closing
  allocate-thread-local-storage and, as a side effect, CFF Explorer's
  query-environment-variable FN. `1d20dca` and `f92526e` fold over-seeded
  jump-table case targets, and the blocks they reach, back into the dispatching
  function, closing check-for-unmoving-mouse-cursor (its GetCursorPos calls live in
  branch-reached case blocks). All seven binaries reach 100% recall, six of seven
  100% precision, the lone remaining diff being the parked msedge FP. Full unit
  suite 519 cases green.

Recall trend (start -> M5, precision in parens where < 100% earlier):
```
chrome  92.3 ▁▁▁ 97.8 ▆▆ 98.9 ███ 98.9 ███ 98.9 ███ 98.9 ███ (prec 100% at M5)
msedge   tmo ··· 97.1 ▅▅ 99.0 ███ 99.0 ███ 99.0 ███ 99.0 ███
cff     86.2 ▂▂▂ 86.2 ▂▂ 91.4 ▆▆▆ 91.4 ▆▆▆ 93.1 ▇▇▇ 93.1 ▇▇▇
capa    92.3 ▃▃▃ 92.3 ▃▃ 94.9 ▆▆▆ 94.9 ▆▆▆ 94.9 ▆▆▆ 94.9 ▆▆▆ (precision 100%)
```

M6 (jump tables): capa 94.9 -> 100; all other binaries unchanged.
M7 (cross-section): chrome 98.9 -> 100; all other binaries unchanged.
M8 (full FLIRT port): CFF 93.1 -> 96.6; all other binaries unchanged.
M9 (tail-call): msedge 99.0 -> 100, CFF 96.6 -> 98.3; all others unchanged.

Aggregate false positives across all 7 binaries: M1 2, M2 3, M3 2, M4 2, M5 1,
M6 1, M7 1, M8 1, M9 1 (only msedge `get number of processors` @0x14009a8d0
remains, a deep CFG-fidelity gap recommended for parking). Aggregate false
negatives at M9 (rule-level): CFF 1, Everything 29 = 30 across the 7 (notepad,
calc, chrome, capa, msedge all 0). After M9 the lone FP is the msedge
get-number-of-processors over-reach, and the only non-32-bit FN is CFF's query
environment variable (a feature-extraction gap); everything else is the
Everything 32-bit recovery gap.
