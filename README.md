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
- **No runtime** - a single native executable that imports only `kernel32.dll`,
  so it runs on a clean machine with no Visual C++ redistributable installed!
- **Much faster : )** - 9x to 75x, and the gap widens as the binary grows.
- **Uses every core** - per-function analysis runs one worker per core, and the
  results are merged back in recovered-function order, so the report doesn't
  depend on how many cores you happen to have.
- **Built for hostile input** - every sample is treated as malformed until
  proven otherwise. Reads are bounds-checked, every loop and recursion driven by
  sample data has an explicit cap, and the instruction emulator runs in a
  sandbox that can never write to the image or dereference an emulated value.
- **Minimal dependencies** - only Zydis for disassembly, miniz for zlib
  decompression (needed for FLIRT) & doctest for unit testing.

## Performance

Measured against `capa.exe 9.4.0` with the matching `capa-rules-9.4.0` ruleset on
the same machine (`--json`, output redirected), on a 4-core i5-7500.

| Sample          |    Size | CAPA      | PAPA    | Speedup |
|-----------------|--------:|----------:|--------:|--------:|
| hostname (x86)  |   12 KB |    15.1 s |   1.0 s |    15x  |
| calc            |   27 KB |    11.5 s |   1.1 s |    11x  |
| notepad         |  196 KB |    49.4 s |   1.9 s |    26x  |
| cmd (x64)       |  283 KB |    64.1 s |   2.2 s |    29x  |
| 7z              |  549 KB |   215.6 s |   3.2 s |    67x  |
| certutil (x64)  |  1.6 MB |   255.6 s |   7.5 s |    34x  |
| msedge          |  4.9 MB |  1283.5 s |  21.4 s |    60x  |

Across the 38 corpus samples with a cached CAPA reference, that's **51.5 minutes
of CAPA versus 88 seconds of PAPA, an aggregate 35x**.

Small binaries are dominated by a fixed startup cost (loading and compiling the
1045-rule corpus), which is why they sit at the lower end. Everything above that
scales with how much code there is to analyze, and that's where PAPA pulls away.

## Testing
In addition to its unit tests, PAPA was also tested against a corpus of 42 PE files.
It reached 100% recall and 100% precision on the validation corpus, so there are no
known false positives or false negatives on tested samples.

Perfect match-set parity on an *arbitrary* binary is currently not promised, so an unseen sample can still diverge a bit. 
In practice, precision and recall should stay ~100%.

Performance work is held to the same bar - every optimization has to produce
output that is byte-for-byte identical to the version before it, across all 42
binaries, in both the JSON and the text report. An optimization that changes so
much as one byte doesn't ship.

The security work is held to it too. One hardening fix was measurably more
correct and still didn't ship, because it shifted extracted feature counts on
two binaries - it's recorded in the source instead, to be settled against CAPA's
own references rather than against PAPA's previous output.
