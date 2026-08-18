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
- **Minimal dependencies** - only Zydis for disassembly, miniz for zlib
  decompression (needed for FLIRT) & doctest for unit testing.

## Performance

Measured against `capa.exe 9.4.0` with the matching `capa-rules-9.4.0` ruleset on
the same machine (`--json`, output redirected), on a 4-core i5-7500.

| Sample          |    Size | CAPA     | PAPA    | Speedup  |
|-----------------|--------:|---------:|--------:|--------: |
| calc            |   27 KB |   11.5 s |   1.1 s |    ~11x  |
| notepad         |  196 KB |   49.4 s |   1.9 s |    ~26x  |
| 7z              |  549 KB |  215.6 s |   3.2 s |    ~67x  |
| msedge          |  4.92 MB| 1283.5 s |  21.4 s |    ~60x  |

Smaller binaries are dominated by a fixed startup cost (loading and compiling the rule corpus), 
while larger binaries need more time for actual code analysis, making the speedup increasingly significant!


## Testing
In addition to its unit tests, PAPA was also tested against a corpus of 42 PE files.
It reached 100% recall and 100% precision on the validation corpus, so there are no
known false positives or false negatives on tested samples.

Perfect match-set parity on an *arbitrary* binary is currently not promised, so an unseen sample can still diverge a bit. 
In practice, precision and recall should stay ~100%.
