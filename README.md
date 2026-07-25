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
- **Much faster : )** - roughly 7x on small to medium binaries.
- **Minimal dependencies** - only Zydis for disassembly, miniz for zlib
  decompression (needed for FLIRT) & doctest for unit testing.

## Performance

Measured against `capa.exe 9.4.0` with the matching `capa-rules-9.4.0` ruleset on
the same machine (`--json`, output redirected).
PAPA is usually ~7X faster on small to medium binaries!


## Testing
In addition to its unit tests, PAPA was also tested against a corpus of 42 PE files.
It reached 100% recall and 100% precision on the validation corpus, so there are no
known false positives or false negatives on tested samples.

Perfect match-set parity on an *arbitrary* binary is currently not promised, so an unseen sample can still diverge a bit. 
In practice, precision and recall should stay ~100%.
