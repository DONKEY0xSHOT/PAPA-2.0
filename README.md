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
whoami_x64.exe
whoami_x86.exe
```

PAPA reaches 100% recall and 100% precision on the validation corpus, so there are no
known false positives or false negatives on tested samples.

Perfect match-set parity on an *arbitrary* binary is currently not promised, so an unseen sample can still diverge a bit. 
In practice, precision and recall should stay ~100%.
