# capa-rules provenance

These are the rules of Mandiant's capa-rules project, the standard rule corpus
that capa 9.4.0 embeds and uses when no rules path is given. PAPA vendors the
same set so its default rules match capa's.

## Source

- Project: capa-rules (https://github.com/mandiant/capa-rules)
- Tag: `v9.4.0`, commit `2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80`
- Archive: `https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.zip`
- License: Apache-2.0 (see `LICENSE.txt` beside this file)
- Authorship: contributors keep their copyright, and each rule lists its
  authors under `meta.authors`

## Files

- 1042 rule files (`*.yml`), in the upstream directory layout
- `LICENSE.txt`

The files are upstream's with CRLF line endings. They are byte-for-byte
identical to the rules embedded in capa.exe 9.4.0, whose Windows build checked
them out with CRLF, and converting them to LF gives upstream's exact bytes.
The `.gitattributes` here marks the tree as binary so git never converts them.

To update, replace the `*.yml` files and `LICENSE.txt` here with those of the
new tag, left out as below, then convert each of them from LF to CRLF.

## Left out

- `.github/`: CI workflows and the contributing guide. Its three `.yml` files
  are workflows, not rules, and capa skips that directory when loading.
- `.gitattributes`: the upstream line-ending setting, replaced by the one here.
- `README.md`, `doc/format.md` and `internal/limitation/static/README.md`:
  documentation, not rules.
