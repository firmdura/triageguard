# Distribution notices

Original TriageGuard code, documentation, tests, and synthetic fixtures are
licensed under [Apache-2.0](LICENSE). The source and patch examples were created
for this project; they were not copied from firmware or upstream fixes. Their
illustrative CVE identifier makes no claim about whether a real product is affected.
See the [fixture attribution](examples/firmware/README.md) in the source
distribution.

The only direct module dependency is **go.yaml.in/yaml/v3 v3.0.4**. Its upstream
[LICENSE](licenses/yaml/LICENSE) and [NOTICE](licenses/yaml/NOTICE) are included
without changes. The Go YAML license also records attribution for portions
derived from libyaml. No YAML implementation has been vendored into this tree.

Release executables include code from the **Go 1.27.4** runtime and standard
library. Their [LICENSE](licenses/go/LICENSE) and [PATENTS](licenses/go/PATENTS)
files are included without changes from the pinned toolchain. These files
contain upstream terms and attribution, not SDK code.

Both binary archives include this notice, the project LICENSE, and the complete
`licenses/` directory. The source archive contains the same files. Before
building, the packaging script compares the four upstream files
`licenses/go/LICENSE`, `licenses/go/PATENTS`, `licenses/yaml/LICENSE`, and
`licenses/yaml/NOTICE` byte for byte with their copies in the prepared toolchain
and module cache.
