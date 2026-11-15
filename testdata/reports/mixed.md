# TriageGuard evidence report

This report compares the assumptions recorded in previous CVE assessments with the available evidence.

An `unchanged` result means only that the recorded assumptions still match. It does not tell you whether a CVE affects a product, whether a fix works, or whether the product is secure or compliant.

Schema version: 1

Overall status: &#34;unverifiable&#34;

Reason: At least one assumption could not be checked. (&#34;evidence&#45;unavailable&#34;)

| Result counts | Unchanged | Review required | Unverifiable |
| --- | ---: | ---: | ---: |
| Decisions | 1 | 1 | 1 |
| Assumptions | 3 | 3 | 1 |

How to read the status codes:

- `unchanged`: The recorded assumptions still match.
- `review-required`: At least one assumption changed, and all evidence was available. Have a human reviewer reassess the original decision.
- `unverifiable`: At least one assumption could not be checked. Restore or correct the evidence and run the check again. Any other changes remain visible in the report.

A baseline identifies the version or build originally reviewed. The original reasoning records why that decision was made. Review this report before sharing it: it can contain sensitive reasoning, configuration values, paths, and hashes.

The evidence cells retain the exact recorded fields. `present` says whether a file or key is expected to exist. `state` describes what was found: `present`, `absent` for a missing key in a valid export, or `unavailable` when the evidence could not be checked. `value` is a configuration string, and `sha256` is a file hash or the hash recorded for a patch ID.

Quoted text preserves the supplied values. Ordinary spaces remain readable; leading, trailing, or repeated spaces appear as `\u0020`. Escaped tabs and line breaks also belong to the original text. An empty string is shown as `""`. In the Key column, (not supplied) means the assumption has no key field; it is different from a key missing from an evidence export.

## Decision &#34;baseline&#45;retained&#34;

CVE: &#34;CVE&#45;2024&#45;0001&#34;

Reviewed baseline: &#34;release&#45;1&#34;

Original reasoning: &#34;Synthetic retained assumptions&#46;&#34;

Status: &#34;unchanged&#34;

Reason: All recorded assumptions match. (&#34;all&#45;unchanged&#34;)

| Assumption | Evidence type | Evidence path | Key | Recorded expectation | Evidence found | Status | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| &#34;absent&#45;inventory&#45;key&#34; | &#34;patch&#34; | &#34;patches&#46;json&#34; | &#34;unused&#45;patch&#34; | &#123;&#34;present&#34;&#58;false&#125; | &#123;&#34;state&#34;&#58;&#34;absent&#34;&#125; | &#34;unchanged&#34; | The evidence matches the recorded expectation. (&#34;match&#34;) |
| &#34;empty&#45;config&#34; | &#34;config&#34; | &#34;config&#46;json&#34; | &#34;&#34; | &#123;&#34;present&#34;&#58;true&#44;&#34;value&#34;&#58;&#34;&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;present&#34;&#44;&#34;value&#34;&#58;&#34;&#34;&#125; | &#34;unchanged&#34; | The evidence matches the recorded expectation. (&#34;match&#34;) |
| &#34;source&#45;retained&#34; | &#34;file&#34; | &#34;src&#47;parser&#46;c&#34; | (not supplied) | &#123;&#34;present&#34;&#58;true&#44;&#34;sha256&#34;&#58;&#34;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;present&#34;&#44;&#34;sha256&#34;&#58;&#34;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&#34;&#125; | &#34;unchanged&#34; | The evidence matches the recorded expectation. (&#34;match&#34;) |

## Decision &#34;feature&#45;drift&#34;

CVE: &#34;CVE&#45;2024&#45;0002&#34;

Reviewed baseline: &#34;release&#45;2&#34;

Original reasoning: &#34;Feature switched on&#46;&#92;nReassess the human decision&#59; café 日本語&#46;&#34;

Status: &#34;review&#45;required&#34;

Reason: At least one recorded assumption changed. (&#34;assumptions&#45;changed&#34;)

| Assumption | Evidence type | Evidence path | Key | Recorded expectation | Evidence found | Status | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| &#34;feature&#45;drift&#34; | &#34;config&#34; | &#34;config&#46;json&#34; | &#34;FEATURE&#95;X&#34; | &#123;&#34;present&#34;&#58;true&#44;&#34;value&#34;&#58;&#34;n&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;present&#34;&#44;&#34;value&#34;&#58;&#34;y&#34;&#125; | &#34;review&#45;required&#34; | The configuration value changed. (&#34;value&#45;changed&#34;) |
| &#34;patch&#45;drift&#34; | &#34;patch&#34; | &#34;patches&#46;json&#34; | &#34;fix&#45;1&#34; | &#123;&#34;present&#34;&#58;true&#44;&#34;sha256&#34;&#58;&#34;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;present&#34;&#44;&#34;sha256&#34;&#58;&#34;bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&#34;&#125; | &#34;review&#45;required&#34; | The file hash or the hash recorded for the patch ID changed. (&#34;hash&#45;changed&#34;) |

## Decision &#34;missing&#45;evidence&#34;

CVE: &#34;CVE&#45;2024&#45;0003&#34;

Reviewed baseline: &#34;release&#45;3&#34;

Original reasoning: &#34;The source evidence is unavailable&#46;&#34;

Status: &#34;unverifiable&#34;

Reason: At least one assumption could not be checked. (&#34;evidence&#45;unavailable&#34;)

| Assumption | Evidence type | Evidence path | Key | Recorded expectation | Evidence found | Status | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| &#34;missing&#45;file&#34; | &#34;file&#34; | &#34;src&#47;missing&#46;c&#34; | (not supplied) | &#123;&#34;present&#34;&#58;true&#44;&#34;sha256&#34;&#58;&#34;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;unavailable&#34;&#44;&#34;reason&#34;&#58;&#34;evidence&#45;missing&#34;&#125; | &#34;unverifiable&#34; | The evidence file is missing. (&#34;evidence&#45;missing&#34;) |
| &#34;missing&#45;inventory&#45;key&#34; | &#34;patch&#34; | &#34;patches&#46;json&#34; | &#34;fix&#45;missing&#34; | &#123;&#34;present&#34;&#58;true&#44;&#34;sha256&#34;&#58;&#34;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;absent&#34;&#125; | &#34;review&#45;required&#34; | A key expected to be present is missing. (&#34;key&#45;missing&#34;) |
