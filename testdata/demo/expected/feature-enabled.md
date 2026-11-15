# TriageGuard evidence report

This report compares the assumptions recorded in previous CVE assessments with the available evidence.

An `unchanged` result means only that the recorded assumptions still match. It does not tell you whether a CVE affects a product, whether a fix works, or whether the product is secure or compliant.

Schema version: 1

Overall status: &#34;review&#45;required&#34;

Reason: At least one recorded assumption changed. (&#34;assumptions&#45;changed&#34;)

| Result counts | Unchanged | Review required | Unverifiable |
| --- | ---: | ---: | ---: |
| Decisions | 0 | 1 | 0 |
| Assumptions | 2 | 1 | 0 |

How to read the status codes:

- `unchanged`: The recorded assumptions still match.
- `review-required`: At least one assumption changed, and all evidence was available. Have a human reviewer reassess the original decision.
- `unverifiable`: At least one assumption could not be checked. Restore or correct the evidence and run the check again. Any other changes remain visible in the report.

A baseline identifies the version or build originally reviewed. The original reasoning records why that decision was made. Review this report before sharing it: it can contain sensitive reasoning, configuration values, paths, and hashes.

The evidence cells retain the exact recorded fields. `present` says whether a file or key is expected to exist. `state` describes what was found: `present`, `absent` for a missing key in a valid export, or `unavailable` when the evidence could not be checked. `value` is a configuration string, and `sha256` is a file hash or the hash recorded for a patch ID.

Quoted text preserves the supplied values. Ordinary spaces remain readable; leading, trailing, or repeated spaces appear as `\u0020`. Escaped tabs and line breaks also belong to the original text. An empty string is shown as `""`. In the Key column, (not supplied) means the assumption has no key field; it is different from a key missing from an evidence export.

## Decision &#34;synthetic&#45;parser&#45;decision&#34;

CVE: &#34;CVE&#45;2024&#45;0001&#34;

Reviewed baseline: &#34;synthetic&#45;release&#45;1&#34;

Original reasoning: &#34;Synthetic historical review assumed FEATURE&#95;X was disabled and the declared source and patch inventory were retained&#46;&#34;

Status: &#34;review&#45;required&#34;

Reason: At least one recorded assumption changed. (&#34;assumptions&#45;changed&#34;)

| Assumption | Evidence type | Evidence path | Key | Recorded expectation | Evidence found | Status | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| &#34;feature&#45;disabled&#34; | &#34;config&#34; | &#34;build&#45;config&#46;json&#34; | &#34;FEATURE&#95;X&#34; | &#123;&#34;present&#34;&#58;true&#44;&#34;value&#34;&#58;&#34;n&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;present&#34;&#44;&#34;value&#34;&#58;&#34;y&#34;&#125; | &#34;review&#45;required&#34; | The configuration value changed. (&#34;value&#45;changed&#34;) |
| &#34;patch&#45;record&#45;retained&#34; | &#34;patch&#34; | &#34;patches&#46;json&#34; | &#34;synthetic&#45;feature&#45;default&#34; | &#123;&#34;present&#34;&#58;true&#44;&#34;sha256&#34;&#58;&#34;696037f8802b168baee59e97178a84782a5f0552b5410126c5e4b3bbf530a4d8&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;present&#34;&#44;&#34;sha256&#34;&#58;&#34;696037f8802b168baee59e97178a84782a5f0552b5410126c5e4b3bbf530a4d8&#34;&#125; | &#34;unchanged&#34; | The evidence matches the recorded expectation. (&#34;match&#34;) |
| &#34;source&#45;retained&#34; | &#34;file&#34; | &#34;src&#47;parser&#46;c&#34; | (not supplied) | &#123;&#34;present&#34;&#58;true&#44;&#34;sha256&#34;&#58;&#34;4f27c07bbe11b7e593bb3b9290ddf9a697a1771cf331aedad0ad10b70fcc9166&#34;&#125; | &#123;&#34;state&#34;&#58;&#34;present&#34;&#44;&#34;sha256&#34;&#58;&#34;4f27c07bbe11b7e593bb3b9290ddf9a697a1771cf331aedad0ad10b70fcc9166&#34;&#125; | &#34;unchanged&#34; | The evidence matches the recorded expectation. (&#34;match&#34;) |
