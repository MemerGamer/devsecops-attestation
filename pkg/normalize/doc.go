package normalize

// Adding a new tool adapter
//
// Each supported security tool gets its own file in this package, named
// after the tool (e.g. semgrep.go, trivy.go). An adapter file should:
//
//  1. Define an unexported type implementing the Normalizer interface
//     (Name, CheckType, Normalize).
//  2. Translate the tool's native severity vocabulary into the canonical
//     Severity scale defined in severity.go. Consult the mapping table in
//     that file's doc comment (also mirrored in docs/severity-mapping.md)
//     before inventing a new mapping; keeping all adapters consistent with
//     that table is what makes findings from different tools comparable.
//  3. Register an instance of the adapter with Register in an init()
//     function, so the adapter is available via Get and Names as soon as
//     the package is imported:
//
//     func init() {
//     Register(myToolNormalizer{})
//     }
//
//  4. Require a schema marker before trusting the input: check for a field
//     or value that only the real tool's report format carries (e.g.
//     trivy's SchemaVersion, semgrep's "results" key, sobelow's non-empty
//     sobelow_version). An adapter must fail closed on an unrecognized
//     input rather than silently returning zero findings, since a
//     zero-findings result is indistinguishable from a genuinely clean
//     scan and would let a misconfigured pipeline (or another tool's
//     output fed to the wrong adapter) pass undetected.
//  5. Add fixture files under testdata/<tool>/ (at minimum a "clean" report
//     with no findings, a "findings" report exercising each severity the
//     adapter maps, and a "malformed" report to exercise the error path)
//     and a corresponding *_test.go file that exercises Normalize directly
//     as well as through Run. Also test that `{}` and another tool's
//     fixture are both rejected by the schema-marker check.
//
// Adapters should not decide pass/fail from findings alone; that decision
// belongs to Run, which applies the caller-supplied failOn threshold
// uniformly across all tools. When the underlying tool additionally reports
// its own independent pass/fail verdict (e.g. mix_audit's top-level "pass"
// boolean), implement the optional ToolPassNormalizer interface instead of
// deciding pass/fail in Normalize itself; Run combines the tool-reported
// verdict with its threshold-based verdict via logical AND.
