# Passive-assessability rubric (final, consolidated) — ETSI TS 103 701 V2.1.1

Source of truth: ~/datasets/standards/ts_103701v020101p.txt (ETSI TS 103 701 V2.1.1, 2025-05; use the BODY
clauses, not the table of contents) and ~/datasets/standards/en_303645v030103p.txt (ETSI EN 303 645 V3.1.3).
Do not invent criteria. Decide only from what each test case's text requires.

## The observer
A strictly passive observer at the home gateway of the device's network. It HAS:
- NET-OBS: all IP traffic of the device crossing the gateway (incl. DHCP/DNS/mDNS/SSDP on the LAN segment),
  over long periods; no TLS decryption; sends nothing to the device; changes nothing.
- PUBLIC: information anyone can obtain without vendor cooperation (published user documentation, vendor
  website, published vulnerability disclosure policy, public databases such as CVE/NVD, reference catalogues
  named by the standard such as ETSI TR 103 621 or SOGIS Agreed Cryptographic Mechanisms).
It does NOT have:
- IXIT/ICS: information supplied by the Supplier Organization.
- DUT-INTERACT: operating the device/UI/app/interfaces, triggering events (reset, update, pairing), sending
  probes/scans/inputs, downgrade attempts, physical access.
- INTERNAL: firmware, storage, source code, processes.

## Per test unit
Tag what it needs: any of IXIT, DUT-INTERACT, INTERNAL, NET-OBS, PUBLIC.

## Per test case — fields
- "verdict_reach": what the observer can conclude using THIS test case's own verdict criteria:
  "pass_and_fail" | "fail_only" (a violation can be shown, PASS cannot) | "pass_only" | "none".
- "uses_reference": true if the verdict needs PUBLIC information or a reference catalogue.
- "assumptions": list of assumptions the observer must make but cannot verify (each <=15 words); [] if none.
- "opportunistic": true if the observation depends on an event the observer cannot cause (outage, vendor
  update release, user pairing, reset).
- "outside_procedure_cues": passive evidence relevant to the PROVISION that this test case gives no way to
  use (own words <=30 words), else "".

### Rule R1 — verdicts that compare with the IXIT
If the verdict criterion is a comparison WITH THE IXIT ("differs from its IXIT documentation", "documented in
the IXIT", "not described in the IXIT", ...), the observer cannot reach it: assuming the IXIT's content is
equivalent to having it. That criterion contributes no reachable verdict; record the passive evidence that
exists in outside_procedure_cues. If a test case has several verdict bullets, consider only bullets that do
NOT compare with the IXIT when deciding verdict_reach.
### Rule R2 — substitution
If a criterion is an external reference, published information, or a property (best-practice catalogue,
presence of plaintext, published policy content), the observer may SUBSTITUTE the subject the IXIT would list
with observed values or public documents; every substitution must appear in assumptions.
Example: observed TLS versions/cipher suites judged against the catalogue named by the TS ->
verdict_reach "fail_only", uses_reference true, assumption "observed channels cover all mechanisms the IXIT
would list".
### Rule R3 — passive_class is derived, never judged
none -> "not_assessable"; else assumptions non-empty -> "inferred"; else uses_reference -> "reference";
else "observed".

## Group-level fields (identical on all case objects of a group)
"conditional": true/false; "condition_passive": "yes" | "partly" | "no" | "n/a".

## Output: JSON array, one object per test case, document order, ALL test cases in range
{"test_case":"5.5-1-2","test_group":"5.5-1","provision":"5.5-1",
 "type":"conceptual|functional|conceptual/functional",
 "summary":"<own words <=25 words>",
 "units":[{"id":"a","needs":["IXIT","NET-OBS"],"note":"<own words <=20 words>"}],
 "verdict_reach":"...","uses_reference":false,"assumptions":[],"opportunistic":false,
 "outside_procedure_cues":"","passive_class":"...","rationale":"<own words <=40 words>",
 "conditional":false,"condition_passive":"n/a"}
Copyright: paraphrase only; never copy sentences from the standards.

---
# v3 amendment (2026-10-17): two observer models — supersedes the single-observer fields above

Reliability check showed that most disagreements came from substituting the manufacturer's PUBLIC
documentation (manuals, privacy policy, web pages) for the IXIT. That is document review, not network
observation. Classify each test case under TWO observer models:

- Model N  (network observer): NET-OBS + reference sources that are NOT the manufacturer's own documents:
  cryptographic catalogues named by the TS (ETSI TR 103 621, SOGIS ACM), public vulnerability databases
  (CVE/NVD) and other third-party registries. The manufacturer's documentation may NOT stand in for the IXIT.
- Model ND (network + documents): Model N plus the manufacturer's PUBLIC documentation (user manuals,
  privacy policy, support pages, published VDP), which MAY stand in for the IXIT under Rule R2.
Rules R1 (no assumptions about IXIT content) and R3 apply to both models.

## Per test case — replace verdict_reach/uses_reference/assumptions/passive_class with:
"N":  {"verdict_reach": "...", "uses_reference": bool, "assumptions": [...], "passive_class": "..."}
"ND": {"verdict_reach": "...", "uses_reference": bool, "assumptions": [...], "passive_class": "..."}
Model ND can never be weaker than Model N (anything reachable under N is reachable under ND).
For ND, using manufacturer documentation counts as uses_reference=true and the substitution goes into
assumptions. Keep: test_case, test_group, provision, type, summary, units, opportunistic,
outside_procedure_cues, rationale, conditional, condition_passive.
