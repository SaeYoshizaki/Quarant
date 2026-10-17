# Passive-assessability rubric for ETSI TS 103 701 V2.1.1 test cases

Source of truth: ~/datasets/standards/ts_103701v020101p.txt (ETSI TS 103 701 V2.1.1, 2025-05)
and ~/datasets/standards/en_303645v030103p.txt (ETSI EN 303 645 V3.1.3).
Do NOT invent criteria. Every classification must be justified only by what the test case text requires.

## The observer
A strictly passive observer at the home gateway of the network the device is on. It has:
- NET-OBS: all IP traffic of the device that crosses the gateway (incl. DHCP/DNS/mDNS/SSDP on the LAN segment),
  over long periods, without decrypting TLS, without sending anything to the device, without changing traffic.
- PUBLIC: information anyone can obtain without vendor cooperation (published user documentation, vendor
  website, published vulnerability disclosure policy, public databases such as CVE/NVD, reference catalogues
  named by the standard such as ETSI TR 103 621 or SOGIS Agreed Cryptographic Mechanisms).
It does NOT have:
- IXIT/ICS: any information supplied by the Supplier Organization (SO).
- DUT-INTERACT: the ability to operate the device, its UI, app, or interfaces, trigger events (reset, update,
  pairing), send probes/scans/inputs, perform downgrade attempts, or physically access it.
- INTERNAL: access to firmware, storage, source code, processes.

## Per test unit
Tag what each test unit needs: IXIT, DUT-INTERACT, INTERNAL, NET-OBS, PUBLIC (one or more).

## Per test case: passive class (choose exactly one)
- observed: the verdict criteria can be decided from NET-OBS alone (the deciding fact appears in traffic).
- inferred: NET-OBS yields an indication but the verdict needs an assumption the standard does not let the
  observer verify (e.g. absence of evidence over an observation window, or substituting observation for
  IXIT comparison without a reference catalogue).
- reference: the observed value is decidable only against PUBLIC information/reference catalogue
  (e.g. observed cipher suite judged against TR 103 621 / SOGIS; or the provision is about published info that
  PUBLIC can check without traffic).
- not_assessable: requires IXIT, DUT-INTERACT, or INTERNAL for every path to a verdict.
Conceptual test cases assess IXIT by definition -> normally not_assessable, unless a unit can be fully decided
from PUBLIC information (say so explicitly).

## Per test group (= one provision)
- passive_class: the strongest class among its test cases (observed > inferred > reference > not_assessable),
  plus "partial" note: what part of the assessment remains impossible (e.g. conceptual part).
- conditional: whether the provision is conditional in EN 303 645 (e.g. "where applicable") and the condition
  itself is passively decidable.

## Output (JSON array, one object per test case)
{
 "test_case": "5.5-1-2",
 "test_group": "5.5-1",
 "provision": "5.5-1",
 "type": "functional" | "conceptual",
 "summary": "<your own words, <=25 words; never copy sentences from the standard>",
 "units": [{"id":"a","needs":["IXIT","NET-OBS"],"note":"<own words, <=20 words>"}],
 "passive_class": "observed|inferred|reference|not_assessable",
 "rationale": "<own words, <=40 words, cite unit ids>",
 "quarant_capabilities": ["<event types from QUARANT_CAPABILITIES.md that could provide the observation, or empty>"],
 "reference_sources": ["<e.g. ETSI TR 103 621, SOGIS ACM, CVE/NVD, published VDP>"]
}
Copyright: summaries and notes must be paraphrases; do not reproduce text from the standards.

---
# Rubric v2 amendments (2026-10-17) — supersede v1 where they conflict

Reason: the three ranges were classified inconsistently, and v1 had no way to express verdicts that a passive
observer can reach in only one direction. v2 replaces the judgement-based class with mechanical fields.

## Per test case, record these fields (in addition to v1 fields)
- "type": "conceptual" | "functional" | "conceptual/functional" (mixed cases as labelled in the TS).
- "verdict_reach": what the passive observer can conclude using THIS test case's own verdict criteria:
    "pass_and_fail" – both PASS and FAIL can be established;
    "fail_only"     – a FAIL can be established (a violation can be seen), PASS cannot (it would need absence
                      of evidence, unseen channels, IXIT, or interaction);
    "pass_only"     – rare; PASS but not FAIL;
    "none"          – neither.
- "uses_reference": true if reaching the verdict requires PUBLIC information or a reference catalogue
  (TR 103 621, SOGIS ACM, CVE/NVD, published VDP/documentation) in addition to or instead of traffic.
- "assumptions": list of assumptions the observer must make but cannot verify (own words, each <=15 words).
  Examples: "observed channels cover all mechanisms the IXIT would list"; "update was not user-initiated";
  "no traffic of this kind outside the observation window"; "fingerprint maps to library version".
  Empty list if none.
- "opportunistic": true if the observation depends on an event the observer cannot cause
  (outage, vendor releasing an update, user pairing a device, reset).
- "outside_procedure_cues": optional, own words <=30 words: passive evidence relevant to the PROVISION that the
  TS test case gives no way to use (e.g. the provision has only a conceptual case). Empty string otherwise.

## passive_class is now DERIVED mechanically (do not judge it separately)
- if verdict_reach == "none"            -> "not_assessable"
- else if assumptions is non-empty      -> "inferred"
- else if uses_reference                -> "reference"
- else                                  -> "observed"

## Conceptual cases
A conceptual case may have verdict_reach other than "none" only if the subject it assesses can be substituted
by observed values or public documents. Any such substitution MUST appear in "assumptions"
(e.g. "observed channels cover all mechanisms the IXIT would list"). Apply this identically in every range:
observed TLS versions/cipher suites judged against the catalogue named by the TS -> verdict_reach "fail_only",
uses_reference true, with that substitution assumption -> class "inferred".

## Group-level fields (put on every case object of the group, identical values)
- "conditional": true/false (provision is conditional in EN 303 645)
- "condition_passive": "yes" | "partly" | "no" | "n/a" — can the observer decide whether the condition applies
  ("partly" if it can show the condition holds but not that it does not, or vice versa)
Remove any other ad-hoc group fields (group_passive_class, group_partial, group_partial_note, condition_note
may be kept only as "group_note", own words <=40 words).

## v2.1 clarification (2026-10-17): assumptions about IXIT content are not allowed
- If a test case's verdict criterion is a comparison WITH THE IXIT (e.g. "differs from the IXIT
  documentation", "not described in IXIT", "interface missing from IXIT"), the passive observer cannot reach
  that verdict: assuming what the IXIT says is equivalent to having it. verdict_reach = "none". Record the
  passive evidence that exists (banners, plaintext, answering services, ...) in outside_procedure_cues.
- If the verdict criterion is an external reference or a property (best-practice catalogue, published
  information, presence of plaintext), the observer may SUBSTITUTE the subject the IXIT would list with
  observed values or public documents; the substitution goes into assumptions (-> class "inferred").
