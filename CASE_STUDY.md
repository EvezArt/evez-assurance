# Case study: a 182-record chain, verified end to end

A real engagement run on a production event spine. Numbers are from the tool in this repo, executed against the live file, not from a demo harness.

## What was examined

- **182 records**, hash-chained, written between 2026-07-04 and 2026-11-07
- Produced by multiple generations of writer code over four months
- The operator had no independent confirmation that the chain was intact

## What the naive check got wrong

The first pass assumed one preimage schema across the whole file. It reported **124 records as corrupt**.

They were not. The chain contained **two legitimate constructions**:

- `json[kind,payload,prev_hash,timestamp]` — 122 records
- `json[entry_id,kind,payload,prev_hash,timestamp]` — 60 records

A single-schema verifier cannot distinguish "the file was tampered with" from "the file was written by two versions of the same code." The failure direction matters: it accuses an honest chain of corruption.

## What the corrected verifier found

- **182/182** records reproduce their digest
- **2** constructions, discovered per record rather than declared in advance
- Zero link breaks, zero parse errors
- **Forgery probe:** record 92 altered in an isolated copy. Recomputed digest `e3666968c7884e99` against stored `fc4e9914f5d59cfc`. Detected.

## Why the detection step is not optional

A verifier that has never caught a forgery is a program that prints "OK." The tamper probe plants an alteration on every run so the report demonstrates detection rather than asserting it.

## Scope and limits

This establishes internal consistency: the records have not been altered relative to the digests they carry. It does not establish that the described events occurred, nor who produced the file. Bounding when the chain existed requires external anchoring, which in this case was published to Bitcoin via OpenTimestamps.

Stating that boundary is part of the deliverable. A report that overclaims is worse than no report.

## Reproduce it

```
python3 verify_report.py your_chain.jsonl report.md "Your Chain Name"
```

Runs on any JSONL chain with per-record digests. No dependencies beyond the standard library.
