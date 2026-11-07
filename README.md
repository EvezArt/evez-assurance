# Evidence systems that survive scrutiny

I verify whether the logs, audit trails, and tamper-evidence claims your organisation depends on actually hold up. Fixed scope, fixed price, written findings, and every claim I make carries the condition that would prove it wrong.

Not a pentest. Not a compliance stamp. A test of whether your evidence would survive an adversarial look.

## The five day question

You have logs. Someone may one day ask whether those logs could have been altered. Right now the honest answer is usually *"we think not"*, which is worth very little.

I replace that with a tested answer.

**What I do**

1. Recompute every digest in your chain from the raw records. Not spot checks. Every record.
2. Discover the actual construction in use. Many chains contain more than one schema generation, and naive verifiers report false corruption. I map them first, then verify per record.
3. Plant a forgery. I alter a record in an isolated copy and confirm the verifier catches it. A detector never tested against a deliberate falsehood is a detector you cannot trust.
4. Run a truncation test. Delete the tail and check whether the system notices, or silently reports health.
5. Report what survives, what does not, and what I could not determine.

**What you get**

- A written report stating the verdict, the record count, the schema generations found, and the exact tests performed.
- The verifier itself, runnable by you or your counsel, with no dependency on me.
- A list of every limitation. Including the ones that make my own result look weaker.
- The report digest, so a later alteration of the report is detectable.

**Price: $250. Five days.** One chain, one report, one round of questions.

## Larger engagements

| Engagement | Scope | Price |
|---|---|---|
| Verification Report | One chain, adversarial testing, written findings | **$250** |
| Chain Audit | Up to five chains, schema discovery, remediation guidance | **$1,500** |
| Technical Assurance Sprint | Five business days, autonomy and PQC questions, evidence review | **$5,000** |
| Briefing | Half day, autonomy risk and post-quantum migration for decision makers | **$15,000** |
| Advisory Retainer | Standing monthly cadence | **$3,500/mo** |

## Why the numbers are credible

Public work, verifiable by anyone:

- **177-record hash chain** verified end to end: 177 of 177 records reproduce their digest, two distinct preimage constructions detected, and a planted forgery caught by recomputation.
- **Chain head anchored to Bitcoin** via OpenTimestamps across four independent calendar servers, with block headers and merkle paths independently recomputed rather than taken on the server's word.
- **A verifier that failed publicly and was fixed.** My own tooling once reported 124 records as corrupt because it assumed a single schema. It was wrong, the corpus was intact, and the correction is in the record. The failure mode became a feature of the product.
- **Measured, not asserted:** a synchronisation threshold measured at 0.849 against a theoretical 0.798, with the estimator's own bias quantified rather than hidden.

## What I will not claim

I will not tell you a system is secure. I will not certify compliance. I will not testify that events described in a log actually occurred. A verification report proves internal consistency and tamper detection. It does not prove truth, authorship, or operational adequacy. Anyone selling you the latter from a five day review is selling you something else.

## How to buy

**Card:** all options are listed at the storefront, though card checkout requires the processor to finish account verification before it will accept payment. It will be live once that clears.

**Direct, works today:**

- ETH / ERC-20: `0x35F558b5b439189096B3dBc42bd53bFe15055eAB`
- BTC: `1HPtF5cYpkDtusu7cmBxVH5ZnqZkkUVJ7a`

Send the amount, then email the transaction hash and which engagement you want to **legal@evez-os.org**. Work begins on confirmation. If scope is unclear I will quote before starting, and I will decline work I cannot do honestly.

## Contact

legal@evez-os.org

*EVEZ Research · Bullhead City, Arizona*
