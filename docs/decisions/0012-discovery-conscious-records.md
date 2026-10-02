# 0012. Discovery-conscious records

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

Case reports, lessons-learned reviews and exports can be requested in litigation or by a regulator. Wording
such as "control failure" or "gap" in a system-generated record is an admission the organization didn't
choose to make.

## Decision

- Built-in labels and generated text use neutral wording: "improvement actions", "opportunities to improve".
- Analyst notes and the working brief are **off** in the case report unless a report layout turns them on.
  They are working reasoning, not findings.
- The post-incident review prints in its **own** lessons-learned report, never inside the case report. It
  can carry a confidentiality legend.
- CaseBook records the determinations made by Legal and by the committee (materiality, referral). It never
  makes them.

## Consequences

Keep new copy neutral and factual. A new report section that exposes working material defaults to off.
