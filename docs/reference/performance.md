# Performance and scalability

CaseBook is sized for one security team: tens of analysts, hundreds to low thousands of cases a year, tens to a
few hundred timeline entries per case. This page lists where time and memory go, so changes don't make them
worse.

## Expected volumes

| Thing | Typical | Grows with |
|---|---|---|
| Cases | hundreds per year | years of retention |
| Timeline entries, entities, notes, tasks per case | tens to a few hundred | case complexity |
| Audit-log rows | a few per change; tens of thousands per year | every edit |
| Access-log rows | coalesced per user, case and window | reads (prunable) |
| Evidence | the main storage growth, on disk | uploads |
| Concurrent users | tens | each open tab holds a circuit in memory |

## Hot paths

| Path | Behavior | Watch out for |
|---|---|---|
| **Opening a case** | `CaseService.GetDetailAsync` loads the whole case and all children in one split query (about 20 `Include`s). The timeline merges entries and milestones in memory. No paging inside a case. | Adding another `Include` adds a round trip to every case open. Keep children small; don't load blobs. |
| **Live refresh** | A save re-reads, for every viewer of the case, only the parts it changed (an entry re-reads the record, a task the tasks); a change to the case itself (phase, rung, severity, team, gates) still re-reads the whole case. The gate readiness is re-evaluated either way. | A burst of case-level changes on a busy case still reloads it for everyone watching. |
| **Case list** | Filtered and paged in SQL (default 25). Sorting by **SLA** loads a small projection of every matching case into memory, ranks them and then loads the page. | Fine at thousands of cases; reconsider if the filtered set grows into tens of thousands. |
| **Dashboard** | Counts and averages are computed in a single scan (`OneScan`, conditional aggregates), measured at 100k cases on SQL Server. Trends are rebuilt from case timestamps. | Don't add per-figure queries; register figures with `OneScan`. |
| **Elapsed-time math** | `DbTime.TicksBetween` maps to `DATEDIFF_BIG` on SQL Server and subtraction on SQLite, so durations aggregate in the database. | Use it rather than loading rows to compute durations. |
| **Integrity monitor** | **Every 10 minutes it loads the entire audit log** and recomputes every hash. | Linear in audit rows. At hundreds of thousands of rows this becomes noticeable CPU and memory every 10 minutes; incremental verification from the last seal isn't implemented. |
| **Compliance bundle** | Loads the whole chain into memory to verify it, then writes the segment. | Same growth as above. |
| **Evidence re-hash** | Reads every stored file on its interval. | I/O heavy; off by default; schedule it for quiet hours via the interval. |
| **Report generation** | Builds the model, renders diagrams with SkiaSharp, writes Word. | A case with very large timelines or graphs takes seconds; it runs on the circuit, so the user waits. |
| **Indicators page** | Capped at 300 rows. | |
| **Audit and access-log CSV** | Capped at 100,000 rows, silently. | Large ranges are truncated. |
| **Graph** | vis-network in the browser; positions saved per drag. | Hundreds of nodes get slow to lay out. |

## Database

- Indexes exist for the common filters: case number (unique), classification, phase, archived, and per-child
  `CaseId`; timeline `(CaseId, Kind, IsCurrent)` and `OccurredAtUtc`; audit `Sequence` (unique), `CaseNumber`,
  `AtUtc`; access log by actor, case, type and time.
- No query filters or lazy loading; queries are explicit LINQ per service, mostly `AsNoTracking` for reads.
- Read-committed snapshot isolation is turned on by the database installer, so dashboards don't block writers.
- SQLite in development stores dates as ticks; performance there isn't representative.

## Memory and connections

- Each browser tab is a Blazor circuit holding its component state in server memory. Large in-memory lists (a
  whole case, a report preview) live as long as the tab.
- Contexts are short-lived, one per operation, so connections return to the pool quickly.
- The SIEM queue is bounded (2048 events).

## Background work

All jobs run in-process on timers; none take a distributed lock. Most poll every 5 minutes and do nothing
unless enabled and due. The integrity monitor is the only one that always runs (see above).

## Cautions when changing code

- Don't add `Include`s to `GetDetailAsync` for data only one tab needs; load it in that tab.
- Don't compute per-row values in C# for list queries if SQL can do it.
- Any new aggregate must use `ForUser` and `ExcludingExercises`, and should go through `OneScan` if it's on the
  dashboard.
- Don't make the integrity check per-request; it's deliberately on a timer and shared.
- **Needs verification:** behavior at very large audit logs (over 1 million rows) hasn't been measured.
