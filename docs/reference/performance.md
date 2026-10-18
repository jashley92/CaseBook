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
| **Integrity monitor** | Every 10 minutes it hashes the audit entries written since the last cycle and checks every record; the whole chain is re-hashed every 6 hours (BUG-257). | The full re-hash is a stream, linear in audit rows. The per-record map of latest hashes is kept in memory between cycles (one entry per audited record). |
| **Compliance bundle** | Streams the whole chain to verify it, then reads the range again into a temp-file zip (BUG-256). | The verify pass is linear in audit rows; memory stays flat. |
| **Evidence re-hash** | Reads every stored file on its interval. | I/O heavy; off by default; schedule it for quiet hours via the interval. |
| **Report generation** | Builds the model, renders diagrams with SkiaSharp, writes Word. | A case with very large timelines or graphs takes seconds. It runs in the background (`ReportJobs`, one at a time), so nobody waits on the page; a queue of many large reports finishes in order. |
| **Indicators page** | Every visible occurrence is read and grouped in memory for each load (the summary counts the whole library); 300 rows a page, paged by keyset (CAP-27). The CSV reads the same way, up to 50,000 indicators. | Linear in recorded entities; a library of hundreds of thousands of occurrences makes each page a second or more. |
| **Audit and access-log CSV** | Streamed to the response as they're read (CAP-32): one statement, written out 64 KB at a time, so memory stays flat. Up to 1,000,000 rows (what one spreadsheet sheet opens); a cut file says so at the top and the end. A time limit of 15 minutes plus a second per 1,000 rows (C10), past which the file's last line says it's incomplete and the download fails. Measured in the test suite: about 100,000 access-log rows in a few seconds on SQLite and SQL Server. | The statement holds a database connection for the length of the download; under read-committed snapshot (set by the installer) it doesn't block writers. A slow client can reach the time limit on a very large range. |
| **Find and the case-list search** (CAP-22) | Find sends one query per kind on every command-bar keystroke (debounced); the case list searches about a dozen kinds of text per case. Without full-text, each word is `LIKE '%word%'` over every row. Measured by `FindThroughputTests` on SQL Server 2022 without Full-Text Search, 500 cases with 50,000 entries and notes: **about 350 ms** a keystroke for Find, **about 2.3 s** for a case-list search. With SQL Server Full-Text Search the free-text columns are matched from full-text indexes (`CONTAINS`, word prefixes) instead of a scan ([OPERATIONS.md §9](../OPERATIONS.md#9-full-text-search-on-sql-server-cap-22)). | Measured 2026-10-18 on SQL Server 2022 **with** Full-Text Search (500 cases, 25,000 entries): Find **about 215 ms** a keystroke (substring on the same data: about 340 ms), case-list search **277 ms** (substring: about 2.0 s). Entities, case numbers and indicators stay substring scans (they're smaller). A new searched text column should be added to `FullTextSchema` and to a migration. |
| **Graph** | vis-network in the browser; positions saved per drag. | Hundreds of nodes get slow to lay out. |

## Database

- Indexes exist for the common filters: case number (unique), classification, phase, archived, and per-child
  `CaseId`; timeline `(CaseId, Kind, IsCurrent)` and `OccurredAtUtc`; audit `Sequence` (unique), `CaseNumber`,
  `AtUtc`; access log by actor, case, type and time.
- No query filters or lazy loading; queries are explicit LINQ per service, mostly `AsNoTracking` for reads.
- Read-committed snapshot isolation is turned on by the database installer, so dashboards don't block writers.
- Optional full-text indexes (CAP-22, catalog `CaseBookText`) on the free-text columns Find and the case list search,
  where the instance has Full-Text Search. Change tracking is automatic, so writes update them in the background.
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
- Match search text through `TextMatch.Has` (CAP-22), not `ToLower().Contains()`, so the column uses the full-text
  index where there is one; keep indicators and case numbers on the exact path.
- **Needs verification:** behavior at very large audit logs (over 1 million rows) hasn't been measured.
