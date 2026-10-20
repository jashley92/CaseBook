# Full-text search on SQL Server

Section 9 of the [operations guide](../OPERATIONS.md), which keeps the deploy-time checklist and the host controls. Section numbers are kept, so "OPERATIONS.md section 9" in the app and the scripts means this page.

## 9. Full-text search on SQL Server (CAP-22)

Find and the case-list search match words. Without help, SQL Server does that by reading every row of every text
column (`LIKE '%word%'`), on every keystroke in the command bar, which slows as the record grows. With SQL Server's
**Full-Text Search** feature, CaseBook keeps full-text indexes on the free-text columns and matches words from them.
It's **optional**: without the feature, search works as before, by substring.

| | With Full-Text Search | Without |
|---|---|---|
| How a word matches | Words that **start with** it (`lsa` finds "LSASS", not "salsa") | **Anywhere** in the text |
| Columns | Case title and summary; brief summary, working assessment, known and open questions; record entry text and *why*; working notes; task titles, descriptions and comments; evidence descriptions | All of them |
| Words joined by `_` or `-` (`svc_backup`, `e-mail`) | One word: found by `svc_backup`, `svc`, `e-mail`; **not** by `backup` or `mail` | Found by any part |
| Indicators, case numbers, entities, evidence file names, phase reasons, the review | Anywhere in the text (substring), as without | Anywhere |
| A save | Searchable within seconds (change tracking) | At once |

**The trade-off, precisely (CAP-22 review).** SQL Server's English word breaker splits text at spaces and most
punctuation, but keeps a word joined by `_` or `-` whole: `svc_backup`, `lsass_dump` and `e-mail` are each one entry
in the index, and a search word matches entries that **start with** it. So by word, `svc` and `svc_backup` find
"svc_backup" but `backup` doesn't, and `e-mail` finds "e-mail" but `mail` doesn't. Evidence file names, which are
nearly always joined words, aren't indexed at all and stay a substring match (`dump` finds `lsass_dump.dmp`); the
Evidence table is small. For the other free text, a site whose analysts need the part after the join found can set
**Administration › Search › How search matches words** (`Search:Mode`) to *Anywhere in the text*
(`Substring`): every search then reads every row of every searched column, as without the feature (on the measured
500-case database, about 340 ms a Find keystroke and 2 s a case-list search instead of 215 ms and 277 ms;
[performance.md](../reference/performance.md)), and the indexes stay in place, kept up to date, for switching back.
`Auto` (the default) uses the indexes; the value is read by name, takes effect at the next search, and anything else
means `Auto`. Merging a substring pass into a full-text one when it finds little was considered and not done: it
would bring the scan back for the rare words analysts search for most, and still miss the joined words whenever the
full-text pass found a few results.

**Setting it up.** Install the feature (SQL Server setup, *Full-Text and Semantic Extractions for Search*) before the
app's first start, and CaseBook's migration (`FullTextSearch`) creates the catalog `CaseBookText` and its indexes:
English word breaker, no stoplist (so no word is ignored as a noise word), automatic change tracking, and each table's
primary key as the full-text key. On a server without the feature the migration does nothing and completes.

Added the feature later? In **Administration › Diagnostics**, the *Search* row offers **Create full-text indexes**
(`Administer`, recorded in the audit trail as `FullTextSearch`). It creates whatever is missing and changes nothing
else. It needs the app's database account to be allowed to (`db_owner`, as `AppMigrates` grants). With `DbaApplies`,
the DBA runs the same statements from `deploy\sql\03-Enable-FullText.sql` (idempotent, not in a transaction):

```powershell
sqlcmd -S SQLHOST\INSTANCE -E -b -C -I -d CaseBook -i deploy\sql\03-Enable-FullText.sql
```

SQL Server fills new indexes in the background; until they're filled, search stays substring. `Verify-Install.ps1`
reports whether the instance has the feature, as information.

**Watching it.** Diagnostics' *Search* row shows the mode:

- *Search: full-text (SQL Server)*
- *Search: full-text on some columns, substring on the rest* (it names them)
- *Search: substring (full-text indexes still being filled)*
- *Search: substring (full-text installed, CaseBook's indexes not created)*
- *Search: substring (full-text not installed)*
- *Search: substring (full-text couldn't be checked)*
- *Search: substring (full-text turned off by the Search mode setting)*, with the indexes' own state beside it

A column with no full-text index is named, and *Create full-text indexes* offered, whatever the mode (one still
being filled while another was never made read only as *still being filled* before).

It's checked at startup (and logged), every 5 minutes (30 seconds while filling), when Diagnostics opens, and on
*Check again*. A full-text query the server refuses (an index dropped since the check, an input the word breaker can't
read) runs again by substring, so the person searching still gets their answer. The first of each kind is logged as a
warning ("A full-text search (Find) failed with SQL Server error …"), later ones at Debug. The row counts them, and the
status is checked again at the next search.

**Schema changes.** SQL Server refuses to alter or drop a column that's in a full-text index. A future migration that
changes one of the columns above has to take it out of the index first (`ALTER FULLTEXT INDEX … DROP (…)`) and put it
back after. `FullTextSchema` in `Infrastructure/Persistence` lists them.

**Taking it out.** Drop the indexes (`DROP FULLTEXT INDEX ON …`), then the catalog (`DROP FULLTEXT CATALOG
[CaseBookText]`). CaseBook returns to substring search at its next check; nothing else depends on them.
