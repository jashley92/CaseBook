# Find

**Find** (`/find`, the sidebar, or typing into the command bar with `Ctrl+K`) searches every case you can see and
returns typed results:

| Kind | What matches | Opens |
|---|---|---|
| **Entities** | An indicator by its exact value; words by an entity's value or label. Each entity lists every case it's on, with the verdict recorded there | The entity on that case; *Across cases* opens it in Intel › Indicators |
| **Cases** | Number, title, summary and the current brief (summary and working assessment). A closed case shows how it ended | The case (a closed case opens on its Briefing) |
| **Record entries** | Current timeline entries and decisions (the text and the *why*), and a closed case's closing brief | The entry, brought into view on the Record and flashed; a closing brief opens the Briefing |
| **Tasks** | Title and description; a person's tasks | The case's Tasks |
| **Evidence names** | File name and description; a file hash matches a file's SHA-256 | The evidence panel |
| **Working notes** | Only with `in:notes` (or *Include working notes*): notes are working reasoning, not the record | The note in the Working notes lens |

The command bar shows the first few of each kind, then *See all N results in Find*.

## How Find reads the query

Above the results Find says how it read what you typed:

- **a case number** (`2026-14`, `2026-01_Phishing_Wave`, `CE-2026-10-04`): cases whose number contains it. Something
  shaped like one that no case number you can see holds (`CVE-2024-3094`, a ticket reference) is read as words.
- **an IP address, domain, URL, file hash, email address or account** (a single value; defanged values like
  `203.0.113[.]66` are refanged): entities with exactly that value, ignoring case, and the record text, tasks and
  evidence that contain it or tag the entity (by its label too), and the tasks about it. An email address or
  `DOMAIN\user` that is a colleague's sign-in name is read as both: the indicator, and that person (their cases, the
  entries they recorded and the tasks they own are listed with it).
- **a person** (a display name, a sign-in name, or a first name only one person has): the cases they lead or are
  assigned to, the entries they recorded and the tasks they own.
- **words in the record**: everything else. Every word must appear, ignoring case, in the text as you see it (a link's
  hidden target, such as `evidence:` and its id, doesn't count); quote a phrase to keep it together.
  Find uses the first 12 words or phrases and says *only the first 12 words used* when there were more.
  Characters like `%`, `_` and `[` match themselves.

## Filters

Filters narrow the question and are said back above the results. The controls beside the results edit them in the
query you can see; nothing is hidden state. A quoted word (`"admin"`) is always searched as a word, never read as a person. A filter Find can't use is listed as *not understood* rather than dropped, and so is one given twice (the last one is
used) or `owner:` alongside `type:` or `by:` (tasks aren't record entries).

| Filter | Meaning |
|---|---|
| `entity:VALUE` | Cases with that exact entity value, and the entries, tasks and notes that mention it or tag it (by its label too). With words, every word must still appear |
| `status:open`, `status:closed` | Open or closed cases (an archived case isn't open; archived results are labelled) |
| `class:event`, `adverse`, `incident`, `breach` | The rung (`event` is a Complex Event) |
| `type:decision`, `handoff`, `adversary`, `response`, or any entry type (`containment`, `communication`, …) | Which record entries; with a type filter Find lists entries only |
| `after:YYYY-MM-DD`, `before:YYYY-MM-DD` | From that day on, or up to (not including) that day: when it happened (entries) or was opened, added or raised (entities: when added to the case), in the organization's days |
| `by:NAME`, `by:me` | Who recorded it: the author of the first version, not whoever last edited it |
| `owner:NAME`, `owner:me` | Whose task: the owner names them by any of their identifiers (sign-in, email, display name). Find then lists tasks only |
| `state:NY` (or `jurisdiction:NY`) | Cases with residents of that state affected |
| `in:notes` | Include working notes |
| `exercises:yes` | Include exercises (left out otherwise) |

Examples:

| Ask | Type |
|---|---|
| My tasks on open cases | `owner:me status:open` |
| Decisions about password resets this year | `type:decision reset after:2026-01-01` |
| Breaches with New York residents | `class:breach state:NY` |
| Handoffs I recorded | `type:handoff by:me` |
| Closed cases mentioning a host | `status:closed FIN-WKS-07` |

## Limits

- Matching is exact and literal. There is no fuzzy matching, no CIDR or subdomain expansion, and part of a domain
  matches the record's text, not related indicators.
- An account and an email address with the same value are one identity (as everywhere in CaseBook).
- Need-to-know applies: restricted cases you can't see contribute nothing, and nothing says they exist.
- Nothing interprets the question but the grammar above. CaseBook never sends a query to an AI.
- Each kind lists its 25 most recent results; the count covers them all. Add words or a filter to narrow it.

Code: `Application/Search/FindQuery.cs` (the grammar), `Application/Search/FindService.cs` (the search),
`Pages/FindPage.razor`, and `Shared/CommandPalette.razor`.
