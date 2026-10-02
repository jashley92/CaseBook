# 0015. Entity tags in Markdown start with `[[`

- **Status:** Accepted (v1.2.4)
- **Recorded:** 2026-10-02

## Context

Notes, the brief, reviews and timeline text can tag a case entity (an account, a host, an IOC), so that it
renders as a link to the entity. The trigger used to be `#`, which in Markdown also starts a heading, so typing
a heading opened the entity picker.

## Decision

Tagging starts with `[[` (wiki-link style). The editor's autocomplete opens on `[[`, inserts the tag and
closes it with `]]`. A toolbar button opens the same picker. The list shows entity type names ("IP address").

## Consequences

`#` is ordinary Markdown again. The change was made before anyone had been trained on `#`. The editor logic is
in `wwwroot/js/markdown-editor.js`; the hints are in the Notes, Review and Timeline tabs.
