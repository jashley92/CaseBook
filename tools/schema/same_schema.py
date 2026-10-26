"""Compares a freshly generated DBA schema script with the checked-in one, apart from the EF Core version stamp.

    python tools/schema/same_schema.py < <generated script>

Each migration's history row is written with the EF Core version that generated the script
(INSERT INTO [__EFMigrationsHistory] ... VALUES (N''<id>'', N''10.0.14'')). The packages float on 10.*, so a new EF
patch changes every stamp without changing the schema; CI then failed with no migration changed. The stamp is
informational, so it's left out of the comparison. Anything else that differs is printed and fails (exit 1).
The generated script comes on stdin and the checked-in one from its place in the repo: no path is taken as an argument.
"""
import difflib
import io
import pathlib
import re
import sys

STAMP = re.compile(r"(VALUES \(N''[^']+'', N'')[^']+('')")
CHECKED_IN = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "sql" / "casebook-schema-sqlserver.sql"


def lines(text):
    return [STAMP.sub(r"\1<ef>\2", line.rstrip("\r")) for line in text.lstrip("﻿").split("\n")]


generated = lines(io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8").read())
checked_in = lines(CHECKED_IN.read_text(encoding="utf-8"))
if generated == checked_in:
    sys.exit(0)
diff = list(difflib.unified_diff(checked_in, generated, "checked-in", "generated", lineterm=""))
print("\n".join(diff[:120]))
sys.exit(1)
