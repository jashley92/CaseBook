"""Compares a freshly generated DBA schema script with the checked-in one, apart from the EF Core version stamp.

    python tools/schema/same_schema.py <generated> <checked-in>

Each migration's history row is written with the EF Core version that generated the script
(INSERT INTO [__EFMigrationsHistory] ... VALUES (N''<id>'', N''10.0.14'')). The packages float on 10.*, so a new EF
patch changes every stamp without changing the schema; CI then failed with no migration changed. The stamp is
informational, so it's left out of the comparison. Anything else that differs is printed and fails (exit 1).
"""
import difflib
import re
import sys

STAMP = re.compile(r"(VALUES \(N''[^']+'', N'')[^']+('')")


def lines(path):
    with open(path, encoding="utf-8-sig") as f:
        return [STAMP.sub(r"\1<ef>\2", line.rstrip("\r\n")) for line in f]


generated, checked_in = lines(sys.argv[1]), lines(sys.argv[2])
if generated == checked_in:
    sys.exit(0)
diff = list(difflib.unified_diff(checked_in, generated, "checked-in", "generated", lineterm=""))
print("\n".join(diff[:120]))
sys.exit(1)
