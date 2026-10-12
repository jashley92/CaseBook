"""Runs each data statement in an EF idempotent SQL Server script through EXEC (BUG-133; see sqlserver-script.sh).

Usage: defer_data_statements.py <ef-script> <output>
"""
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding='utf-8-sig') as f:
    text = f.read().replace('\r\n', '\n')

# A guarded block: IF NOT EXISTS (... MigrationId ...) BEGIN <body> END;. A data statement there (INSERT, UPDATE,
# DELETE, MERGE) comes from migrationBuilder.Sql; EF's schema statements (CREATE, ALTER, DROP, the DECLARE before a
# DROP COLUMN, sp_rename) and its own EXEC-wrapped data seeding are left as they are.
GUARD = re.compile(
    r"(IF NOT EXISTS \(\n    SELECT \* FROM \[__EFMigrationsHistory\]\n    WHERE \[MigrationId\] = N'[^']+'\n\)\nBEGIN\n)"
    r"(.*?)(\nEND;\n)", re.S)
DATA = re.compile(r"^\s*(INSERT|UPDATE|DELETE|MERGE)\b", re.I)

wrapped = 0


def wrap(m):
    global wrapped
    body = m.group(2).strip('\n')
    if not DATA.match(body):
        return m.group(0)
    wrapped += 1
    return m.group(1) + "    EXEC(N'" + body.replace("'", "''") + "');" + m.group(3)


fixed = GUARD.sub(wrap, text)
# Written as EF writes it on Windows (BOM, CRLF), the form checked in.
with open(dst, 'w', encoding='utf-8-sig', newline='\r\n') as f:
    f.write(fixed)
print(f"wrote {dst} ({wrapped} data statement(s) run through EXEC)")
