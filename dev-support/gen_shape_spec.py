#!/usr/bin/env python3
"""Generate shape_spec.rs from central-rust/migrations/*.sql + manifest.json."""
import json, re, sys, os

MIG = "$CENTRAL_RUST_SRC/migrations"
manifest = json.load(open(os.path.join(MIG, "manifest.json")))["migrations"]
manifest.sort(key=lambda m: m["version"])

def split_statements(sql):
    """Split on top-level ';', tracking quotes, $$ bodies, line comments."""
    stmts, buf, i, n = [], [], 0, len(sql)
    depth, in_sq, in_dq, in_line_comment = 0, False, False, False
    dollar_tag = None
    while i < n:
        c = sql[i]
        two = sql[i:i+2]
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            i += 1
            continue
        if dollar_tag is not None:
            if sql.startswith(dollar_tag, i):
                i += len(dollar_tag)
                dollar_tag = None
                continue
            i += 1
            continue
        if in_sq:
            if c == "'":
                if sql[i+1:i+2] == "'":
                    i += 2
                    continue
                in_sq = False
            buf.append(c); i += 1; continue
        if in_dq:
            if c == '"':
                in_dq = False
            buf.append(c); i += 1; continue
        if two == "--":
            in_line_comment = True; i += 2; continue
        if c == "$":
            mtag = re.match(r"\$[A-Za-z_0-9]*\$", sql[i:])
            if mtag:
                dollar_tag = mtag.group(0)
                i += len(dollar_tag); continue
        if c == "'":
            in_sq = True; buf.append(c); i += 1; continue
        if c == '"':
            in_dq = True; buf.append(c); i += 1; continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == ";" and depth == 0:
            stmts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c); i += 1
    if "".join(buf).strip():
        stmts.append("".join(buf))
    return stmts

def split_top_commas(s):
    parts, buf, depth, i, n = [], [], 0, 0, len(s)
    in_sq = False
    while i < n:
        c = s[i]
        if in_sq:
            if c == "'":
                in_sq = False
            buf.append(c); i += 1; continue
        if c == "'":
            in_sq = True; buf.append(c); i += 1; continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(buf)); buf = []
            i += 1; continue
        buf.append(c); i += 1
    if "".join(buf).strip():
        parts.append("".join(buf))
    return parts

KW_SKIP = {"CONSTRAINT","PRIMARY","FOREIGN","UNIQUE","CHECK","LIKE","EXCLUDE","REFERENCES"}

class Spec:
    def __init__(self, version, checksum):
        self.version = version
        self.checksum = checksum
        self.tables = []
        self.new_table_columns = []   # (table, col)
        self.added_columns = []       # (table, col)
        self.dropped_columns = []
        self.indexes = []
        self.dropped_indexes = []
        self.constraints = []
        self.dropped_constraints = []
        self.grants = []              # (table, priv) -> order preserved, dedup
        self.column_grants = []       # (table, col)
        self.revoked = []             # (table, priv)
        self.functions = []
        self.triggers = []
        self.dropped_triggers = []
        self.tables_dropped = []
        self.unrecognized = []
        self.events = []  # ordered (action, payload) tuples

def norm(s):
    return re.sub(r"\s+", " ", s).strip()

specs = []
unrec_all = []
for m in manifest:
    sp = Spec(m["version"], m["ledger_checksum"])
    raw = open(os.path.join(MIG, m["file"])).read()
    for stmt in split_statements(raw):
        s = norm(stmt)
        if not s:
            continue
        low = s.upper()
        if low == "DO" or low.startswith(("BEGIN", "COMMIT", "SET ", "INSERT INTO CENTRAL.SCHEMA_MIGRATIONS",
                            "UPDATE CENTRAL.SCHEMA_MIGRATIONS", "INSERT INTO CENTRAL.MIGRATION_CHECKSUMS",
                            "INSERT INTO CENTRAL.WORKSPACES", "INSERT INTO CENTRAL.EPOCH_MARKERS",
                            "INSERT INTO CENTRAL.BOOTSTRAP_GENERATIONS", "INSERT INTO CENTRAL.MIGRATION_PROGRESS", "INSERT INTO CENTRAL.", "WITH ",
                            "DO", "LOCK TABLE", "UPDATE CENTRAL.", "DELETE FROM CENTRAL.", "CREATE SCHEMA")):
            continue
        mt = re.match(r"CREATE TABLE (?:IF NOT EXISTS )?central\.(\w+)\s*\(", s, re.I)
        if mt:
            tbl = mt.group(1)
            sp.tables.append(tbl)
            sp.events.append(("create", ("T", tbl)))
            body = s[s.index("(", mt.start()):]
            body = body[1:body.rfind(")")] if ")" in body else body[1:]
            for item in split_top_commas(body):
                it = norm(item)
                if not it:
                    continue
                kw = re.match(r"[A-Za-z_][A-Za-z_0-9$]*", it)
                first = kw.group(0) if kw else ""
                if first.upper() in KW_SKIP:
                    if first.upper() == "CONSTRAINT":
                        cname = it.split()[1]
                        sp.constraints.append(cname)
                        sp.events.append(("create", ("K", cname)))
                    continue
                sp.new_table_columns.append((tbl, first))
                sp.events.append(("create", ("C", tbl, first)))
            continue
        mt = re.match(r"ALTER TABLE (?:ONLY )?central\.(\w+)\s+(.*)", s, re.I | re.S)
        if mt:
            tbl, actions = mt.group(1), mt.group(2)
            for act in split_top_commas(actions):
                a = norm(act)
                if not a:
                    continue
                mm = re.match(r"ADD COLUMN (?:IF NOT EXISTS )?(\w+)", a, re.I)
                if mm:
                    sp.added_columns.append((tbl, mm.group(1)))
                    sp.events.append(("create", ("C", tbl, mm.group(1))))
                    continue
                mm = re.match(r"DROP COLUMN (?:IF EXISTS )?(\w+)", a, re.I)
                if mm:
                    sp.dropped_columns.append((tbl, mm.group(1)))
                    sp.events.append(("drop", ("C", tbl, mm.group(1))))
                    continue
                mm = re.match(r"ADD CONSTRAINT (\w+)", a, re.I)
                if mm:
                    sp.constraints.append(mm.group(1))
                    sp.events.append(("create", ("K", mm.group(1))))
                    continue
                mm = re.match(r"DROP CONSTRAINT (?:IF EXISTS )?(\w+)", a, re.I)
                if mm:
                    sp.dropped_constraints.append(mm.group(1))
                    sp.events.append(("drop", ("K", mm.group(1))))
                    continue
                if re.match(r"(ALTER COLUMN|ADD PRIMARY KEY|VALIDATE CONSTRAINT|ADD UNIQUE|ENABLE|DISABLE|RENAME)", a, re.I):
                    continue
                sp.unrecognized.append("ALTER action: " + a[:80])
            continue
        mt = re.match(r"CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?(\w+)", s, re.I)
        if mt:
            sp.indexes.append(mt.group(1))
            sp.events.append(("create", ("I", mt.group(1))))
            continue
        mt = re.match(r"DROP INDEX (?:IF EXISTS )?(?:central\.)?(\w+)", s, re.I)
        if mt:
            sp.dropped_indexes.append(mt.group(1))
            sp.events.append(("drop", ("I", mt.group(1))))
            continue
        mt = re.match(r"CREATE (?:OR REPLACE )?FUNCTION central\.(\w+)", s, re.I)
        if mt:
            sp.functions.append(mt.group(1))
            sp.events.append(("create", ("F", mt.group(1))))
            continue
        mt = re.match(r"CREATE (?:OR REPLACE )?TRIGGER (\w+)", s, re.I)
        if mt:
            sp.triggers.append(mt.group(1))
            sp.events.append(("create", ("TR", mt.group(1))))
            continue
        mt = re.match(r"DROP TRIGGER (?:IF EXISTS )?(\w+)", s, re.I)
        if mt:
            sp.dropped_triggers.append(mt.group(1))
            sp.events.append(("drop", ("TR", mt.group(1))))
            continue
        mt = re.match(r"DROP TABLE (?:IF EXISTS )?(?:central\.)?(\w+)", s, re.I)
        if mt:
            sp.tables_dropped.append(mt.group(1))
            sp.events.append(("drop", ("T", mt.group(1))))
            continue
        mt = re.match(r"GRANT ([A-Z, ]+?)\s*(?:\(([^)]*)\))?\s+ON (?:SCHEMA |TABLE )?((?:central\.)?\w+(?:\s*,\s*(?:central\.)?\w+)*)\s+TO (\w+)", s, re.I)
        if mt:
            privs = [p.strip() for p in mt.group(1).split(",")]
            cols = mt.group(2)
            tables = [t.strip().split(".")[-1] for t in mt.group(3).split(",")]
            grantee = mt.group(4)
            if grantee != "central_runtime" or "SCHEMA" in mt.group(0).upper().split(" ON ")[1].split(" TO ")[0]:
                if mt.group(3).strip() == "central" and "SCHEMA" in s.upper():
                    continue
            if grantee != "central_runtime":
                continue
            for t in tables:
                for p in privs:
                    if cols:
                        for c in [x.strip() for x in cols.split(",")]:
                            sp.column_grants.append((t, c))
                            sp.events.append(("cgrant", ("CG", t, c, p)))
                    else:
                        sp.grants.append((t, p))
                        sp.events.append(("grant", ("G", t, p)))
            continue
        mt = re.match(r"REVOKE ([A-Z, ]+?)\s+ON (?:TABLE )?((?:central\.)?\w+(?:\s*,\s*(?:central\.)?\w+)*)\s+FROM (\w+)", s, re.I)
        if mt:
            privs = [p.strip() for p in mt.group(1).split(",")]
            tables = [t.strip().split(".")[-1] for t in mt.group(2).split(",")]
            grantee = mt.group(3)
            if grantee == "central_runtime":
                for t in tables:
                    for p in privs:
                        sp.revoked.append((t, p))
                        sp.events.append(("revoke", ("G", t, p)))
            continue
        # Fallback: conditional DDL inside DO bodies (BEGIN IF ... THEN ALTER ...)
        if re.search(r"\bADD CONSTRAINT\b", s):
            mt2 = re.search(r"ALTER TABLE (?:ONLY )?central\.(\w+)", s, re.I)
            tbl2 = mt2.group(1) if mt2 else None
            for nm in re.finditer(r"ADD CONSTRAINT (\w+)", s):
                sp.constraints.append(nm.group(1))
                sp.events.append(("create", ("K", nm.group(1))))
            for nm in re.finditer(r"ADD COLUMN (?:IF NOT EXISTS )?(\w+)", s):
                if tbl2:
                    sp.added_columns.append((tbl2, nm.group(1)))
                    sp.events.append(("create", ("C", tbl2, nm.group(1))))
            continue
        sp.unrecognized.append(s[:90])

    # DO bodies: re-run the same classifier over their inner statements.
    for dm in re.finditer(r"\$[A-Za-z_0-9]*\$(.*?)\$[A-Za-z_0-9]*\$", raw, re.S):
        body = dm.group(1)
        for inner in split_statements(body):
            is_ = norm(inner)
            if not is_:
                continue
            mtb = re.search(r"ALTER TABLE (?:ONLY )?central\.(\w+)", is_, re.I)
            tblb = mtb.group(1) if mtb else None
            for nm in re.finditer(r"ADD CONSTRAINT (\w+)", is_):
                sp.constraints.append(nm.group(1))
                sp.events.append(("create", ("K", nm.group(1))))
            for nm in re.finditer(r"ADD COLUMN (?:IF NOT EXISTS )?(\w+)", is_):
                if tblb:
                    sp.added_columns.append((tblb, nm.group(1)))
                    sp.events.append(("create", ("C", tblb, nm.group(1))))
            for nm in re.finditer(r"DROP CONSTRAINT (?:IF EXISTS )?(\w+)", is_):
                sp.events.append(("drop", ("K", nm.group(1))))
            for nm in re.finditer(r"CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?(\w+)", is_):
                sp.indexes.append(nm.group(1))
                sp.events.append(("create", ("I", nm.group(1))))
            for nm in re.finditer(r"DROP INDEX (?:IF EXISTS )?(?:central\.)?(\w+)", is_):
                sp.events.append(("drop", ("I", nm.group(1))))
            for nm in re.finditer(r"GRANT ([A-Z, ]+?)(?:\(([^)]*)\))?\s+ON (?:TABLE )?((?:central\.)?\w+(?:\s*,\s*(?:central\.)?\w+)*)\s+TO (\w+)", is_):
                privs = [p.strip() for p in nm.group(1).split(",")]
                cols = nm.group(2)
                tables = [t.strip().split(".")[-1] for t in nm.group(3).split(",")]
                if nm.group(4) != "central_runtime":
                    continue
                for t in tables:
                    for p in privs:
                        if cols:
                            for c in [x.strip() for x in cols.split(",")]:
                                sp.events.append(("cgrant", ("CG", t, c, p)))
                        else:
                            sp.events.append(("grant", ("G", t, p)))
    specs.append(sp)
    unrec_all.extend((m["version"], u) for u in sp.unrecognized)

print("=== UNRECOGNIZED ===", file=sys.stderr)
for v, u in unrec_all:
    print(v, u, file=sys.stderr)

# ---- compute net final state (replay events in file order) ----
created = {}   # key -> creating version
dropped_final = {}  # key -> dropping version (only net-absent kept at the end)

for sp in specs:
    for action, key in sp.events:
        if action == "create" or action == "cgrant" or action == "grant":
            created[key] = sp.version
            if action == "grant":
                dropped_final.pop(("RV", key[1], key[2]), None)
            elif key in dropped_final:
                del dropped_final[key]
        elif action == "drop":
            created.pop(key, None)
            dropped_final[key] = sp.version
        elif action == "revoke":
            if key[2] == "ALL":
                for k in [k for k in created if k[0] == "G" and k[1] == key[1]]:
                    del created[k]
            else:
                created.pop(key, None)
            dropped_final[("RV", key[1], key[2])] = sp.version

by_version = {}
for key, ver in created.items():
    by_version.setdefault(ver, []).append(key)
for key, ver in dropped_final.items():
    by_version.setdefault(ver, []).append(("ABSENT",) + key[1:] if key[0] != "RV" else key)

def fmt_list(items):
    return "&[" + ", ".join(items) + "]"

out = []
out.append("#![allow(clippy::all)]")
out.append("#![allow(dead_code)]")
out.append("")
out.append("//! GENERATED from `migrations/*.sql` + `manifest.json` — do not edit by hand.")
out.append("//! Regenerate with `python3 dev-support/gen_shape_spec.py`.")
out.append("")
out.append("pub(crate) struct MigrationShape {")
out.append("    pub version: i64,")
out.append("    pub checksum: &'static str,")
out.append("    pub tables: &'static [&'static str],")
out.append("    pub columns: &'static [(&'static str, &'static str)],")
out.append("    pub indexes: &'static [&'static str],")
out.append("    pub constraints: &'static [&'static str],")
out.append("    pub runtime_grants: &'static [(&'static str, &'static str)],")
out.append("    pub column_grants: &'static [(&'static str, &'static str)],")
out.append("    pub revoked_table_privileges: &'static [(&'static str, &'static str)],")
out.append("    pub functions: &'static [&'static str],")
out.append("    pub triggers: &'static [&'static str],")
out.append("    pub absent_constraints: &'static [&'static str],")
out.append("    pub absent_indexes: &'static [&'static str],")
out.append("    pub absent_triggers: &'static [&'static str],")
out.append("}")
out.append("")
out.append("pub(crate) static MIGRATION_SHAPES: &[MigrationShape] = &[")

for sp in specs:
    keys = by_version.get(sp.version, [])
    def pick(kind):
        return sorted(k[1:] for k in keys if k[0] == kind)
    def pick1(kind):
        return sorted(k[1] for k in keys if k[0] == kind)
    tables = pick1("T"); cols = pick("C"); idx = pick1("I"); cons = pick1("K")
    grants = pick("G"); cgs = pick("CG"); fns = pick1("F"); trs = pick1("TR")
    rvs = pick("RV")
    abs_c = sorted(k[1] for k in keys if k[0] == "ABSENT" and len(k) == 3)
    # absent entries from dropped_final mapped by ("ABSENT", name)
    absent_cons = sorted(set(c for (k, v) in dropped_final.items() for c in ([k[1]] if k[0]=="K" else []) if v == sp.version))
    absent_idx = sorted(set(k[1] for k, v in dropped_final.items() if k[0] == "I" and v == sp.version))
    absent_trg = sorted(set(k[1] for k, v in dropped_final.items() if k[0] == "TR" and v == sp.version))
    out.append("    MigrationShape {")
    out.append(f'        version: {sp.version},')
    out.append(f'        checksum: "{sp.checksum}",')
    out.append("        tables: " + fmt_list([f'"{t}"' for t in tables]) + ",")
    out.append("        columns: " + fmt_list([f'("{t}", "{c}")' for t, c in cols]) + ",")
    out.append("        indexes: " + fmt_list([f'"{i}"' for i in idx]) + ",")
    out.append("        constraints: " + fmt_list([f'"{c}"' for c in cons]) + ",")
    out.append("        runtime_grants: " + fmt_list([f'("{t}", "{p}")' for t, p in grants]) + ",")
    out.append("        column_grants: " + fmt_list([f'("{t}", "{c}")' for t, c, _p in cgs]) + ",")
    out.append("        revoked_table_privileges: " + fmt_list([f'("{t}", "{p}")' for t, p in rvs]) + ",")
    out.append("        functions: " + fmt_list([f'"{f}"' for f in fns]) + ",")
    out.append("        triggers: " + fmt_list([f'"{t}"' for t in trs]) + ",")
    out.append("        absent_constraints: " + fmt_list([f'"{c}"' for c in absent_cons]) + ",")
    out.append("        absent_indexes: " + fmt_list([f'"{i}"' for i in absent_idx]) + ",")
    out.append("        absent_triggers: " + fmt_list([f'"{t}"' for t in absent_trg]) + ",")
    out.append("    },")
out.append("];")

sys.stdout.write("\n".join(out) + "\n")
