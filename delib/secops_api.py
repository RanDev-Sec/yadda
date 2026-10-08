"""secops_api - runs the queries in shared/queries through the SecOps dashboard query API and saves each result in
the environment's inputs/ folder."""
from __future__ import annotations

import datetime as dt

from delib import inputs

from delib.config import die, read_env, secops_env, SHARED, write_rows


# ---------------------------------------------------------------- run SecOps dashboard queries via the API
QUERIES = {  # name: (query file, time unit, amount, output file)
    "inventory": ("telemetry_inventory.yaral", "DAY", 7, "inventory.csv"),
    "rule_health": ("rule_health.yaral", "YEAR", 20, "rule_health.csv"),
    "rule_fp": ("rule_fp_rate.yaral", "DAY", 365, "rule_fp.csv"),
    "rule_logtypes": ("rule_logtypes.yaral", "DAY", 90, "rule_logtypes.csv"),
    "product_alerts": ("product_alerts.yaral", "DAY", 30, "product_alerts.csv"),
    "host_os": ("log_type_host_os.yaral", "DAY", 7, "host_os.csv"),
}


def _column_value(v: dict):
    """One ExecuteDashboardQueryResponse ColumnValue (proto3 JSON) -> plain value."""
    if "list" in v:
        return ";".join(str(_column_value(x)) for x in v["list"].get("values", []))
    v = v.get("value", v)
    for k in ("stringVal", "int64Val", "uint64Val", "doubleVal", "boolVal", "timestampVal"):
        if k in v:
            return v[k]
    if "dateVal" in v:
        d = v["dateVal"]
        return f"{d.get('year', 0):04d}-{d.get('month', 0):02d}-{d.get('day', 0):02d}"
    return ""


def _response_to_rows(resp: dict) -> tuple[list, list]:
    cols = resp.get("results", [])
    header = [c.get("column", f"col{i}") for i, c in enumerate(cols)]
    n = max((len(c.get("values", [])) for c in cols), default=0)
    rows = [[_column_value(c["values"][i]) if i < len(c.get("values", [])) else "" for c in cols] for i in range(n)]
    return header, rows


def run_queries(c, names=None) -> list:
    """Run the SecOps queries through the API; each result is saved into inputs/. Returns the names that worked."""
    env = read_env(c / "environment.env")
    if "INSTANCE_ID" in env.get("GOOGLE_SECOPS_INSTANCE", "INSTANCE_ID"):
        die(f"{c.name}: environment.env has no SecOps instance - export the queries by hand, or fill it in")
    import google.auth
    from google.auth.transport.requests import AuthorizedSession
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    login = secops_env(c).get("GOOGLE_APPLICATION_CREDENTIALS")     # the environment's own login, if environment.env names one
    creds, _ = (google.auth.load_credentials_from_file(login, scopes=scopes) if login
                else google.auth.default(scopes=scopes))
    session = AuthorizedSession(creds)
    url = f"{env['GOOGLE_SECOPS_API_BASE_URL'].rstrip('/')}/{env['GOOGLE_SECOPS_INSTANCE']}/dashboardQueries:execute"
    ok = []
    for name in (names or list(QUERIES)):
        if name not in QUERIES:
            die(f"unknown query {name}: one of {', '.join(QUERIES)}")
        qfile, unit, amount, out = QUERIES[name]
        text = "\n".join(l for l in (SHARED / "queries" / qfile).read_text(encoding="utf-8").splitlines()
                         if not l.strip().startswith("//"))
        body = {"query": {"query": text, "input": {"relativeTime": {"timeUnit": unit, "startTimeVal": str(amount)}}}}
        r = session.post(url, json=body, timeout=600)
        if r.status_code != 200:
            print(f"  {name}: HTTP {r.status_code} {r.text[:400]}")
            continue
        resp = r.json()
        for e in resp.get("queryRuntimeErrors", []):
            print(f"  {name}: {e.get('errorSeverity', '')} {e.get('errorTitle', '')} {e.get('errorDescription', '')[:300]}")
        header, rows = _response_to_rows(resp)
        if not header:
            print(f"  {name}: no results")
            continue
        inputs.folder(c).mkdir(exist_ok=True)
        dst = inputs.folder(c) / f"{name}_api_{dt.date.today()}.csv"
        write_rows(dst, header, rows, encoding="utf-8")
        print(f"  {name}: {len(rows)} rows -> {dst}")
        ok.append(name)
    return ok
