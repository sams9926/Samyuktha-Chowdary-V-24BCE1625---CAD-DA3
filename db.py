import oracledb
from config import ORACLE_USER, ORACLE_PASSWORD, ORACLE_DSN

_pool = None


def get_pool():
    """One shared pool of connections, created on first use."""
    global _pool
    if _pool is None:
        _pool = oracledb.create_pool(
            user=ORACLE_USER,
            password=ORACLE_PASSWORD,
            dsn=ORACLE_DSN,
            min=1,
            max=5,
            increment=1,
        )
    return _pool


def _rows_as_dicts(cursor):
    # Oracle returns column names in UPPERCASE; we lowercase them
    cols = [c[0].lower() for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def query(sql, params=None):
    """Run a SELECT, return a list of dicts."""
    with get_pool().acquire() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or {})
            return _rows_as_dicts(cur)


def query_one(sql, params=None):
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql, params=None):
    """Run INSERT/UPDATE/DELETE and commit. Returns rows affected."""
    with get_pool().acquire() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or {})
            conn.commit()
            return cur.rowcount


def insert(sql, params=None):
    """INSERT and return the new row's id.
    The SQL must end with: RETURNING id INTO :new_id
    """
    with get_pool().acquire() as conn:
        with conn.cursor() as cur:
            new_id = cur.var(int)
            p = dict(params or {})
            p["new_id"] = new_id
            cur.execute(sql, p)
            conn.commit()
            val = new_id.getvalue()
            return val[0] if isinstance(val, list) else val