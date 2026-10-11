#!/usr/bin/env python3
"""
audit_engine.py
Simple high-performance log auditing engine with YAML rules and tamper-evident output.
Dependencies (optional for speed/Excel): orjson, pyyaml, pandas, openpyxl
"""

import sys
import json
import yaml
import hashlib
import hmac
import time
import csv
import html
from datetime import datetime, timedelta
from collections import deque, defaultdict, Counter
from multiprocessing import Pool, cpu_count
from typing import Dict, Any, List, Tuple

# Optional fast JSON
try:
    import orjson as jsonlib
    loads = lambda s: jsonlib.loads(s)
except Exception:
    loads = lambda s: json.loads(s)

# Optional pandas for Excel
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except Exception:
    PANDAS_AVAILABLE = False

# -------------------------
# Utilities
# -------------------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

# -------------------------
# Safe expression compilation
# -------------------------
import ast, operator

ALLOWED_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.And: operator.and_,
    ast.Or: operator.or_,
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.In: lambda a,b: a in b,
    ast.NotIn: lambda a,b: a not in b,
}

ALLOWED_NAMES = {
    'len': len,
    'int': int,
    'float': float,
    'str': str,
    're_match': None,  # set later if regex used
}

import re
def re_match(pattern, s):
    if s is None:
        return False
    return re.match(pattern, str(s)) is not None
ALLOWED_NAMES['re_match'] = re_match

class SafeExpr:
    def __init__(self, expr: str):
        self.expr = expr
        self.code = self._compile(expr)

    def _compile(self, expr):
        tree = ast.parse(expr, mode='eval')
        self._validate(tree)
        return compile(tree, '<expr>', 'eval')

    def _validate(self, node):
        # recursively validate AST nodes
        if isinstance(node, ast.Expression):
            self._validate(node.body)
        elif isinstance(node, ast.BoolOp):
            if type(node.op) not in ALLOWED_OPERATORS:
                raise ValueError("Operator not allowed")
            for v in node.values:
                self._validate(v)
        elif isinstance(node, ast.BinOp):
            if type(node.op) not in ALLOWED_OPERATORS:
                raise ValueError("Operator not allowed")
            self._validate(node.left); self._validate(node.right)
        elif isinstance(node, ast.Compare):
            self._validate(node.left)
            for op, comp in zip(node.ops, node.comparators):
                if type(op) not in ALLOWED_OPERATORS:
                    raise ValueError("Comparison not allowed")
                self._validate(comp)
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise ValueError("Only simple function calls allowed")
            if node.func.id not in ALLOWED_NAMES:
                raise ValueError(f"Function {node.func.id} not allowed")
            for a in node.args:
                self._validate(a)
        elif isinstance(node, ast.Name):
            # names are allowed (they map to fields)
            if node.id.startswith('__'):
                raise ValueError("Invalid name")
        elif isinstance(node, ast.Constant):
            pass
        elif isinstance(node, ast.UnaryOp):
            self._validate(node.operand)
        elif isinstance(node, ast.Subscript):
            self._validate(node.value)
            self._validate(node.slice)
        elif isinstance(node, ast.Attribute):
            raise ValueError("Attribute access not allowed")
        else:
            # allow simple nodes like List, Tuple
            for child in ast.iter_child_nodes(node):
                self._validate(child)

    def eval(self, context: Dict[str, Any]):
        safe_globals = {k: v for k, v in ALLOWED_NAMES.items()}
        # map context fields to names
        safe_locals = dict(context)
        return eval(self.code, safe_globals, safe_locals)

# -------------------------
# Rule engine
# -------------------------
class Rule:
    def __init__(self, spec: Dict[str, Any]):
        self.id = spec['id']
        self.description = spec.get('description', '')
        self.type = spec.get('type', 'match')  # match or aggregate
        self.severity = spec.get('severity', 'medium')
        self.condition_expr = spec.get('condition')  # string
        self.condition = SafeExpr(self.condition_expr) if self.condition_expr else None
        # aggregate specifics
        self.window_seconds = int(spec.get('window_seconds', 0))
        self.agg_op = spec.get('agg_op')  # count, sum, unique_count
        self.agg_field = spec.get('agg_field')
        self.threshold = spec.get('threshold')
        self.group_by = spec.get('group_by')  # list of fields

    def matches(self, record: Dict[str, Any]) -> bool:
        if self.type == 'match':
            try:
                return bool(self.condition.eval(record))
            except Exception:
                return False
        return False

# -------------------------
# Aggregation manager (sliding window)
# -------------------------
class SlidingWindowAgg:
    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        # key -> deque of (timestamp, value)
        self.store = defaultdict(deque)

    def add(self, key: Tuple, ts: datetime, value):
        dq = self.store[key]
        dq.append((ts, value))
        self._evict(key, ts)

    def _evict(self, key, now_ts):
        dq = self.store[key]
        cutoff = now_ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def compute(self, key: Tuple, op: str):
        dq = self.store.get(key, deque())
        if op == 'count':
            return len(dq)
        if op == 'sum':
            return sum(v for _, v in dq)
        if op == 'unique_count':
            return len(set(v for _, v in dq))
        return None

# -------------------------
# Tamper-evident chain
# -------------------------
class TamperChain:
    def __init__(self, secret_key: bytes):
        self.secret = secret_key
        self.prev = '0' * 64  # genesis
        self.root = None

    def add_record(self, record_json: str, metadata: str) -> Dict[str, str]:
        record_hash = sha256_hex(record_json.encode('utf-8'))
        data = (self.prev + record_hash + metadata).encode('utf-8')
        chain_hash = hmac_sha256_hex(self.secret, data)
        entry = {'prev': self.prev, 'record_hash': record_hash, 'chain_hash': chain_hash}
        self.prev = chain_hash
        self.root = chain_hash
        return entry

    def get_root(self):
        return self.root

# -------------------------
# Evaluator and processing
# -------------------------
def process_chunk(args):
    chunk, rules_spec, secret_key = args
    rules = [Rule(r) for r in rules_spec]
    chain = TamperChain(secret_key)
    violations = []
    agg_managers = {}  # rule_id -> SlidingWindowAgg
    for rec in chunk:
        rec_json = json.dumps(rec, sort_keys=True, separators=(',', ':'))
        ts = None
        # try to parse timestamp field
        for tfield in ('timestamp', 'time', 'ts'):
            if tfield in rec:
                try:
                    ts = datetime.fromisoformat(rec[tfield].replace('Z',''))
                except Exception:
                    ts = datetime.utcnow()
                break
        if ts is None:
            ts = datetime.utcnow()
        for rule in rules:
            if rule.type == 'match':
                if rule.matches(rec):
                    meta = f"{rule.id}|{rule.severity}"
                    chain_entry = chain.add_record(rec_json, meta)
                    violations.append({
                        'rule_id': rule.id,
                        'description': rule.description,
                        'severity': rule.severity,
                        'record': rec,
                        'record_hash': chain_entry['record_hash'],
                        'chain_hash': chain_entry['chain_hash'],
                        'timestamp': ts.isoformat() + 'Z'
                    })
            elif rule.type == 'aggregate':
                # build key
                key_fields = tuple(rec.get(f) for f in (rule.group_by or []))
                if rule.id not in agg_managers:
                    agg_managers[rule.id] = SlidingWindowAgg(rule.window_seconds)
                val = rec.get(rule.agg_field, 1) if rule.agg_field else 1
                agg_managers[rule.id].add(key_fields, ts, val)
                current = agg_managers[rule.id].compute(key_fields, rule.agg_op)
                if current is not None and current >= rule.threshold:
                    meta = f"{rule.id}|{rule.severity}|agg={current}"
                    chain_entry = chain.add_record(rec_json, meta)
                    violations.append({
                        'rule_id': rule.id,
                        'description': rule.description,
                        'severity': rule.severity,
                        'record': rec,
                        'agg_value': current,
                        'record_hash': chain_entry['record_hash'],
                        'chain_hash': chain_entry['chain_hash'],
                        'timestamp': ts.isoformat() + 'Z'
                    })
    return {'violations': violations, 'chain_root': chain.get_root()}

# -------------------------
# Reporter
# -------------------------
def generate_html_report(violations: List[Dict[str,Any]], chain_root: str, out_path: str):
    rows = []
    for v in violations:
        rows.append({
            'Rule ID': v['rule_id'],
            'Severity': v['severity'],
            'Description': v['description'],
            'Timestamp': v['timestamp'],
            'Record Hash': v['record_hash'],
            'Chain Hash': v['chain_hash'],
            'Record': html.escape(json.dumps(v['record'], ensure_ascii=False))
        })
    # simple HTML
    html_rows = "".join(
        f"<tr><td>{r['Rule ID']}</td><td>{r['Severity']}</td><td>{r['Description']}</td>"
        f"<td>{r['Timestamp']}</td><td><code>{r['Record Hash']}</code></td><td><code>{r['Chain Hash']}</code></td>"
        f"<td><pre style='white-space:pre-wrap'>{r['Record']}</pre></td></tr>"
        for r in rows
    )
    summary = f"<p>Generated: {now_iso()} | Violations: {len(rows)} | Chain root: <code>{chain_root}</code></p>"
    html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Audit Report</title>
<style>table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:6px}}th{{background:#f2f2f2}}</style>
</head><body><h1>Audit Report</h1>{summary}<table><thead><tr><th>Rule</th><th>Severity</th><th>Description</th><th>Timestamp</th><th>Record Hash</th><th>Chain Hash</th><th>Record</th></tr></thead><tbody>{html_rows}</tbody></table></body></html>"""
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html_doc)
    return out_path

def generate_excel_report(violations: List[Dict[str,Any]], out_path: str):
    if not PANDAS_AVAILABLE:
        raise RuntimeError("pandas required for Excel export")
    rows = []
    for v in violations:
        rows.append({
            'Rule ID': v['rule_id'],
            'Severity': v['severity'],
            'Description': v['description'],
            'Timestamp': v['timestamp'],
            'Record Hash': v['record_hash'],
            'Chain Hash': v['chain_hash'],
            'Record': json.dumps(v['record'], ensure_ascii=False)
        })
    df = pd.DataFrame(rows)
    df.to_excel(out_path, index=False)
    return out_path

# -------------------------
# CLI / Orchestration
# -------------------------
def stream_json_lines(fileobj):
    for line in fileobj:
        line = line.strip()
        if not line:
            continue
        try:
            yield loads(line)
        except Exception:
            # try normal json
            yield json.loads(line)

def chunked_iterable(iterable, size=1000):
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

def main(argv):
    import argparse
    p = argparse.ArgumentParser(description="Audit engine")
    p.add_argument('--logs', help='Path to JSONL logs (default stdin)', default='-')
    p.add_argument('--rules', required=True, help='YAML rules file')
    p.add_argument('--out-html', default='audit_report.html')
    p.add_argument('--out-xlsx', default=None)
    p.add_argument('--chunk-size', type=int, default=5000)
    p.add_argument('--workers', type=int, default=max(1, cpu_count()-1))
    p.add_argument('--secret', required=True, help='HMAC secret key (keep safe)')
    args = p.parse_args(argv)

    with open(args.rules, 'r', encoding='utf-8') as f:
        rules_spec = yaml.safe_load(f)

    if args.logs == '-':
        source = sys.stdin
    else:
        source = open(args.logs, 'r', encoding='utf-8')

    iterator = stream_json_lines(source)
    chunks = list(chunked_iterable(iterator, size=args.chunk_size))

    # prepare parallel processing
    secret_key = args.secret.encode('utf-8')
    pool_args = [(chunk, rules_spec, secret_key) for chunk in chunks]
    results = []
    if args.workers > 1 and len(pool_args) > 1:
        with Pool(processes=args.workers) as pool:
            for res in pool.imap_unordered(process_chunk, pool_args):
                results.append(res)
    else:
        for arg in pool_args:
            results.append(process_chunk(arg))

    # merge violations and chain roots (note: each worker has its own chain; we record worker roots)
    all_violations = []
    chain_roots = []
    for r in results:
        all_violations.extend(r['violations'])
        if r.get('chain_root'):
            chain_roots.append(r['chain_root'])
    # final root is HMAC of concatenated worker roots (tamper-evidence across workers)
    final_root = hmac_sha256_hex(secret_key, ("|".join(chain_roots)).encode('utf-8')) if chain_roots else None

    html_path = generate_html_report(all_violations, final_root, args.out_html)
    print(f"HTML report: {html_path}")
    if args.out_xlsx:
        if PANDAS_AVAILABLE:
            xlsx_path = generate_excel_report(all_violations, args.out_xlsx)
            print(f"Excel report: {xlsx_path}")
        else:
            print("pandas not available; skipping Excel export")

if __name__ == '__main__':
    main(sys.argv[1:])
