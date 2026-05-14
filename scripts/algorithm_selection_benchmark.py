#!/usr/bin/env python3
import argparse
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Metric:
  total_ns: int
  ns_per_op: float
  ops_per_sec: float


def _metric(start_ns: int, end_ns: int, iterations: int) -> Metric:
  total = max(1, end_ns - start_ns)
  return Metric(total_ns=total, ns_per_op=total / iterations, ops_per_sec=(iterations * 1_000_000_000.0) / total)


def _bench_pid_lookup(iterations: int, table_size: int, buckets: int) -> dict:
  rng = random.Random(23)
  pids = [100000 + i * 3 for i in range(table_size)]
  pid_to_idx = {pid: i for i, pid in enumerate(pids)}
  bucket_heads = [-1] * buckets
  next_idx = [-1] * table_size
  for i, pid in enumerate(pids):
    b = pid % buckets
    next_idx[i] = bucket_heads[b]
    bucket_heads[b] = i
  queries = [pids[rng.randrange(table_size)] for _ in range(iterations)]

  start = time.perf_counter_ns()
  acc_linear = 0
  for q in queries:
    found = -1
    for i, pid in enumerate(pids):
      if pid == q:
        found = i
        break
    acc_linear += found
  end = time.perf_counter_ns()
  linear = _metric(start, end, iterations)

  start = time.perf_counter_ns()
  acc_hash = 0
  for q in queries:
    b = q % buckets
    cur = bucket_heads[b]
    found = -1
    while cur != -1:
      if pids[cur] == q:
        found = cur
        break
      cur = next_idx[cur]
    acc_hash += found
  end = time.perf_counter_ns()
  hashed = _metric(start, end, iterations)

  start = time.perf_counter_ns()
  acc_dict = 0
  for q in queries:
    acc_dict += pid_to_idx[q]
  end = time.perf_counter_ns()
  dict_metric = _metric(start, end, iterations)

  return {
      "linear_scan": linear.__dict__,
      "bucket_hash_chain": hashed.__dict__,
      "reference_dict": dict_metric.__dict__,
      "sanity_accumulators": [acc_linear, acc_hash, acc_dict],
  }


def _bench_ready_pick(iterations: int, classes: int) -> dict:
  rng = random.Random(41)
  bitmaps = []
  for _ in range(iterations):
    mask = 0
    for c in range(classes):
      if rng.random() < 0.65:
        mask |= 1 << c
    if mask == 0:
      mask = 1 << rng.randrange(classes)
    bitmaps.append(mask)

  start = time.perf_counter_ns()
  acc_scan = 0
  for bm in bitmaps:
    idx = -1
    for c in range(classes - 1, -1, -1):
      if bm & (1 << c):
        idx = c
        break
    acc_scan += idx
  end = time.perf_counter_ns()
  scan_metric = _metric(start, end, iterations)

  start = time.perf_counter_ns()
  acc_bit = 0
  for bm in bitmaps:
    idx = bm.bit_length() - 1
    acc_bit += idx
  end = time.perf_counter_ns()
  bit_metric = _metric(start, end, iterations)

  return {
      "priority_scan": scan_metric.__dict__,
      "bit_length_ff1": bit_metric.__dict__,
      "sanity_accumulators": [acc_scan, acc_bit],
  }


def run(iterations: int, table_size: int, hash_buckets: int) -> dict:
  pid_lookup = _bench_pid_lookup(iterations, table_size, hash_buckets)
  ready_pick = _bench_ready_pick(iterations, 8)

  winners = {
      "pid_lookup": "bucket_hash_chain"
      if pid_lookup["bucket_hash_chain"]["ops_per_sec"] >= pid_lookup["linear_scan"]["ops_per_sec"]
      else "linear_scan",
      "ready_pick": "bit_length_ff1"
      if ready_pick["bit_length_ff1"]["ops_per_sec"] >= ready_pick["priority_scan"]["ops_per_sec"]
      else "priority_scan",
  }

  return {
      "schema_version": 1,
      "iterations": iterations,
      "table_size": table_size,
      "hash_buckets": hash_buckets,
      "pid_lookup": pid_lookup,
      "ready_pick": ready_pick,
      "winners": winners,
  }


def main() -> int:
  parser = argparse.ArgumentParser(description="AegisOS algorithm simulation benchmark lab")
  parser.add_argument("--iterations", type=int, default=250000)
  parser.add_argument("--table-size", type=int, default=256)
  parser.add_argument("--hash-buckets", type=int, default=128)
  parser.add_argument("--out", default=None)
  args = parser.parse_args()

  payload = run(args.iterations, args.table_size, args.hash_buckets)
  out = json.dumps(payload, sort_keys=True, separators=(",", ":"))
  if args.out:
    Path(args.out).write_text(out + "\n", encoding="utf-8")
  print(out)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
