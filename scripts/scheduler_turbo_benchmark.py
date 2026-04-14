#!/usr/bin/env python3
import argparse
import json
import random
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Task:
  pid: int
  priority: int
  enqueue_tick: int
  dispatch_count: int = 0
  total_wait: int = 0
  last_wait: int = 0


def _pick_round_robin(tasks: List[Task], head: int) -> int:
  return head % len(tasks)


def _pick_turbo(tasks: List[Task], now_tick: int, wait_weight: int = 2, priority_weight: int = 4) -> int:
  best_idx = 0
  best_score = -10**9
  for idx, task in enumerate(tasks):
    waited = now_tick - task.enqueue_tick
    score = task.priority * priority_weight + waited * wait_weight - (task.dispatch_count // 4)
    if score > best_score:
      best_score = score
      best_idx = idx
  return best_idx


def _p95(values: List[int]) -> int:
  if not values:
    return 0
  ordered = sorted(values)
  idx = int(0.95 * (len(ordered) - 1))
  return ordered[idx]


def simulate(strategy: str, ticks: int = 300, seed: int = 1337) -> Dict[str, object]:
  rng = random.Random(seed)
  tasks: List[Task] = [
      Task(pid=1001, priority=1, enqueue_tick=0),
      Task(pid=1002, priority=2, enqueue_tick=0),
      Task(pid=1003, priority=3, enqueue_tick=0),
      Task(pid=1004, priority=1, enqueue_tick=0),
      Task(pid=1005, priority=3, enqueue_tick=0),
  ]
  head = 0
  wait_samples: List[int] = []
  high_priority_wait_samples: List[int] = []
  for tick in range(1, ticks + 1):
    if strategy == "turbo":
      idx = _pick_turbo(tasks, tick)
    else:
      idx = _pick_round_robin(tasks, head)
    task = tasks[idx]
    wait = tick - task.enqueue_tick
    task.last_wait = wait
    task.total_wait += wait
    task.dispatch_count += 1
    task.enqueue_tick = tick
    wait_samples.append(wait)
    if task.priority == 3:
      high_priority_wait_samples.append(wait)
    head = (idx + 1) % len(tasks)
    if rng.random() < 0.12:
      burst_idx = rng.randrange(0, len(tasks))
      tasks[burst_idx].enqueue_tick = min(tasks[burst_idx].enqueue_tick, tick - rng.randrange(1, 4))

  per_task = {
      str(t.pid): {
          "dispatch_count": t.dispatch_count,
          "mean_wait": round(t.total_wait / max(1, t.dispatch_count), 3),
          "last_wait": t.last_wait,
      }
      for t in tasks
  }
  return {
      "strategy": strategy,
      "ticks": ticks,
      "mean_wait": round(sum(wait_samples) / len(wait_samples), 3),
      "p95_wait": _p95(wait_samples),
      "high_priority_p95_wait": _p95(high_priority_wait_samples),
      "max_wait": max(wait_samples),
      "per_task": per_task,
  }


def compare(ticks: int = 300, seed: int = 1337) -> Dict[str, object]:
  rr = simulate("round_robin", ticks=ticks, seed=seed)
  turbo = simulate("turbo", ticks=ticks, seed=seed)
  return {
      "schema_version": 1,
      "ticks": ticks,
      "seed": seed,
      "round_robin": rr,
      "turbo": turbo,
      "delta": {
          "mean_wait_improvement": round(rr["mean_wait"] - turbo["mean_wait"], 3),
          "p95_wait_improvement": rr["p95_wait"] - turbo["p95_wait"],
          "high_priority_p95_wait_improvement": rr["high_priority_p95_wait"] - turbo["high_priority_p95_wait"],
          "max_wait_improvement": rr["max_wait"] - turbo["max_wait"],
      },
  }


def main() -> int:
  parser = argparse.ArgumentParser(description="Benchmark scheduler turbo strategy versus round-robin.")
  parser.add_argument("--ticks", type=int, default=300)
  parser.add_argument("--seed", type=int, default=1337)
  args = parser.parse_args()
  if args.ticks <= 0:
    raise ValueError("ticks must be > 0")
  print(json.dumps(compare(ticks=args.ticks, seed=args.seed), separators=(",", ":"), sort_keys=True))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
