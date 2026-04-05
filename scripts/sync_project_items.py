#!/usr/bin/env python3
import json
import subprocess
import sys


def run(*args):
  return subprocess.run(args, capture_output=True, text=True, check=False)


def main():
  if len(sys.argv) != 3:
    print("usage: sync_project_items.py <owner> <project_number>")
    return 1
  owner = sys.argv[1]
  project_number = sys.argv[2]

  issue_list = run("gh", "issue", "list", "--limit", "200", "--json", "url")
  if issue_list.returncode != 0:
    print(issue_list.stderr.strip())
    return 1
  issues = json.loads(issue_list.stdout)

  added = 0
  failed = 0
  for item in issues:
    url = item.get("url", "")
    if not url:
      continue
    add = run("gh", "project", "item-add", project_number, "--owner", owner, "--url", url)
    if add.returncode == 0:
      added += 1
    else:
      failed += 1
      print(f"FAIL {url} :: {add.stderr.strip()}")

  print(f"added={added} failed={failed}")
  return 0 if failed == 0 else 1


if __name__ == "__main__":
  raise SystemExit(main())
