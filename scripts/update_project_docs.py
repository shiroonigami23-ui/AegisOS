#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from urllib import request
from urllib.error import URLError, HTTPError


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXPLAIN_PATH = os.path.join(ROOT, "EXPLAIN.md")
CHANGELOG_PATH = os.path.join(ROOT, "CHANGELOG.md")
HEATMAP_WINDOWS = {
    "weekly": 7,
    "monthly": 30,
}


def run_git(*args):
  cmd = ["git"] + list(args)
  result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
  if result.returncode != 0:
    return ""
  return result.stdout.strip()


def get_recent_commits(limit=12):
  raw = run_git("log", f"-n{limit}", "--pretty=format:%h|%ad|%s", "--date=short")
  if not raw:
    return []
  commits = []
  for line in raw.splitlines():
    parts = line.split("|", 2)
    if len(parts) != 3:
      continue
    commits.append({"hash": parts[0], "date": parts[1], "subject": parts[2]})
  return commits


def detect_component_from_path(path):
  p = path.replace("\\", "/")
  if p.startswith("kernel/"):
    return "kernel"
  if p.startswith("userland/"):
    return "userland"
  if p.startswith("packages/"):
    return "packages"
  if p.startswith("docs/") or p == "README.md" or p == "EXPLAIN.md" or p == "CHANGELOG.md":
    return "docs"
  if p.startswith(".github/workflows/"):
    return "workflows"
  if p.startswith("tests/"):
    return "tests"
  if p.startswith("tools/"):
    return "tools"
  if p.startswith("platform/"):
    return "platform"
  if p.startswith("scripts/"):
    return "scripts"
  return "other"


def get_commit_component_counts(days=7):
  raw = run_git("log", "--since", f"{days} days ago", "--name-only", "--pretty=format:")
  counts = {
      "kernel": 0,
      "userland": 0,
      "packages": 0,
      "docs": 0,
      "workflows": 0,
      "tests": 0,
      "tools": 0,
      "platform": 0,
      "scripts": 0,
      "other": 0,
  }
  if not raw:
    return counts
  for line in raw.splitlines():
    path = line.strip()
    if not path:
      continue
    comp = detect_component_from_path(path)
    counts[comp] += 1
  return counts


def get_open_issues(limit=12):
  repo = os.getenv("GITHUB_REPOSITORY", "")
  token = os.getenv("GITHUB_TOKEN", "")
  if not repo or not token:
    gh = subprocess.run(
        ["gh", "issue", "list", "--limit", str(limit), "--json", "number,title,labels"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if gh.returncode != 0 or not gh.stdout.strip():
      return []
    try:
      payload = json.loads(gh.stdout)
    except json.JSONDecodeError:
      return []
    items = []
    for item in payload:
      items.append(
          {
              "number": item.get("number"),
              "title": item.get("title", ""),
              "labels": [lbl.get("name", "") for lbl in item.get("labels", [])],
          }
      )
    return items

  url = f"https://api.github.com/repos/{repo}/issues?state=open&per_page={limit}"
  req = request.Request(
      url,
      headers={
          "Accept": "application/vnd.github+json",
          "Authorization": f"Bearer {token}",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "aegisos-auto-docs",
      },
  )
  try:
    with request.urlopen(req, timeout=15) as resp:
      payload = json.loads(resp.read().decode("utf-8"))
  except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
    return []

  items = []
  for item in payload:
    if "pull_request" in item:
      continue
    items.append(
        {
            "number": item.get("number"),
            "title": item.get("title", ""),
            "labels": [lbl.get("name", "") for lbl in item.get("labels", [])],
        }
    )
  return items


def get_issue_component_counts(issues):
  counts = {
      "security": 0,
      "kernel": 0,
      "packages": 0,
      "docs": 0,
      "other": 0,
  }
  for issue in issues:
    title = issue.get("title", "").lower()
    labels = [x.lower() for x in issue.get("labels", [])]
    if "security" in labels:
      counts["security"] += 1
    elif "kernel" in labels:
      counts["kernel"] += 1
    elif "package" in title or "packages" in title:
      counts["packages"] += 1
    elif "docs" in title or "doc" in title:
      counts["docs"] += 1
    else:
      counts["other"] += 1
  return counts


def has_label(issue, prefix):
  prefix = prefix.lower()
  for lbl in issue.get("labels", []):
    if lbl.lower().startswith(prefix):
      return True
  return False


def group_issues(issues):
  grouped = {
      "priority_p0": [],
      "priority_p1": [],
      "security": [],
      "kernel": [],
      "good_first_task": [],
      "other": [],
  }
  seen_numbers = set()
  for issue in issues:
    if has_label(issue, "priority-p0"):
      grouped["priority_p0"].append(issue)
      seen_numbers.add(issue["number"])
      continue
    if has_label(issue, "priority-p1"):
      grouped["priority_p1"].append(issue)
      seen_numbers.add(issue["number"])
      continue
  for issue in issues:
    if issue["number"] in seen_numbers:
      continue
    labels = [x.lower() for x in issue.get("labels", [])]
    if "security" in labels:
      grouped["security"].append(issue)
    elif "kernel" in labels:
      grouped["kernel"].append(issue)
    elif "good-first-task" in labels:
      grouped["good_first_task"].append(issue)
    else:
      grouped["other"].append(issue)
  return grouped


def render_issue_lines(issues):
  lines = []
  for issue in issues:
    labels = ", ".join([x for x in issue.get("labels", []) if x])
    if labels:
      lines.append(f"- #{issue['number']} {issue['title']} ({labels})")
    else:
      lines.append(f"- #{issue['number']} {issue['title']}")
  if not lines:
    lines = ["- none"]
  return lines


def render_explain(now_iso, commits, issues, commit_components, issue_components, heatmap_window_label):
  grouped = group_issues(issues)

  recent_lines = [f"- `{c['hash']}` ({c['date']}): {c['subject']}" for c in commits]
  if not recent_lines:
    recent_lines = ["- No commits detected yet."]

  return f"""# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: {now_iso}

## What AegisOS Is Building

AegisOS is a security-first operating system designed to combine the strongest traits of major platforms in one coherent product:

- iOS: secure defaults, trusted update path, cohesive platform behavior.
- Linux: customization, openness, privacy-first control.
- Windows: practical compatibility strategy for apps and workflows.
- macOS: polish, consistency, and efficiency.
- Android: broad device profile flexibility.

## How We Build It

We implement in vertical slices:

1. Core kernel and scheduler primitives.
2. Security controls (capabilities, sandbox policies, enforcement engine).
3. Packaging and update integrity.
4. UX and compatibility layers.
5. Observability, reliability, and contributor scale-out.

## Current Technical Baseline

- Kernel simulation target with round-robin scheduler skeleton and tests.
- Capability token lifecycle (`issue`, `revoke`, authorization checks).
- Sandbox policy schema validator and test suite.
- CI/docs workflows and contributor-ready GitHub templates.

## Live Backlog Snapshot

### Priority P0
{os.linesep.join(render_issue_lines(grouped["priority_p0"]))}

### Priority P1
{os.linesep.join(render_issue_lines(grouped["priority_p1"]))}

### Security
{os.linesep.join(render_issue_lines(grouped["security"]))}

### Kernel
{os.linesep.join(render_issue_lines(grouped["kernel"]))}

### Good First Task
{os.linesep.join(render_issue_lines(grouped["good_first_task"]))}

### Other
{os.linesep.join(render_issue_lines(grouped["other"]))}

## Component Activity Heatmap

Recent commit touches in `{heatmap_window_label}` window (higher means more active recently):

- kernel: {commit_components["kernel"]}
- userland: {commit_components["userland"]}
- packages: {commit_components["packages"]}
- docs: {commit_components["docs"]}
- workflows: {commit_components["workflows"]}
- tests: {commit_components["tests"]}
- tools: {commit_components["tools"]}
- platform: {commit_components["platform"]}
- scripts: {commit_components["scripts"]}
- other: {commit_components["other"]}

Open issue pressure by component signal:

- security: {issue_components["security"]}
- kernel: {issue_components["kernel"]}
- packages: {issue_components["packages"]}
- docs: {issue_components["docs"]}
- other: {issue_components["other"]}

## Recent Engineering Changes

{os.linesep.join(recent_lines)}
"""


def render_changelog(now_iso, commits):
  recent_lines = [f"- {c['date']} `{c['hash']}` {c['subject']}" for c in commits]
  if not recent_lines:
    recent_lines = ["- No entries yet."]
  return f"""# CHANGELOG

Auto-updated by workflow.
Last generated: {now_iso}

## Unreleased

{os.linesep.join(recent_lines)}
"""


def write_file(path, content):
  existing = ""
  if os.path.exists(path):
    with open(path, "r", encoding="utf-8") as f:
      existing = f.read()
  if existing == content:
    return False
  with open(path, "w", encoding="utf-8", newline="\n") as f:
    f.write(content)
  return True


def parse_args():
  parser = argparse.ArgumentParser(description="Update EXPLAIN.md and CHANGELOG.md from repo state.")
  parser.add_argument(
      "--heatmap-window",
      choices=["weekly", "monthly", "custom"],
      default="weekly",
      help="Time window preset used for component activity heatmap.",
  )
  parser.add_argument(
      "--heatmap-days",
      type=int,
      default=0,
      help="Custom day window when --heatmap-window=custom.",
  )
  return parser.parse_args()


def resolve_heatmap_days(args):
  if args.heatmap_window in HEATMAP_WINDOWS:
    return HEATMAP_WINDOWS[args.heatmap_window], args.heatmap_window
  if args.heatmap_days <= 0:
    raise SystemExit("--heatmap-days must be > 0 when --heatmap-window=custom")
  return args.heatmap_days, f"custom-{args.heatmap_days}d"


def main():
  args = parse_args()
  heatmap_days, heatmap_window_label = resolve_heatmap_days(args)
  now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
  commits = get_recent_commits(limit=15)
  issues = get_open_issues(limit=20)
  commit_components = get_commit_component_counts(days=heatmap_days)
  issue_components = get_issue_component_counts(issues)

  explain = render_explain(
      now_iso, commits, issues, commit_components, issue_components, heatmap_window_label
  )
  changelog = render_changelog(now_iso, commits)

  changed = False
  changed |= write_file(EXPLAIN_PATH, explain)
  changed |= write_file(CHANGELOG_PATH, changelog)

  print("updated" if changed else "no-change")


if __name__ == "__main__":
  main()
