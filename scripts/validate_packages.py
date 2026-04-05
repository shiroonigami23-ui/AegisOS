#!/usr/bin/env python3
import os
import sys
import json


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CORE_DIR = os.path.join(ROOT, "packages", "core")
PROFILES_DIR = os.path.join(ROOT, "packages", "profiles")


def validate_signature_placeholders(data, path):
  required = ["signature_format", "signature_key_id", "signature_digest", "signature_value"]
  missing = [k for k in required if k not in data]
  if missing:
    raise ValueError(f"{path}: missing signature keys: {', '.join(missing)}")
  if data["signature_format"] != "placeholder-v1":
    raise ValueError(f"{path}: unsupported signature_format {data['signature_format']}")
  if not str(data["signature_key_id"]).startswith("aegis-placeholder-"):
    raise ValueError(f"{path}: signature_key_id must start with aegis-placeholder-")
  if not str(data["signature_digest"]).startswith("sha256:"):
    raise ValueError(f"{path}: signature_digest must start with sha256:")
  if data["signature_value"] != "UNSIGNED_PLACEHOLDER":
    raise ValueError(f"{path}: unsupported signature_value {data['signature_value']}")


def parse_simple_yaml(path):
  data = {}
  current_list_key = None
  with open(path, "r", encoding="utf-8") as f:
    for raw in f:
      line = raw.rstrip()
      if not line or line.lstrip().startswith("#"):
        continue
      stripped = line.lstrip()
      if stripped.startswith("- "):
        if current_list_key is None:
          raise ValueError(f"{path}: list item without parent key")
        data.setdefault(current_list_key, []).append(stripped[2:].strip())
        continue
      if ":" not in line:
        raise ValueError(f"{path}: invalid line: {line}")
      key, value = line.split(":", 1)
      key = key.strip()
      value = value.strip()
      if value == "":
        current_list_key = key
        data.setdefault(key, [])
      elif value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if inner == "":
          data[key] = []
        else:
          data[key] = [item.strip() for item in inner.split(",") if item.strip()]
        current_list_key = None
      else:
        data[key] = value
        current_list_key = None
  return data


def validate_core_manifest(path):
  req = ["schema_version", "name", "version", "summary", "license", "source", "dependencies"]
  data = parse_simple_yaml(path)
  missing = [k for k in req if k not in data]
  if missing:
    raise ValueError(f"{path}: missing keys: {', '.join(missing)}")
  if not isinstance(data["dependencies"], list):
    raise ValueError(f"{path}: dependencies must be a list")
  if str(data["schema_version"]) != "1":
    raise ValueError(f"{path}: unsupported schema_version {data['schema_version']}")
  if not data["name"].startswith("aegis-"):
    raise ValueError(f"{path}: package name must start with aegis-")
  if data["license"] != "Apache-2.0":
    raise ValueError(f"{path}: unsupported license {data['license']}")
  validate_signature_placeholders(data, path)
  return data


def validate_profile_manifest(path, known_packages):
  req = ["schema_version", "profile", "description", "packages"]
  data = parse_simple_yaml(path)
  missing = [k for k in req if k not in data]
  if missing:
    raise ValueError(f"{path}: missing keys: {', '.join(missing)}")
  if not isinstance(data["packages"], list):
    raise ValueError(f"{path}: packages must be a list")
  if str(data["schema_version"]) != "1":
    raise ValueError(f"{path}: unsupported schema_version {data['schema_version']}")
  validate_signature_placeholders(data, path)
  unknown = [p for p in data["packages"] if p not in known_packages]
  if unknown:
    raise ValueError(f"{path}: unknown packages: {', '.join(unknown)}")


def collect_files(directory):
  if not os.path.isdir(directory):
    return []
  return sorted(
      [os.path.join(directory, name) for name in os.listdir(directory) if name.endswith(".yaml")]
  )


def main():
  core_files = collect_files(CORE_DIR)
  profile_files = collect_files(PROFILES_DIR)
  if not core_files:
    print("No core package manifests found.")
    return 1
  manifests = []
  known = set()
  for path in core_files:
    manifest = validate_core_manifest(path)
    manifests.append(manifest)
    known.add(manifest["name"])
  dep_graph = {}
  for manifest in manifests:
    dep_graph[manifest["name"]] = list(manifest["dependencies"])
  for pkg, deps in dep_graph.items():
    for dep in deps:
      if dep not in known:
        raise ValueError(f"{pkg}: unknown dependency {dep}")
  visited = set()
  active = set()

  def dfs(node):
    if node in active:
      raise ValueError(f"dependency cycle detected at {node}")
    if node in visited:
      return
    active.add(node)
    for nxt in dep_graph.get(node, []):
      dfs(nxt)
    active.remove(node)
    visited.add(node)

  for name in dep_graph:
    dfs(name)
  for path in profile_files:
    validate_profile_manifest(path, known)
  graph_dir = os.path.join(ROOT, "packages")
  json_path = os.path.join(graph_dir, "dependency-graph.json")
  dot_path = os.path.join(graph_dir, "dependency-graph.dot")
  graph_json = {
      "packages": [{"name": m["name"], "dependencies": list(m["dependencies"])} for m in manifests]
  }
  with open(json_path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(graph_json, f, indent=2)
    f.write("\n")
  with open(dot_path, "w", encoding="utf-8", newline="\n") as f:
    f.write("digraph aegis_packages {\n")
    for pkg, deps in dep_graph.items():
      if not deps:
        f.write(f"  \"{pkg}\";\n")
      for dep in deps:
        f.write(f"  \"{pkg}\" -> \"{dep}\";\n")
    f.write("}\n")
  print(f"Validated {len(core_files)} core manifests and {len(profile_files)} profiles.")
  print(f"Wrote dependency graph: {json_path}")
  print(f"Wrote dependency graph: {dot_path}")
  return 0


if __name__ == "__main__":
  try:
    sys.exit(main())
  except ValueError as exc:
    print(f"Validation failed: {exc}")
    sys.exit(1)
