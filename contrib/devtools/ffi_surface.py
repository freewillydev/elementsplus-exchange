#!/usr/bin/env python3
"""Inventory static native FFI use sites, not runtime invocations or reachability."""
import collections
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "301acc64be91d9fce1282d1af7bb673a397b6df2"
LEXICAL = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True)


def code_only(text):
    return LEXICAL.sub(lambda match: re.sub(r"[^\n]", " ", match[0]), text)


def category(path):
    if "/test/" in path or "/bench/" in path or path.endswith("_tests.cpp"):
        return "test_or_benchmark"
    return "tool" if path.startswith("contrib/") else "production"


def inventory():
    paths = sorted({p for p in git("ls-files", "-c", "-o", "--exclude-standard", "-z").split("\0")
                    if p and (ROOT / p).is_file()})
    baseline = set(git("ls-tree", "-r", "--name-only", BASELINE).splitlines())
    bindings = {name: domain for domain, name in re.findall(
        r'Binding<(elements_hs_\w+_api_v[12]),[^\n]+>\s+(elements_hs_\w+)\{\};',
        (ROOT / "src/haskell/domain_abi.h").read_text())}
    exports, sites, includes, added = [], [], [], []
    for path in paths:
        if path.endswith(".cpp") and path not in baseline:
            added.append({"path": path, "category": category(path)})
        if path.startswith("src/haskell/") and path.endswith(".hs") and "/test/" not in path:
            exports.extend(re.findall(r'foreign export ccall\s+"?(elements_hs_\w+)"?', (ROOT / path).read_text()))
        if not path.startswith("src/") or Path(path).suffix not in (".cpp", ".h", ".c", ".mm"):
            continue
        if category(path) != "production" or path == "src/haskell/domain_abi.h":
            continue
        text = (ROOT / path).read_text()
        if re.search(r'#include <haskell/(?:bridge.h|simplicity_ffi.h|domain_abi.h)>', text):
            includes.append(path)
        source = code_only(text)
        for match in re.finditer(r'\belements_hs_\w+\b', source):
            if match[0] in bindings:
                sites.append({"path": path, "line": source.count("\n", 0, match.start()) + 1,
                              "binding": match[0], "domain": bindings[match[0]],
                              "direct_syntax": bool(re.match(r'\s*\(', source[match.end():]))})
    # These are direct call expressions; the Utreexo forward declaration is excluded.
    other = []
    for path, name in [("src/mainchainrpc.cpp", "elements_hs_grpc_v1"),
                       ("src/node/blockstorage.cpp", "elements_hs_utreexo_v1")]:
        source = code_only((ROOT / path).read_text())
        for match in re.finditer(r'=\s*(' + name + r')\s*\(', source):
            other.append({"binding": name, "path": path, "line": source.count("\n", 0, match.start()) + 1})
    used = {site["binding"] for site in sites}
    return {
        "scope": "Static production binding/entry use sites, excluding declarations, tests and tools; not dynamic calls.",
        "baseline": BASELINE, "haskell_export_count": len(exports), "haskell_exports": sorted(exports),
        "registered_domain_operations": len(bindings), "used_production_bindings": len(used),
        "domain_use_sites": len(sites), "other_entry_use_sites": other,
        "total_production_entry_use_sites": len(sites) + len(other),
        "direct_domain_call_expressions": sum(site["direct_syntax"] for site in sites),
        "sites_by_domain": dict(sorted(collections.Counter(site["domain"] for site in sites).items())),
        "sites_by_file": dict(collections.Counter(site["path"] for site in sites)),
        "bindings_without_production_uses": sorted(set(bindings) - used),
        "production_files_including_bridge_headers": includes,
        "baseline_added_cpp_counts": dict(collections.Counter(item["category"] for item in added)),
        "baseline_added_cpp": added, "domain_sites": sites,
    }


if __name__ == "__main__":
    print(json.dumps(inventory(), indent=2))
