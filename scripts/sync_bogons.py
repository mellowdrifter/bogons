#!/usr/bin/env python3
"""
sync_bogons.py - Universal synchronization, parity checker, and version bumper
for the bogons library across all 6 language implementations:
- Go (github.com/mellowdrifter/bogons)
- Python (github.com/mellowdrifter/python-bogons)
- Rust (github.com/mellowdrifter/rust-bogons)
- C (github.com/mellowdrifter/c-bogons)
- C++ (github.com/mellowdrifter/cpp-bogons)
- TypeScript / JS (github.com/mellowdrifter/ts-bogons)
"""

import sys
import os
import json
import re
import subprocess
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

REPOS = {
    "go": BASE_DIR / "bogons",
    "python": BASE_DIR / "python-bogons",
    "rust": BASE_DIR / "rust-bogons",
    "c": BASE_DIR / "c-bogons",
    "cpp": BASE_DIR / "cpp-bogons",
    "ts": BASE_DIR / "ts-bogons",
}

NODE_BIN = "/home/mellowd/.antigravity-ide-server/bin/2.5.5-ecfbad74d93962fc8ca485d93ab9b4f3d4cb6cf8/node"
if not os.path.exists(NODE_BIN):
    NODE_BIN = "node"

def load_canonical_data():
    json_path = REPOS["go"] / "data" / "bogons.json"
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

def check_versions(canonical_ver):
    target_parts = canonical_ver.split(".")
    target_major, target_minor = target_parts[0], target_parts[1]
    print(f"=== Checking Version Parity (Target: {canonical_ver}, Major.Minor lockstep: {target_major}.{target_minor}.x) ===")
    all_match = True

    def eval_ver(name, ver_str):
        nonlocal all_match
        if ver_str == "UNKNOWN":
            print(f"  [{name}] UNKNOWN -> FAIL")
            all_match = False
            return
        parts = ver_str.split(".")
        if len(parts) < 2:
            print(f"  [{name}] Invalid version '{ver_str}' -> FAIL")
            all_match = False
            return
        major_ok = (parts[0] == target_major)
        minor_ok = (parts[1] == target_minor)
        if major_ok and minor_ok:
            if len(parts) >= 3 and parts[2] != target_parts[2]:
                print(f"  [{name}] {ver_str} -> PASS (Language patch {parts[2]} != {target_parts[2]})")
            else:
                print(f"  [{name}] {ver_str} -> PASS (Exact match)")
        else:
            print(f"  [{name}] {ver_str} -> FAIL (Major/Minor mismatch with {target_major}.{target_minor}.x)")
            all_match = False

    # 1. Rust Cargo.toml
    cargo_path = REPOS["rust"] / "Cargo.toml"
    if cargo_path.exists():
        content = cargo_path.read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
        eval_ver("Rust", m.group(1) if m else "UNKNOWN")

    # 2. Python pyproject.toml
    pyproject_path = REPOS["python"] / "pyproject.toml"
    if pyproject_path.exists():
        content = pyproject_path.read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
        eval_ver("Python", m.group(1) if m else "UNKNOWN")

    # 3. C include/bogons.h
    c_header = REPOS["c"] / "include" / "bogons.h"
    if c_header.exists():
        content = c_header.read_text()
        m = re.search(r'#define\s+BOGONS_VERSION\s+"([^"]+)"', content)
        eval_ver("C", m.group(1) if m else "UNKNOWN")

    # 4. C++ include/bogons/bogons.hpp
    cpp_header = REPOS["cpp"] / "include" / "bogons" / "bogons.hpp"
    if cpp_header.exists():
        content = cpp_header.read_text()
        m = re.search(r'VERSION\s*=\s*"([^"]+)"', content)
        eval_ver("C++", m.group(1) if m else "UNKNOWN")

    # 5. TypeScript package.json
    ts_pkg = REPOS["ts"] / "package.json"
    if ts_pkg.exists():
        data = json.loads(ts_pkg.read_text())
        eval_ver("TypeScript", data.get("version", "UNKNOWN"))

    return all_match

def run_tests():
    print("\n=== Running Test Suites Across All Implementations ===")
    results = {}

    # Go
    try:
        res = subprocess.run(["go", "test", "./..."], cwd=REPOS["go"], capture_output=True, text=True, check=True)
        results["Go"] = True
        print("  ✓ Go: PASS")
    except Exception as e:
        results["Go"] = False
        print(f"  ✗ Go: FAILED\n{getattr(e, 'stderr', str(e))}")

    # Python
    try:
        res = subprocess.run([sys.executable, "-m", "unittest", "bogons_test.py"], cwd=REPOS["python"], capture_output=True, text=True, check=True)
        results["Python"] = True
        print("  ✓ Python: PASS")
    except Exception as e:
        results["Python"] = False
        print(f"  ✗ Python: FAILED\n{getattr(e, 'stderr', str(e))}")

    # Rust
    try:
        res = subprocess.run(["cargo", "test"], cwd=REPOS["rust"], capture_output=True, text=True, check=True)
        results["Rust"] = True
        print("  ✓ Rust: PASS")
    except Exception as e:
        results["Rust"] = False
        print(f"  ✗ Rust: FAILED\n{getattr(e, 'stderr', str(e))}")

    # C
    try:
        res = subprocess.run(["make", "test"], cwd=REPOS["c"], capture_output=True, text=True, check=True)
        results["C"] = True
        print("  ✓ C: PASS")
    except Exception as e:
        results["C"] = False
        print(f"  ✗ C: FAILED\n{getattr(e, 'stderr', str(e))}")

    # C++
    try:
        res = subprocess.run(["make", "test"], cwd=REPOS["cpp"], capture_output=True, text=True, check=True)
        results["C++"] = True
        print("  ✓ C++: PASS")
    except Exception as e:
        results["C++"] = False
        print(f"  ✗ C++: FAILED\n{getattr(e, 'stderr', str(e))}")

    # TypeScript / Node
    try:
        res = subprocess.run([NODE_BIN, "--test", "test/test_bogons.js"], cwd=REPOS["ts"], capture_output=True, text=True, check=True)
        results["TypeScript"] = True
        print("  ✓ TypeScript: PASS")
    except Exception as e:
        results["TypeScript"] = False
        print(f"  ✗ TypeScript: FAILED\n{getattr(e, 'stderr', str(e))}")

    return all(results.values())

def bump_version(new_ver):
    print(f"\n=== Bumping All 6 Implementations to v{new_ver} ===")
    parts = new_ver.split(".")
    major, minor, patch = parts[0], parts[1], parts[2]

    # 1. data/bogons.json
    json_path = REPOS["go"] / "data" / "bogons.json"
    data = json.loads(json_path.read_text())
    data["version"] = new_ver
    json_path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"  Updated {json_path}")

    # 2. Rust Cargo.toml & src/lib.rs
    cargo_path = REPOS["rust"] / "Cargo.toml"
    c_text = re.sub(r'^version\s*=\s*"[^"]+"', f'version = "{new_ver}"', cargo_path.read_text(), flags=re.MULTILINE)
    cargo_path.write_text(c_text)
    lib_path = REPOS["rust"] / "src" / "lib.rs"
    l_text = re.sub(r'pub const VERSION: &str = "[^"]+";', f'pub const VERSION: &str = "{new_ver}";', lib_path.read_text())
    lib_path.write_text(l_text)
    print("  Updated Rust Cargo.toml & src/lib.rs")

    # 3. Python pyproject.toml & setup.py
    pyproject_path = REPOS["python"] / "pyproject.toml"
    p_text = re.sub(r'^version\s*=\s*"[^"]+"', f'version = "{new_ver}"', pyproject_path.read_text(), flags=re.MULTILINE)
    pyproject_path.write_text(p_text)
    setup_path = REPOS["python"] / "setup.py"
    s_text = re.sub(r'version="[^"]+"', f'version="{new_ver}"', setup_path.read_text())
    setup_path.write_text(s_text)
    print("  Updated Python pyproject.toml & setup.py")

    # 4. C include/bogons.h & Makefile
    c_header = REPOS["c"] / "include" / "bogons.h"
    ch_text = re.sub(r'#define BOGONS_VERSION "[^"]+"', f'#define BOGONS_VERSION "{new_ver}"', c_header.read_text())
    ch_text = re.sub(r'#define BOGONS_VERSION_MAJOR \d+', f'#define BOGONS_VERSION_MAJOR {major}', ch_text)
    ch_text = re.sub(r'#define BOGONS_VERSION_MINOR \d+', f'#define BOGONS_VERSION_MINOR {minor}', ch_text)
    ch_text = re.sub(r'#define BOGONS_VERSION_PATCH \d+', f'#define BOGONS_VERSION_PATCH {patch}', ch_text)
    c_header.write_text(ch_text)
    c_mk = REPOS["c"] / "Makefile"
    mk_text = re.sub(r'VERSION = [^\n]+', f'VERSION = {new_ver}', c_mk.read_text())
    c_mk.write_text(mk_text)
    print("  Updated C include/bogons.h & Makefile")

    # 5. C++ include/bogons/bogons.hpp & CMakeLists.txt
    cpp_header = REPOS["cpp"] / "include" / "bogons" / "bogons.hpp"
    cpp_text = re.sub(r'VERSION = "[^"]+"', f'VERSION = "{new_ver}"', cpp_header.read_text())
    cpp_header.write_text(cpp_text)
    cmake_path = REPOS["cpp"] / "CMakeLists.txt"
    cmake_text = re.sub(r'project\(bogons VERSION [^\s]+', f'project(bogons VERSION {new_ver}', cmake_path.read_text())
    cmake_path.write_text(cmake_text)
    print("  Updated C++ bogons.hpp & CMakeLists.txt")

    # 6. TypeScript package.json, dist/index.d.ts, src/index.js, dist/index.cjs
    ts_pkg = REPOS["ts"] / "package.json"
    ts_data = json.loads(ts_pkg.read_text())
    ts_data["version"] = new_ver
    ts_pkg.write_text(json.dumps(ts_data, indent=2) + "\n")
    ts_src = REPOS["ts"] / "src" / "index.js"
    ts_text = re.sub(r'export const VERSION = "[^"]+";', f'export const VERSION = "{new_ver}";', ts_src.read_text())
    ts_src.write_text(ts_text)
    (REPOS["ts"] / "dist" / "index.js").write_text(ts_text)
    ts_cjs = REPOS["ts"] / "dist" / "index.cjs"
    cjs_text = re.sub(r'const VERSION = "[^"]+";', f'const VERSION = "{new_ver}";', ts_cjs.read_text())
    ts_cjs.write_text(cjs_text)
    print("  Updated TypeScript package.json & dist files")

def print_release_cmds(ver):
    print(f"\n=== Release Commands for v{ver} ===")
    print("# 1. Commit and tag across all repos:")
    for name, p in REPOS.items():
        tag = f"v{ver}" if name != "python" else ver
        print(f"git -C {p} commit -am 'release: v{ver}' && git -C {p} tag -a {tag} -m 'Release {ver}' && git -C {p} push --follow-tags")
    print("\n# 2. Publish to registries:")
    print(f"  - Go:        curl https://proxy.golang.org/github.com/mellowdrifter/bogons/@v/v{ver}.info")
    print(f"  - Python:    (cd {REPOS['python']} && python3 -m build && twine upload dist/*)")
    print(f"  - Rust:      (cd {REPOS['rust']} && cargo publish)")
    print(f"  - npm:       (cd {REPOS['ts']} && npm publish)")

def main():
    parser = argparse.ArgumentParser(description="Multi-language bogons synchronization & release tool")
    parser.add_argument("--check", action="store_true", help="Verify version parity and run all test suites")
    parser.add_argument("--bump", type=str, help="Bump version across all 6 libraries")
    parser.add_argument("--release", action="store_true", help="Print registry release instructions")
    args = parser.parse_args()

    data = load_canonical_data()
    canonical_ver = data["version"]

    if args.bump:
        bump_version(args.bump)
        check_versions(args.bump)
        run_tests()
        print_release_cmds(args.bump)
        return

    if args.release:
        print_release_cmds(canonical_ver)
        return

    # Default is check
    ver_ok = check_versions(canonical_ver)
    tests_ok = run_tests()
    if ver_ok and tests_ok:
        print("\n🎉 ALL 6 IMPLEMENTATIONS ARE 100% IN LOCKSTEP AND PASSING!")
        sys.exit(0)
    else:
        print("\n⚠️ PARITY OR TEST FAILURE DETECTED!")
        sys.exit(1)

if __name__ == "__main__":
    main()
