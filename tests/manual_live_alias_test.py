"""Exercise the production predicate that protects simultaneous live icons.

Run with Python 3 and a C++17 compiler available on PATH.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "tray-order-lock.wh.cpp").read_text(encoding="utf-8")


def section(start, end):
    return source[source.index(start) : source.index(end, source.index(start))]


helper_name = "bool HasSimultaneousContinuityAlias("
if helper_name in source:
    start = source.index(helper_name)
    opening = source.index("{", start)
    depth = 1
    closing = opening + 1
    while depth:
        depth += (source[closing] == "{") - (source[closing] == "}")
        closing += 1
    helper = source[start:closing]
else:
    # Before the guard exists, model the old behavior: no simultaneous alias is detected.
    helper = "bool HasSimultaneousContinuityAlias(const ContinuityGroupAnalysis&, const LiveOverflowSnapshot&, std::uint64_t) { return false; }"

duplicate_name = "bool HasDuplicateLiveIdentity("
if duplicate_name in source:
    start = source.index(duplicate_name)
    opening = source.index("{", start)
    depth = 1
    closing = opening + 1
    while depth:
        depth += (source[closing] == "{") - (source[closing] == "}")
        closing += 1
    duplicate_helper = source[start:closing]
else:
    # Before this guard exists, model the old behavior: duplicate identities are not detected.
    duplicate_helper = "bool HasDuplicateLiveIdentity(const LiveOverflowSnapshot&, std::uint64_t) { return false; }"

code = r'''
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
using HRESULT = long;
constexpr HRESULT E_FAIL = -1;
''' + section("struct LiveOverflowEntry {", "using NotificationAreaIcon2_Constructor_t =") + section(
    "struct ContinuityGroupAnalysis {", "bool FindGuidContinuityPredecessorFromRegistry("
) + helper + duplicate_helper + r'''
bool check(bool condition, const char* name) {
    if (!condition) std::cerr << "FAIL: " << name << '\n';
    return condition;
}
int main() {
    ContinuityGroupAnalysis group;
    group.identities = {100, 200, 0};
    group.keys = {L"target", L"old"};
    LiveOverflowSnapshot live;
    live.valid = true;
    live.entries = {{100, L"target", true, true}, {200, L"old", true, true}};
    if (!check(HasSimultaneousContinuityAlias(group, live, 100), "a different mapped group member is active")) return 1;
    live.entries = {{100, L"target", true, true}, {300, L"old", true, true}};
    if (!check(HasSimultaneousContinuityAlias(group, live, 100), "a live predecessor key is detected without its old identity")) return 1;
    live.entries = {{100, L"target", true, true}, {100, L"target", true, true}};
    if (!check(!HasSimultaneousContinuityAlias(group, live, 100), "repeated target identity is not another alias")) return 1;
    live.entries = {{100, L"target", true, true}, {300, L"unrelated", true, true}};
    if (!check(!HasSimultaneousContinuityAlias(group, live, 100), "unrelated live identities are not aliases")) return 1;
    live.entries = {{100, L"target", true, true}, {200, L"old", false, false}};
    if (!check(!HasSimultaneousContinuityAlias(group, live, 100), "an unmapped entry is not a mapped live alias")) return 1;
    live.entries = {{100, L"target", true, true}, {100, L"target", true, true}};
    if (!check(HasDuplicateLiveIdentity(live, 100), "two mapped entries of the target identity are duplicates")) return 1;
    live.entries = {{100, L"target", true, true}, {200, L"other", true, true}};
    if (!check(!HasDuplicateLiveIdentity(live, 100), "a different identity does not duplicate the target")) return 1;
    live.entries = {{100, L"target", true, true}, {100, L"target", false, false}};
    if (!check(!HasDuplicateLiveIdentity(live, 100), "an unmapped entry does not duplicate the target")) return 1;
    live.entries = {{200, L"other", true, true}};
    if (!check(!HasDuplicateLiveIdentity(live, 100), "no target entries do not duplicate the target")) return 1;
    std::cout << "PASS: simultaneous live alias and duplicate identity detection\n";
}
'''

compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("A C++17 compiler (g++ or clang++) is required on PATH")
folder = Path(tempfile.gettempdir()) / "tray-order-lock-continuity-test"
folder.mkdir(exist_ok=True)
cpp = folder / "manual_live_alias_test.cpp"
exe = folder / "manual_live_alias_test.exe"
cpp.write_text(code, encoding="utf-8")
subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
