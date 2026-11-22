"""Exercise canonical WindowsApps predecessor selection with simulated entries.

Run with Python 3 and a C++17 compiler available on PATH.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "tray-order-lock.wh.cpp").read_text(encoding="utf-8")


def section(start, end):
    return source[source.index(start) : source.index(end, source.index(start))]


code = r'''
#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
using DWORD = unsigned long;
#define TOR_LOG(...) ((void)0)
''' + section("std::wstring ToLower(", "bool StartsWithOrdinalIgnoreCase(") + section(
    "bool IsNumericDottedVersionCore(", "bool LooksLikeVersionDirectory("
) + section("int CompareVersionParts(", "bool ContainsText(") + r'''
std::wstring targetPath;
std::wstring MakeTrayEntrySubkey(std::uint64_t) { return L"fixture"; }
bool QueryDwordValue(const std::wstring&, const wchar_t*, DWORD* uid) { *uid=3; return true; }
std::wstring QueryStringValue(const std::wstring&, const wchar_t*) { return targetPath; }
''' + section("bool FindWindowsAppsUidCanonicalPredecessor(", "bool AnalyzeContinuityGroup(") + r'''
bool check(bool condition, const char* name) {
    if (!condition) std::cerr << "FAIL: " << name << '\n';
    return condition;
}
int main() {
    const std::wstring oldKey = LR"(uid:3|path:d:\windowsapps\claude_6.6395.0.0_x64__publisher\app\claude.exe)";
    const std::wstring duplicateVersion = LR"(uid:3|path:e:\windowsapps\claude_6.6395.0.0_x64__publisher\app\claude.exe)";
    targetPath = LR"(c:\program files\windowsapps\claude_6.28899.2.0_x64__publisher\app\claude.exe)";
    const std::wstring targetKey = L"uid:3|path:" + targetPath;
    std::wstring selected;
    bool ambiguous = true;
    if (!check(FindWindowsAppsUidCanonicalPredecessor(1, targetKey, {oldKey}, &selected, &ambiguous) && selected == oldKey && !ambiguous,
               "same package family and UID match across installation roots")) return 1;
    const std::wstring sameVersionOtherRoot = LR"(uid:3|path:d:\windowsapps\claude_6.28899.2.0_x64__publisher\app\claude.exe)";
    if (!check(FindWindowsAppsUidCanonicalPredecessor(1, targetKey, {sameVersionOtherRoot}, &selected, &ambiguous) && selected == sameVersionOtherRoot && !ambiguous,
               "the same package version matches across installation roots")) return 1;
    if (!check(!FindWindowsAppsUidCanonicalPredecessor(1, targetKey, {oldKey, duplicateVersion}, &selected, &ambiguous) && ambiguous,
               "multiple canonical keys for the closest version remain ambiguous")) return 1;
    if (!check(!FindWindowsAppsUidCanonicalPredecessor(1, targetKey, {}, &selected, &ambiguous) && !ambiguous,
               "a missing candidate is not ambiguous")) return 1;
    ambiguous = true;
    if (!check(!FindWindowsAppsUidCanonicalPredecessor(1, targetKey, {oldKey, targetKey}, &selected, &ambiguous) && !ambiguous,
               "a known target retains its established position")) return 1;
    std::cout << "PASS: canonical WindowsApps predecessor selection\n";
}
'''

compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("A C++17 compiler (g++ or clang++) is required on PATH")
folder = Path(tempfile.gettempdir()) / "tray-order-lock-continuity-test"
folder.mkdir(exist_ok=True)
cpp = folder / "continuity_predecessor_test.cpp"
exe = folder / "continuity_predecessor_test.exe"
cpp.write_text(code, encoding="utf-8")
subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
