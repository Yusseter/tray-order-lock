"""Exercise the production canonical append function with simulated storage."""

from pathlib import Path
import shutil
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "tray-order-lock.wh.cpp").read_text(encoding="utf-8")
start = source.index("bool AppendNewCanonicalKeyAtEnd(")
end = source.index("void HandleNewIcon(", start)

code = r'''
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <type_traits>
#include <vector>
std::mutex g_canonicalMutex;
std::vector<std::wstring> g_canonicalOrder;
bool storageOk=true;
bool PersistCanonicalOrderLocked() { return storageOk; }
bool ContainsCanonicalKeyLocked(const std::wstring& key) {
    return std::find(g_canonicalOrder.begin(),g_canonicalOrder.end(),key)!=g_canonicalOrder.end();
}
struct LiveOverflowEntry { std::wstring logicalKey; bool uniqueLogical=true; };
struct LiveOverflowSnapshot { bool valid=true, targetFound=true; unsigned targetIndex=1; std::vector<LiveOverflowEntry> entries; };
struct LogicalSnapshotEntry { std::uint64_t identity; std::wstring key; bool unique=true; };
struct UIOrderSnapshot { bool valid=true; };
UIOrderSnapshot CaptureUIOrderSnapshot() { return {}; }
std::vector<LogicalSnapshotEntry> BuildLogicalSnapshot(const UIOrderSnapshot&) {
    return {{1,L"a",true},{2,L"target",true},{3,L"b",true}};
}
''' + source[start:end] + r'''
template<typename Function>
bool append(Function function, const std::wstring& key,
            const std::vector<std::wstring>& expected, bool* persisted) {
    if constexpr (std::is_invocable_r_v<bool, Function, const std::wstring&,
                                        const std::vector<std::wstring>&, bool*>) {
        return function(key, expected, persisted);
    } else if constexpr (std::is_invocable_r_v<bool, Function, const std::wstring&,
                                               bool*, const std::vector<std::wstring>&>) {
        return function(key, persisted, expected);
    } else {
        return function(key, persisted);
    }
}
bool check(bool condition, const char* name) {
    if (!condition) std::cerr << "FAIL: " << name << '\n';
    return condition;
}
int main() {
    bool failed=false, persisted=false;
    const std::vector<std::wstring> expected={L"a"};
    g_canonicalOrder={L"a",L"other"}; storageOk=true;
    append(&AppendNewCanonicalKeyAtEnd,L"target",expected,&persisted);
    if (!check(g_canonicalOrder==std::vector<std::wstring>{L"a",L"other"},
               "a changed canonical snapshot must not adopt the new key")) failed=true;
    g_canonicalOrder=expected; storageOk=false; persisted=true;
    append(&AppendNewCanonicalKeyAtEnd,L"target",expected,&persisted);
    if (!check(g_canonicalOrder==expected && !persisted,
               "failed persistence must roll canonical order back")) failed=true;
    g_canonicalOrder=expected; storageOk=true; persisted=false;
    append(&AppendNewCanonicalKeyAtEnd,L"target",expected,&persisted);
    if (!check(g_canonicalOrder==std::vector<std::wstring>{L"a",L"target"} && persisted,
               "matching snapshot and successful persistence append the new key")) failed=true;
    const std::vector<std::wstring> before={L"a",L"b"};
    const LiveOverflowSnapshot overflow={true,true,1,{{L"a",true},{L"target",true},{L"b",true}}};
    for (int kind=0; kind<2; ++kind) {
        auto adopt = [&]() { return kind==0
            ? AdoptNewIconAtWindowsDefault(L"target",before,overflow,&persisted)
            : AdoptNewIconFromUiOrder(L"target",2,before,&persisted); };
        g_canonicalOrder={L"a",L"b",L"other"}; storageOk=true; persisted=false;
        adopt();
        if (!check(g_canonicalOrder==std::vector<std::wstring>{L"a",L"b",L"other"},
                   kind==0 ? "windows-default stale snapshot must not mutate" : "UI-order stale snapshot must not mutate")) failed=true;
        g_canonicalOrder=before; storageOk=false; persisted=true;
        adopt();
        if (!check(g_canonicalOrder==before && !persisted,
                   kind==0 ? "windows-default failed persistence rolls back" : "UI-order failed persistence rolls back")) failed=true;
        g_canonicalOrder=before; storageOk=true; persisted=false;
        adopt();
        if (!check(g_canonicalOrder==std::vector<std::wstring>{L"a",L"target",L"b"} && persisted,
                   kind==0 ? "windows-default adopts between neighbours" : "UI-order adopts between neighbours")) failed=true;
    }
    if (failed) return 1;
    std::cout << "PASS: canonical append consistency\n";
}
'''

compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("A C++17 compiler is required on PATH")
folder = Path(tempfile.gettempdir()) / "tray-order-lock-continuity-test"
folder.mkdir(exist_ok=True)
cpp = folder / "canonical_append_test.cpp"
exe = folder / "canonical_append_test.exe"
cpp.write_text(code, encoding="utf-8")
subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
