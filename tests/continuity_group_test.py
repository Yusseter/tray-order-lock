"""Exercise real continuity-group selection using simulated registry entries."""

from pathlib import Path
import shutil
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "tray-order-lock.wh.cpp").read_text(encoding="utf-8")


def section(start, end):
    return source[source.index(start):source.index(end, source.index(start))]


code = r'''
#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
using BYTE = unsigned char;
using DWORD = unsigned long;
#define TOR_LOG(...) ((void)0)
struct Entry { DWORD uid; std::wstring path, tooltip; std::vector<BYTE> icon; };
std::map<std::wstring, Entry> entries;
''' + section("struct LogicalSnapshotEntry {", "struct LiveIdentityMapping {") + section(
    "std::wstring ToLower(", "bool StartsWithOrdinalIgnoreCase("
) + section("bool IsNumericDottedVersionCore(", "bool LooksLikeVersionDirectory(") + section(
    "int CompareVersionParts(", "bool ContainsText("
) + r'''
std::wstring MakeTrayEntrySubkey(std::uint64_t identity) { return std::to_wstring(identity); }
bool QueryIconGuid(const std::wstring&, std::wstring*) { return false; }
bool QueryDwordValue(const std::wstring& key, const wchar_t*, DWORD* uid) {
    auto it=entries.find(key); if (it == entries.end()) return false;
    *uid=it->second.uid; return true;
}
std::wstring QueryStringValue(const std::wstring& key, const wchar_t* name) {
    auto it=entries.find(key); if (it == entries.end()) return L"";
    return std::wstring(name) == L"ExecutablePath" ? it->second.path : it->second.tooltip;
}
bool QueryBinaryValue(const std::wstring& key, const wchar_t*, std::vector<BYTE>* value) {
    auto it=entries.find(key); if (it == entries.end()) return false;
    *value=it->second.icon; return !value->empty();
}
''' + section("std::wstring NormalizeContinuityTooltip(", "std::wstring BuildLogicalKey(") + section(
    "struct ContinuityGroupAnalysis {", "bool FindGuidContinuityPredecessorFromRegistry("
) + r'''
bool FindGuidContinuityPredecessorFromRegistry(
    const ContinuityIdentityMetadata&, const std::wstring&,
    const std::vector<std::wstring>&, std::uint64_t*, std::wstring*) { return false; }
''' + section("bool FindWindowsAppsUidCanonicalPredecessor(", "bool ContainsCanonicalKeyLocked(") + r'''
struct LiveIdentityMapping { void* implementation=nullptr; void* abi=nullptr; std::uint64_t windowsIdentity=0; };
struct LiveOverflowEntry { std::uint64_t windowsIdentity=0; std::wstring logicalKey; bool mapped=false; bool uniqueLogical=true; };
struct LiveOverflowSnapshot { bool valid=false, targetFound=false; unsigned size=0, mappedEntries=0; std::vector<LiveOverflowEntry> entries; };
LiveOverflowSnapshot liveFixture;
extern std::vector<std::wstring> g_canonicalOrder;
bool insertTargetOnCapture=false;
std::wstring concurrentTarget;
LiveOverflowSnapshot CaptureLiveOverflowSnapshot(void*) {
    if (insertTargetOnCapture) {
        g_canonicalOrder.push_back(concurrentTarget);
        insertTargetOnCapture=false;
    }
    return liveFixture;
}
struct UIOrderSnapshot { bool valid=true; };
std::vector<std::wstring> g_canonicalOrder;
std::vector<std::wstring>& canonicalFixture=g_canonicalOrder;
std::mutex g_canonicalMutex;
bool persistSuccess=true;
bool PersistCanonicalOrderLocked() { return persistSuccess; }
bool baselineSufficient=true;
bool HasSufficientTrustedLiveBaseline(unsigned) { return baselineSufficient; }
std::uint64_t DiagnosticCanonicalFingerprint(const std::vector<std::wstring>&) { return 0; }
std::vector<LogicalSnapshotEntry> logicalFixture;
std::vector<std::wstring> GetCanonicalOrderSnapshot() { return canonicalFixture; }
UIOrderSnapshot CaptureUIOrderSnapshot() { return {}; }
std::vector<LogicalSnapshotEntry> BuildLogicalSnapshot(const UIOrderSnapshot&) { return logicalFixture; }
enum class ContinuityReconcileResult { NoCandidate, Reconciled, Deferred };
''' + section("bool HasSimultaneousContinuityAlias(", "bool TryRebaseCanonicalLiveOrderLocked(") + section("bool IsSafeContinuityLiveState(", "bool IsCanonicalRelationSatisfied(") + r'''
bool check(bool condition, const char* name) {
    if (!condition) std::cerr << "FAIL: " << name << '\n';
    return condition;
}
int main() {
    const std::wstring oldPath = LR"(d:\windowsapps\app_6.6395.0.0_x64__publisher\app\app.exe)";
    const std::wstring oldKey = L"uid:3|path:" + oldPath;
    const std::wstring duplicate = LR"(uid:3|path:e:\windowsapps\app_6.6395.0.0_x64__publisher\app\app.exe)";
    const std::wstring targetPath = LR"(c:\program files\windowsapps\app_6.28899.2.0_x64__publisher\app\app.exe)";
    const std::wstring targetKey = L"uid:3|path:" + targetPath;
    entries[L"1"]={3,oldPath,L"",{1,2,3}};
    entries[L"2"]={3,targetPath,L"",{1,2,3}};
    const std::vector<LogicalSnapshotEntry> logical = {{1,oldKey,true},{2,targetKey,true}};
    ContinuityGroupAnalysis group;
    if (!check(AnalyzeContinuityGroup(2,targetKey,logical,{oldKey},&group) &&
               !group.ambiguous && group.canonicalMembers==1 && group.earliestCanonicalKey==oldKey,
               "new target matches a single older canonical entry")) return 1;
    if (!check(AnalyzeContinuityGroup(2,targetKey,logical,{oldKey,duplicate},&group) &&
               group.ambiguous, "duplicate closest version must be ambiguous, including absent registry entry")) return 1;
    if (!check(AnalyzeContinuityGroup(2,targetKey,logical,{oldKey,targetKey},&group) &&
               !group.ambiguous && group.canonicalMembers==2,
               "known target and older key are visible to caller")) return 1;
    logicalFixture=logical;
    LiveIdentityMapping target; target.windowsIdentity=2;
    liveFixture={true,true,2,2,{{1,oldKey,true},{2,targetKey,true}}};
    if (!check(!IsSafeContinuityLiveState(target,group), "two matching live icons must not be treated as one")) return 1;
    group.identities={2,0}; group.keys={targetKey,oldKey};
    entries[L"1"].icon={9,9,9};
    if (!check(!IsSafeContinuityLiveState(target,group), "live predecessor key must block even if its metadata differs")) return 1;
    entries[L"1"].icon={1,2,3};
    liveFixture={true,true,1,1,{{2,targetKey,true}}};
    if (!check(IsSafeContinuityLiveState(target,group), "one mapped target is safe")) return 1;
    liveFixture.entries[0].uniqueLogical=false;
    if (!check(!IsSafeContinuityLiveState(target,group), "nonunique logical identity is unsafe")) return 1;
    liveFixture.entries[0].uniqueLogical=true;
    liveFixture.entries[0].logicalKey.clear();
    if (!check(!IsSafeContinuityLiveState(target,group), "empty logical identity is unsafe")) return 1;
    liveFixture={true,true,2,1,{{1,oldKey,false},{2,targetKey,true}}};
    if (!check(!IsSafeContinuityLiveState(target,group), "incomplete live mapping is unsafe")) return 1;
    canonicalFixture={oldKey,targetKey};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::NoCandidate,
               "known target must retain its manual position")) return 1;
    canonicalFixture={oldKey,duplicate};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred,
               "ambiguous canonical predecessor must be deferred")) return 1;
    canonicalFixture={L"first",oldKey,L"last"};
    liveFixture={true,true,2,2,{{1,oldKey,true},{2,targetKey,true}}};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last"},
               "a simultaneous predecessor defers migration without altering canonical order")) return 1;
    liveFixture={true,true,1,1,{{2,targetKey,true}}};
    baselineSufficient=false;
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last"},
               "insufficient live baseline prevents package migration")) return 1;
    baselineSufficient=true;
    persistSuccess=false;
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last"},
               "failed persistence rolls canonical order back")) return 1;
    persistSuccess=true;
    concurrentTarget=targetKey;
    insertTargetOnCapture=true;
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last",targetKey},
               "target concurrently added after snapshot is not migrated")) return 1;
    canonicalFixture={L"first",oldKey,L"last"};
    concurrentTarget=duplicate;
    insertTargetOnCapture=true;
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last",duplicate},
               "a competing predecessor concurrently added after snapshot prevents migration")) return 1;
    canonicalFixture={L"first",oldKey,L"last"};
    concurrentTarget=L"unrelated-new-key";
    insertTargetOnCapture=true;
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last",L"unrelated-new-key"},
               "any canonical change after snapshot prevents stale migration")) return 1;
    canonicalFixture={L"first",oldKey,L"last"};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"first",targetKey,L"last"},
               "successful migration keeps canonical neighbours")) return 1;
    entries[L"1"].icon={9,9,9};
    const std::wstring olderPath = LR"(d:\windowsapps\app_6.1000.0.0_x64__publisher\app\app.exe)";
    const std::wstring olderKey = L"uid:3|path:" + olderPath;
    entries[L"3"]={3,olderPath,L"",{1,2,3}};
    logicalFixture={{3,olderKey,true},{1,oldKey,true},{2,targetKey,true}};
    canonicalFixture={olderKey,oldKey};
    bool predecessorFailure = false;
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred,
               "different newest predecessor icon must not select an older matching version")) predecessorFailure = true;
    entries.erase(L"1");
    logicalFixture={{3,olderKey,true},{2,targetKey,true}};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred,
               "missing newest predecessor registry entry must not select an older version")) predecessorFailure = true;
    if (predecessorFailure) return 1;
    entries[L"1"]={3,oldPath,L"",{9,9,9}};
    logicalFixture=logical;
    canonicalFixture={oldKey};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred,
               "different predecessor icon metadata must not be accepted by fallback")) return 1;
    entries[L"1"].icon={1,2,3};
    entries[L"2"].icon.clear();
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred,
               "missing target icon metadata with a possible predecessor must be deferred")) return 1;
    canonicalFixture={};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::NoCandidate,
               "missing metadata without a predecessor has no candidate")) return 1;
    entries.erase(L"1");
    entries[L"2"].icon={1,2,3};
    logicalFixture={{2,targetKey,true}};
    canonicalFixture={L"first",oldKey,L"last"};
    liveFixture={true,true,1,1,{{2,targetKey,true}}};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last"},
               "missing predecessor registry metadata with empty tooltip defers")) return 1;
    entries[L"2"].tooltip=L"Example";
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"first",targetKey,L"last"},
               "known tooltip permits unique canonical predecessor without old registry record")) return 1;
    std::cout << "PASS: continuity group selection\n";
}
'''

compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("A C++17 compiler is required on PATH")
folder = Path(tempfile.gettempdir()) / "tray-order-lock-continuity-test"
folder.mkdir(exist_ok=True)
cpp = folder / "continuity_group_test.cpp"
exe = folder / "continuity_group_test.exe"
cpp.write_text(code, encoding="utf-8")
subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
