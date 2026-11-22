"""Run the production event-driven retry loop with simulated COM ownership."""

from pathlib import Path
import shutil
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "tray-order-lock.wh.cpp").read_text(encoding="utf-8")
retry = source[source.index("void RetryDeferredLiveContinuity("):source.index("void ReconcileKnownLiveOverflowOrder(")]
code = r'''
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
enum class OrderingBehavior { LockAll, PreserveManual };
std::atomic<int> g_orderingBehavior{1};
unsigned g_internalMoveDepth=0, g_taskbarMoveDepth=0;
struct LiveOverflowEntry { std::uint64_t windowsIdentity; std::wstring logicalKey; bool mapped=true, uniqueLogical=true; };
struct LiveOverflowSnapshot { bool valid=true; unsigned size=2, mappedEntries=2; std::vector<LiveOverflowEntry> entries; };
struct LiveIdentityMapping { std::uint64_t windowsIdentity=0; };
int held=0, restores=0, captures=0, acquiredIndex=-1;
bool sufficient=true, wrongIdentity=false, migrate=false;
struct IUnknown { unsigned Release() { --held; return 0; } } icon;
LiveOverflowSnapshot snapshot{true,2,2,{{1,L"known"},{2,L"updated"}}};
std::vector<std::wstring> canonical{L"known",L"old"};
LiveOverflowSnapshot CaptureLiveOverflowSnapshot(void*) { ++captures; return snapshot; }
bool HasSufficientTrustedLiveBaseline(unsigned) { return sufficient; }
std::vector<std::wstring> GetCanonicalOrderSnapshot() { return canonical; }
bool FindWindowsAppsUidCanonicalPredecessor(std::uint64_t, const std::wstring& key,
    const std::vector<std::wstring>&, std::wstring*, bool* ambiguous) {
    *ambiguous=false; return key==L"updated";
}
void* AcquireCurrentOverflowIconAtIndex(unsigned index, const LiveOverflowEntry&) {
    acquiredIndex=index; ++held; return &icon;
}
bool LookupLiveMapping(void*, LiveIdentityMapping* mapping) {
    mapping->windowsIdentity=wrongIdentity ? 999 : 2; return true;
}
void RestoreCanonicalRelationForMapping(void*, const LiveIdentityMapping&) {
    ++restores;
    if (migrate) { canonical.push_back(L"updated"); }
}
''' + retry + r'''
bool check(bool ok, const char* name) { if (!ok) std::cerr << "FAIL: " << name << '\n'; return ok; }
int main() {
    void* manager=&icon;
    sufficient=false;
    RetryDeferredLiveContinuity(manager);
    if (!check(restores==0 && held==0, "incomplete baseline waits without acquiring COM references")) return 1;
    sufficient=true;
    g_internalMoveDepth=1;
    RetryDeferredLiveContinuity(manager);
    if (!check(restores==0, "internal moves cannot recurse into retry")) return 1;
    g_internalMoveDepth=0;
    RetryDeferredLiveContinuity(manager);
    if (!check(restores==1 && held==0 && acquiredIndex==1 && captures<10, "one pending key is retried once per event and released")) return 1;
    RetryDeferredLiveContinuity(manager);
    if (!check(restores==2 && held==0, "a later event can retry a still-deferred key")) return 1;
    wrongIdentity=true;
    RetryDeferredLiveContinuity(manager);
    if (!check(restores==2 && held==0, "changed mapping is rejected and reference released")) return 1;
    wrongIdentity=false; migrate=true;
    RetryDeferredLiveContinuity(manager);
    if (!check(restores==3 && held==0, "successful migration is not retried again in the same event")) return 1;
    RetryDeferredLiveContinuity(manager);
    if (!check(restores==3 && held==0, "known manual or migrated key is left alone")) return 1;
    std::cout << "PASS: deferred continuity retries and reference ownership\n";
}
'''

compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("A C++17 compiler is required on PATH")
folder = Path(tempfile.gettempdir()) / "tray-order-lock-continuity-test"
folder.mkdir(exist_ok=True)
cpp = folder / "deferred_retry_test.cpp"
exe = folder / "deferred_retry_test.exe"
cpp.write_text(code, encoding="utf-8")
subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
