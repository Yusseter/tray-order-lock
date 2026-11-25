"""Exercise the production single-icon restore with fewer apps open than at startup."""

from pathlib import Path
import shutil
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "tray-order-lock.wh.cpp").read_text(encoding="utf-8")


def section(start, end):
    return source[source.index(start):source.index(end, source.index(start))]


code = r'''
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>
using HRESULT=long;
constexpr HRESULT E_FAIL=-1;
#define TOR_LOG(...) ((void)0)
''' + section("struct LiveIdentityMapping {", "using NotificationAreaIcon2_Constructor_t =") + r'''
enum class OrderingBehavior { LockAll, PreserveManual };
enum class ContinuityReconcileResult { NoCandidate, Reconciled, Deferred };
std::atomic<int> g_orderingBehavior{1};
std::atomic<bool> g_liveBaselineActiveInSession{true};
unsigned g_internalMoveDepth=0,g_taskbarMoveDepth=0;
std::mutex g_restoreRetryMutex;
std::vector<std::uint64_t> g_restoreRetryIdentities;
std::atomic<unsigned long long> g_restoreObservationCount{0},g_restoreKnownCandidateCount{0},
 g_restoreNewIconCount{0},g_restoreMoveAttemptCount{0},g_restoreMoveObservedCount{0},g_restoreMoveVerifiedCount{0};
std::vector<std::wstring> canonical{L"a",L"target",L"b"};
LiveOverflowSnapshot live;
bool quorum=false;
ContinuityReconcileResult continuity=ContinuityReconcileResult::NoCandidate;
std::wstring skip;
unsigned moves=0;
std::vector<std::wstring> GetCanonicalOrderSnapshot() { return canonical; }
std::wstring BuildLogicalKey(std::uint64_t) { return L"target"; }
ContinuityReconcileResult TryReconcileCanonicalContinuityGroup(const LiveIdentityMapping&,const std::wstring&) { return continuity; }
std::uint64_t DiagnosticCanonicalFingerprint(const std::vector<std::wstring>&) { return 0; }
void RecordRestoreObservationSkip(const wchar_t* reason,std::uint64_t) { skip=reason; }
bool HasSufficientTrustedLiveBaseline(unsigned) { return quorum; }
LiveOverflowSnapshot CaptureLiveOverflowSnapshot(void*) { return live; }
void HandleNewIcon(void*,const LiveIdentityMapping&,const std::wstring&,const std::vector<std::wstring>&,unsigned long long,unsigned long long) {}
constexpr int kOverflowLocation=1;
void moveIcon(void*,void**,int,unsigned index) {
 ++moves;
 auto target=live.entries[live.targetIndex];
 live.entries.erase(live.entries.begin()+live.targetIndex);
 live.entries.insert(live.entries.begin()+index,target);
 live.targetIndex=index;
}
auto NotificationAreaIconManager_MoveIcon=&moveIcon;
''' + section("bool FindUniqueOverflowIndexForKey(", "enum class ContinuityReconcileResult {") + section(
    "bool IsCanonicalRelationSatisfied(", "bool AppendNewCanonicalKeyAtEnd("
) + section("void RestoreCanonicalRelationForMapping(", "void RestoreCanonicalRelation(void*") + r'''
void reset() {
 skip.clear(); moves=0; quorum=false; continuity=ContinuityReconcileResult::NoCandidate;
 g_liveBaselineActiveInSession=true;
 live={}; live.valid=true; live.targetFound=true; live.targetIndex=0; live.size=3; live.mappedEntries=3;
 live.entries={{1,L"target",true,true},{2,L"a",true,true},{3,L"b",true,true}};
}
bool check(bool ok,const char* message) { if(!ok) std::cerr<<"FAIL: "<<message<<"\n";return ok; }
int main() {
 LiveIdentityMapping target{nullptr,reinterpret_cast<void*>(1),1};
 reset(); RestoreCanonicalRelationForMapping(&live,target);
 if(!check(moves==1 && live.targetIndex==1,"known icon restores between verified neighbours without a baseline-size quorum")) return 1;
 reset();live.mappedEntries=2;RestoreCanonicalRelationForMapping(&live,target);
 if(!check(moves==0,"incomplete live mapping cannot be used for local restore")) return 1;
 reset();g_liveBaselineActiveInSession=false;RestoreCanonicalRelationForMapping(&live,target);
 if(!check(moves==0,"initial untrusted ordering remains inactive")) return 1;
 reset();quorum=true;continuity=ContinuityReconcileResult::Deferred;RestoreCanonicalRelationForMapping(&live,target);
 if(!check(moves==0,"an unsafe continuity group blocks even a known target")) return 1;
 reset();live.entries[2].logicalKey=L"unknown";RestoreCanonicalRelationForMapping(&live,target);
 if(!check(moves==0,"missing following anchor is not guessed")) return 1;
 std::cout<<"PASS: local restore with changing live icon counts\n";
}
'''

compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("A C++17 compiler is required on PATH")
folder = Path(tempfile.gettempdir()) / "tray-order-lock-continuity-test"
folder.mkdir(exist_ok=True)
cpp = folder / "local_restore_test.cpp"
exe = folder / "local_restore_test.exe"
cpp.write_text(code, encoding="utf-8")
subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
