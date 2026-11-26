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
#include <atomic>
#include <cstdint>
#include <cwctype>
#include <iostream>
#include <cwchar>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
using BYTE = unsigned char;
using DWORD = unsigned long;
#define TOR_LOG(...) ((void)0)
struct Entry { DWORD uid; std::wstring path, tooltip; std::vector<BYTE> icon; std::wstring guid; };
std::map<std::wstring, Entry> entries;
std::map<std::wstring,std::wstring> packageStorage;
bool packageWriteSuccess=true;
int Wh_SetStringValue(const wchar_t* key,const wchar_t* value) {
    if(!packageWriteSuccess) return 0;
    packageStorage[key]=value; return 1;
}
std::size_t Wh_GetStringValue(const wchar_t* key,wchar_t* buffer,std::size_t chars) {
    const auto it=packageStorage.find(key);
    if(it==packageStorage.end() || it->second.size()>=chars) return 0;
    std::copy(it->second.begin(),it->second.end(),buffer);
    buffer[it->second.size()]=0; return it->second.size();
}
''' + section("struct LogicalSnapshotEntry {", "struct LiveIdentityMapping {") + section(
    "std::wstring ToLower(", "bool ContainsText("
) + r'''
std::wstring MakeTrayEntrySubkey(std::uint64_t identity) { return std::to_wstring(identity); }
bool QueryIconGuid(const std::wstring& key, std::wstring* guid) {
    auto it=entries.find(key); if(it==entries.end() || it->second.guid.empty()) return false;
    *guid=it->second.guid; return true;
}
bool QueryDwordValue(const std::wstring& key, const wchar_t*, DWORD* uid) {
    auto it=entries.find(key); if (it == entries.end()) return false;
    *uid=it->second.uid; return it->second.guid.empty();
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
std::atomic<bool> g_liveBaselineActiveInSession{true};
bool HasSufficientTrustedLiveBaseline(unsigned) { return baselineSufficient; }
std::uint64_t DiagnosticCanonicalFingerprint(const std::vector<std::wstring>&) { return 0; }
std::vector<LogicalSnapshotEntry> logicalFixture;
std::vector<std::wstring> GetCanonicalOrderSnapshot() { return canonicalFixture; }
UIOrderSnapshot CaptureUIOrderSnapshot() { return {}; }
std::vector<LogicalSnapshotEntry> BuildLogicalSnapshot(const UIOrderSnapshot&) { return logicalFixture; }
bool ContainsCanonicalKeyLocked(const std::wstring& key) {
    return std::find(g_canonicalOrder.begin(),g_canonicalOrder.end(),key)!=g_canonicalOrder.end();
}
enum class ContinuityReconcileResult { NoCandidate, Reconciled, Deferred };
''' + section("unsigned int MergeLoadedLiveKeysLocked(", "void InitializeCanonicalState(") + section("bool HasSimultaneousContinuityAlias(", "bool TryRebaseCanonicalLiveOrderLocked(") + section("bool IsSafeContinuityLiveState(", "bool IsCanonicalRelationSatisfied(") + r'''
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
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred,
               "a package with incomplete metadata is not adopted as a new icon")) return 1;
    entries.erase(L"1");
    entries[L"2"].icon={1,2,3};
    logicalFixture={{2,targetKey,true}};
    canonicalFixture={L"first",oldKey,L"last"};
    liveFixture={true,true,1,1,{{2,targetKey,true}}};
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last"},
               "missing predecessor registry metadata with empty tooltip defers")) return 1;
    packageStorage.erase(L"PackageIdentityV1."+oldKey);
    g_packageHistory.clear();
    entries[L"2"].tooltip=L"Example";
    if (!check(TryReconcileCanonicalContinuityGroup(target,targetKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"first",targetKey,L"last"},
               "known tooltip permits unique canonical predecessor without old registry record")) return 1;
    const std::wstring guidKey=L"guid:{updated-package-guid}";
    entries[L"2"].guid=L"{updated-package-guid}";
    entries[L"2"].icon.clear();
    canonicalFixture={L"first",oldKey,L"last"};
    logicalFixture={{2,guidKey,true}};
    liveFixture={true,true,1,1,{{2,guidKey,true}}};
    unsigned int deferred=0;
    const auto beforeStartup=canonicalFixture;
    if (!check(MergeLoadedLiveKeysLocked(logicalFixture,beforeStartup,&deferred)==0 &&
               deferred==1 && canonicalFixture==beforeStartup,
               "startup does not permanently append incomplete GUID metadata")) return 1;
    if (!check(TryReconcileCanonicalContinuityGroup(target,guidKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",oldKey,L"last"},
               "partial GUID metadata waits instead of placing the updated app at the end")) return 1;
    entries[L"2"].icon={1,2,3};
    if (!check(TryReconcileCanonicalContinuityGroup(target,guidKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"first",guidKey,L"last"},
               "UID to GUID migration preserves the old neighbours even without old registry data")) return 1;
    if (!check(TryReconcileCanonicalContinuityGroup(target,guidKey)==ContinuityReconcileResult::NoCandidate,
               "a known GUID is not overwritten by UID history")) return 1;
    const std::wstring returnedUidKey=L"uid:3|path:"+targetPath;
    entries[L"3"]={3,targetPath,L"",{1,2,3}};
    LiveIdentityMapping returned; returned.windowsIdentity=3;
    logicalFixture={{2,guidKey,true},{3,returnedUidKey,true}};
    liveFixture={true,true,1,1,{{3,returnedUidKey,true}}};
    canonicalFixture={L"first",guidKey,L"last"};
    baselineSufficient=false;
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"first",returnedUidKey,L"last"},
               "GUID to UID re-registration preserves position with fewer applications open")) return 1;
    canonicalFixture={L"first",guidKey,L"last"};
    g_liveBaselineActiveInSession=false;
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Deferred,
               "metadata evidence does not activate initially untrusted ordering")) return 1;
    g_liveBaselineActiveInSession=true;
    liveFixture={true,true,2,2,{{2,guidKey,true},{3,returnedUidKey,true}}};
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==std::vector<std::wstring>{L"first",guidKey,L"last"},
               "simultaneously live GUID and UID icons are kept separate")) return 1;
    liveFixture={true,true,1,1,{{3,returnedUidKey,true}}};
    entries[L"2"].icon={9,9,9};
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Deferred,
               "a package GUID with a different icon is not adopted or overwritten")) return 1;
    entries[L"2"].icon={1,2,3};
    const std::wstring secondGuid=L"guid:{second-package-icon}";
    entries[L"4"]=entries[L"2"];entries[L"4"].guid=L"{second-package-icon}";
    logicalFixture.push_back({4,secondGuid,true});
    canonicalFixture={guidKey,secondGuid};
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Deferred,
               "two matching GUID icons cannot be guessed")) return 1;
    logicalFixture.pop_back();
    canonicalFixture={guidKey,L"uid:4|path:"+targetPath};
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Deferred,
               "multiple historical UID roles cannot share one GUID anchor")) return 1;
    canonicalFixture={oldKey,guidKey};
    entries[L"1"]={3,oldPath,L"",{1,2,3}};
    logicalFixture.push_back({1,oldKey,true});
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{oldKey,returnedUidKey},
               "newer GUID position is preferred over obsolete UID history")) return 1;
    canonicalFixture={L"first",guidKey,L"last"};
    entries.erase(L"2");
    g_packageHistory.clear();
    logicalFixture={{3,returnedUidKey,true}};
    if (!check(TryReconcileCanonicalContinuityGroup(returned,returnedUidKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"first",returnedUidKey,L"last"},
               "removing old Windows registry data does not erase the GUID position evidence")) return 1;
    canonicalFixture={L"first",guidKey,L"last"};
    entries[L"5"]={3,targetPath,L"",{1,2,3},L"{replacement-guid}"};
    const std::wstring replacementGuid=L"guid:{replacement-guid}";
    LiveIdentityMapping replacement;replacement.windowsIdentity=5;
    logicalFixture={{5,replacementGuid,true}};
    liveFixture={true,true,1,1,{{5,replacementGuid,true}}};
    if (!check(TryReconcileCanonicalContinuityGroup(replacement,replacementGuid)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"first",replacementGuid,L"last"},
               "GUID replacement survives removal of old registry data and a session restart")) return 1;
    const std::wstring cachedOlder=L"guid:{cached-older}";
    const std::wstring cachedNewer=L"guid:{cached-newer}";
    const std::wstring cachedTarget=L"guid:{cached-target}";
    const std::wstring cachedPath=LR"(d:\windowsapps\example_5.0.0.0_x64__publisher\app\example.exe)";
    const std::wstring newerCachedPath=LR"(d:\windowsapps\example_6.0.0.0_x64__publisher\app\example.exe)";
    const std::wstring cachedTargetPath=LR"(d:\windowsapps\example_7.0.0.0_x64__publisher\app\example.exe)";
    RememberPackageIdentity(cachedOlder,cachedPath,{1,2,3});
    RememberPackageIdentity(cachedNewer,newerCachedPath,{9,9,9});
    entries.clear();
    entries[L"70"]={3,cachedTargetPath,L"",{1,2,3},L"{cached-target}"};
    logicalFixture={{70,cachedTarget,true}};
    liveFixture={true,true,1,1,{{70,cachedTarget,true}}};
    LiveIdentityMapping cachedMapping;cachedMapping.windowsIdentity=70;
    canonicalFixture={cachedOlder,cachedNewer};
    auto cachedBefore=canonicalFixture;
    if (!check(TryReconcileCanonicalContinuityGroup(cachedMapping,cachedTarget)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==cachedBefore,
               "conflicting newest cached GUID must not fall back to an older matching GUID")) return 1;
    canonicalFixture={cachedOlder};cachedBefore=canonicalFixture;
    entries[L"71"]={3,LR"(d:\windowsapps\other_5.0.0.0_x64__publisher\app\example.exe)",L"",{1,2,3},L"{cached-older}"};
    logicalFixture.push_back({71,cachedOlder,true});
    if (!check(TryReconcileCanonicalContinuityGroup(cachedMapping,cachedTarget)!=ContinuityReconcileResult::Reconciled &&
               canonicalFixture==cachedBefore,
               "a current GUID record from another package invalidates cached identity evidence")) return 1;
    // A full lifecycle, rather than independent one-transition examples.
    packageStorage.clear();g_packageHistory.clear();entries.clear();
    std::wstring currentKey=L"guid:{cycle-0}";
    const std::wstring initialPath=LR"(d:\windowsapps\example_1.0.0.0_x64__publisher\app\example.exe)";
    entries[L"100"]={3,initialPath,L"",{1,2,3},L"{cycle-0}"};
    ContinuityIdentityMetadata initial;
    if (!check(BuildContinuityIdentityMetadata(100,&initial), "initial lifecycle metadata is captured")) return 1;
    canonicalFixture={L"before",currentKey,L"after"};
    baselineSufficient=false;
    for (unsigned step=1;step<=8;++step) {
        entries.clear();g_packageHistory.clear();
        const auto path=(step%2 ? L"c:\\program files\\windowsapps\\" : L"d:\\windowsapps\\")+
            std::wstring(L"example_")+std::to_wstring(step+1)+L".0.0.0_x64__publisher\\app\\example.exe";
        const auto identity=100+step;
        const auto textId=std::to_wstring(identity);
        const auto guid=L"{cycle-"+std::to_wstring(step)+L"}";
        const auto nextKey=step%2 ? L"uid:3|path:"+path : L"guid:"+guid;
        entries[textId]={3,path,step%3 ? L"" : L"Example",{1,2,3},step%2 ? L"" : guid};
        logicalFixture={{identity,nextKey,true}};
        liveFixture={true,true,1,1,{{identity,nextKey,true}}};
        LiveIdentityMapping next;next.windowsIdentity=identity;
        const auto before=canonicalFixture;
        if (step==3) {
            entries[textId].icon.clear();
            if (!check(TryReconcileCanonicalContinuityGroup(next,nextKey)==ContinuityReconcileResult::Deferred && canonicalFixture==before,
                       "delayed metadata cannot corrupt the lifecycle position")) return 1;
            entries[textId].icon={1,2,3};
        }
        if (step==5) {
            persistSuccess=false;
            if (!check(TryReconcileCanonicalContinuityGroup(next,nextKey)==ContinuityReconcileResult::Deferred && canonicalFixture==before,
                       "a lifecycle write failure rolls back to its previous identity")) return 1;
            persistSuccess=true;
        }
        auto expected=before;
        std::replace(expected.begin(),expected.end(),currentKey,nextKey);
        if (!check(TryReconcileCanonicalContinuityGroup(next,nextKey)==ContinuityReconcileResult::Reconciled && canonicalFixture==expected,
                   "repeated updates, root changes, session resets and registry pruning preserve position")) return 1;
        currentKey=nextKey;
        if (step==4) {
            canonicalFixture={currentKey,L"before",L"after"};
            if (!check(TryReconcileCanonicalContinuityGroup(next,currentKey)==ContinuityReconcileResult::NoCandidate &&
                       canonicalFixture==std::vector<std::wstring>{currentKey,L"before",L"after"},
                       "an established manual preference survives the next identity change")) return 1;
        }
    }
    for (unsigned version=8;version>=6;--version) {
        entries.clear();g_packageHistory.clear();
        const auto path=L"c:\\program files\\windowsapps\\example_"+std::to_wstring(version)+
            L".0.0.0_x64__publisher\\app\\example.exe";
        const bool guid=version%2;
        const auto nextKey=guid ? L"guid:{rollback-"+std::to_wstring(version)+L"}" : L"uid:3|path:"+path;
        entries[L"200"]={3,path,L"",{1,2,3},guid ? L"{rollback-"+std::to_wstring(version)+L"}" : L""};
        logicalFixture={{200,nextKey,true}};
        liveFixture={true,true,1,1,{{200,nextKey,true}}};
        LiveIdentityMapping rollback;rollback.windowsIdentity=200;
        auto expected=canonicalFixture;
        std::replace(expected.begin(),expected.end(),currentKey,nextKey);
        if (!check(TryReconcileCanonicalContinuityGroup(rollback,nextKey)==ContinuityReconcileResult::Reconciled &&
                   canonicalFixture==expected,
                   "verified version rollbacks retain the latest selected position")) return 1;
        currentKey=nextKey;
    }
    const auto rollbackPath=LR"(c:\program files\windowsapps\example_2.0.0.0_x64__publisher\app\example.exe)";
    const auto futurePath=LR"(d:\windowsapps\example_3.0.0.0_x64__publisher\app\example.exe)";
    const auto futureKey=L"uid:3|path:"+std::wstring(futurePath);
    const std::wstring rollbackKey=L"guid:{rollback-safety}";
    entries.clear();g_packageHistory.clear();packageStorage.clear();
    RememberPackageIdentity(futureKey,futurePath,{1,2,3});
    entries[L"300"]={3,rollbackPath,L"",{1,2,3},L"{rollback-safety}"};
    logicalFixture={{300,rollbackKey,true}};
    liveFixture={true,true,1,1,{{300,rollbackKey,true}}};
    LiveIdentityMapping rollback;rollback.windowsIdentity=300;
    canonicalFixture={futureKey,L"uid:4|path:"+std::wstring(futurePath)};
    auto beforeRollback=canonicalFixture;
    if (!check(TryReconcileCanonicalContinuityGroup(rollback,rollbackKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==beforeRollback,
               "rollback cannot guess between multiple historical package icon roles")) return 1;
    canonicalFixture={L"before",futureKey,L"after"};
    beforeRollback=canonicalFixture;
    entries[L"301"]={3,futurePath,L"",{9,9,9}};
    logicalFixture.push_back({301,futureKey,true});
    if (!check(TryReconcileCanonicalContinuityGroup(rollback,rollbackKey)!=ContinuityReconcileResult::Reconciled &&
               canonicalFixture==beforeRollback,
               "current registry metadata overrides conflicting cached rollback evidence")) return 1;
    entries[L"301"].icon={1,2,3};
    liveFixture={true,true,2,2,{{300,rollbackKey,true},{301,futureKey,true}}};
    if (!check(TryReconcileCanonicalContinuityGroup(rollback,rollbackKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==beforeRollback,
               "a simultaneously live future identity prevents rollback migration")) return 1;
    entries.erase(L"301");logicalFixture.pop_back();
    liveFixture={true,true,1,1,{{300,rollbackKey,true}}};
    g_liveBaselineActiveInSession=false;
    if (!check(TryReconcileCanonicalContinuityGroup(rollback,rollbackKey)==ContinuityReconcileResult::Deferred &&
               canonicalFixture==beforeRollback,
               "cached rollback evidence cannot activate an untrusted session")) return 1;
    g_liveBaselineActiveInSession=true;
    if (!check(TryReconcileCanonicalContinuityGroup(rollback,rollbackKey)==ContinuityReconcileResult::Reconciled &&
               canonicalFixture==std::vector<std::wstring>{L"before",rollbackKey,L"after"},
               "a verified rollback succeeds after temporary blockers are removed")) return 1;
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
