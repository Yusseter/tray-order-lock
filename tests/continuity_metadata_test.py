"""Exercise production continuity matching with simulated tray registry entries.

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
#include <cwchar>
#include <mutex>
#include <map>
#include <string>
#include <vector>
using BYTE = unsigned char;
using DWORD = unsigned long;
struct Entry { DWORD uid; std::wstring path, tooltip; std::vector<BYTE> icon; };
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
''' + section("struct ContinuityIdentityMetadata {", "struct LiveIdentityMapping {") + section(
    "std::wstring ToLower(", "bool ContainsText(") + r'''
std::wstring MakeTrayEntrySubkey(std::uint64_t identity) { return std::to_wstring(identity); }
bool QueryIconGuid(const std::wstring&, std::wstring*) { return false; }
bool QueryDwordValue(const std::wstring& key, const wchar_t*, DWORD* uid) {
    *uid = entries.at(key).uid; return true;
}
std::wstring QueryStringValue(const std::wstring& key, const wchar_t* name) {
    return std::wstring(name) == L"ExecutablePath" ? entries.at(key).path : entries.at(key).tooltip;
}
bool QueryBinaryValue(const std::wstring& key, const wchar_t*, std::vector<BYTE>* value) {
    *value = entries.at(key).icon; return !value->empty();
}
''' + section("std::wstring NormalizeContinuityTooltip(", "std::wstring BuildLogicalKey(") + r'''
bool check(bool condition, const char* name) {
    if (!condition) std::cerr << "FAIL: " << name << '\n';
    return condition;
}
int main() {
    entries[L"1"] = {3, LR"(C:\Program Files\WindowsApps\Claude_6.6395.0.0_x64__publisher\app\Claude.exe)", L"", {1,2,3}};
    entries[L"2"] = {3, LR"(C:\Program Files\WindowsApps\Claude_6.28899.2.0_x64__publisher\app\Claude.exe)", L"", {1,2,3}};
    entries[L"3"] = {3, LR"(C:\Program Files\WindowsApps\Other_6.28899.2.0_x64__publisher\app\Other.exe)", L"", {1,2,3}};
    entries[L"4"] = {4, entries[L"2"].path, L"", {1,2,3}};
    entries[L"5"] = {3, entries[L"2"].path, L"", {1,2,4}};
    entries[L"6"] = {3, LR"(C:\other.exe)", L"  Example  ", {1,2,3}};
    entries[L"7"] = {3, LR"(C:\other2.exe)", L"example", {1,2,3}};
    entries[L"8"] = {3, LR"(C:\other.exe)", L"", {1,2,3}};
    entries[L"9"] = {3, LR"(D:\WindowsApps\Claude_6.6395.0.0_x64__publisher\app\Claude.exe)", L"", {1,2,3}};
    entries[L"10"] = {3, entries[L"2"].path, L"Claude", {1,2,3}};
    entries[L"11"] = {3, entries[L"3"].path, L"Claude", {1,2,3}};
    entries[L"12"] = {3, entries[L"2"].path, L"Claude", {1,2,4}};
    ContinuityIdentityMetadata a,b,c,d,e,legacy1,legacy2,nonpackage,otherRoot,withTooltip,otherFamily,otherIcon;
    if (!check(BuildContinuityIdentityMetadata(1, &a), "old WindowsApps identity without tooltip is supported")) return 1;
    if (!check(BuildContinuityIdentityMetadata(2, &b), "new WindowsApps identity without tooltip is supported")) return 1;
    if (!check(BuildContinuityIdentityMetadata(3, &c) && BuildContinuityIdentityMetadata(4, &d) && BuildContinuityIdentityMetadata(5, &e), "other WindowsApps identities are supported")) return 1;
    if (!check(ContinuityIdentityMatches(a,b), "same family, UID and icon match across package versions")) return 1;
    if (!check(BuildContinuityIdentityMetadata(9, &otherRoot) && ContinuityIdentityMatches(otherRoot,b), "matching package across installation roots")) return 1;
    if (!check(!ContinuityIdentityMatches(a,c) && !ContinuityIdentityMatches(a,d) && !ContinuityIdentityMatches(a,e), "different family, UID or icon do not match")) return 1;
    if (!check(BuildContinuityIdentityMetadata(10, &withTooltip) && BuildContinuityIdentityMetadata(11, &otherFamily) && BuildContinuityIdentityMetadata(12, &otherIcon), "WindowsApps identities with tooltips are supported")) return 1;
    if (!check(ContinuityIdentityMatches(a,withTooltip) && ContinuityIdentityMatches(withTooltip,a), "a missing tooltip on either version preserves same-family matching")) return 1;
    if (!check(!ContinuityIdentityMatches(a,otherFamily) && !ContinuityIdentityMatches(otherFamily,a) && !ContinuityIdentityMatches(a,otherIcon) && !ContinuityIdentityMatches(otherIcon,a), "mixed tooltip states do not match different families or icons")) return 1;
    if (!check(BuildContinuityIdentityMetadata(6, &legacy1) && BuildContinuityIdentityMetadata(7, &legacy2) && ContinuityIdentityMatches(legacy1,legacy2), "legacy tooltip matching remains supported")) return 1;
    if (!check(!BuildContinuityIdentityMetadata(8, &nonpackage), "missing tooltip on non-WindowsApps identity remains unsupported")) return 1;
    const std::wstring storedGuid=L"guid:{persisted-package}";
    RememberPackageIdentity(storedGuid,entries[L"2"].path,entries[L"2"].icon);
    g_packageHistory.clear();
    ContinuityIdentityMetadata stored;
    if (!check(LoadPackageIdentity(storedGuid,&stored) && stored.guidBacked &&
               ContinuityIdentityMatches(a,stored), "GUID evidence survives an in-memory cache reset")) return 1;
    const auto uidKey=L"uid:3|path:"+BuildVersionNormalizedPath(entries[L"2"].path);
    RememberPackageIdentity(uidKey,entries[L"2"].path,entries[L"2"].icon);
    g_packageHistory.clear();
    if (!check(LoadPackageIdentity(uidKey,&stored) && !stored.guidBacked && stored.uid==3 &&
               ContinuityIdentityMatches(b,stored), "UID evidence also survives session changes")) return 1;
    packageStorage[L"PackageIdentityV1."+storedGuid]=L"TOR_PACKAGE_V1\n"+entries[L"2"].path+L"\n0g";
    if (!check(!LoadPackageIdentity(storedGuid,&stored), "invalid hex metadata is rejected")) return 1;
    packageStorage[L"PackageIdentityV1."+storedGuid]=L"TOR_PACKAGE_V1\n"+entries[L"2"].path+L"\n0";
    if (!check(!LoadPackageIdentity(storedGuid,&stored), "truncated metadata is rejected")) return 1;
    packageStorage[L"PackageIdentityV1."+storedGuid]=L"unknown-version\n"+entries[L"2"].path+L"\n01";
    if (!check(!LoadPackageIdentity(storedGuid,&stored), "unsupported metadata format is rejected")) return 1;
    packageStorage[L"PackageIdentityV1."+uidKey]=L"TOR_PACKAGE_V1\n"+entries[L"3"].path+L"\n010203";
    if (!check(!LoadPackageIdentity(uidKey,&stored), "a UID record with the wrong executable is rejected")) return 1;
    packageWriteSuccess=false;
    RememberPackageIdentity(L"guid:{failed-write}",entries[L"2"].path,entries[L"2"].icon);
    if (!check(!LoadPackageIdentity(L"guid:{failed-write}",&stored), "a failed write does not create false persisted evidence")) return 1;
    std::cout << "PASS: continuity metadata matching\n";
}
'''

compiler = shutil.which("g++") or shutil.which("clang++")
if not compiler:
    raise SystemExit("A C++17 compiler (g++ or clang++) is required on PATH")
folder = Path(tempfile.gettempdir()) / "tray-order-lock-continuity-test"
folder.mkdir(exist_ok=True)
cpp = folder / "continuity_metadata_test.cpp"
exe = folder / "continuity_metadata_test.exe"
cpp.write_text(code, encoding="utf-8")
subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
