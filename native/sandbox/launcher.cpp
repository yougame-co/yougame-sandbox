// yougame-sandbox: runs one program inside a Windows AppContainer and a job object, so a game,
// an emulator or the ROM it parses gets none of the user's rights: it reads only the folders it
// is granted, writes only its own, has no network unless asked for, and cannot start programs
// unless opted in. It dies with the launcher. The desktop app (src/sandbox-policy.ts) spawns this with the grants
// and the program after "--"; the program's stdin/stdout/stderr are the launcher's own, handed
// down as they are, so a pipe protocol (yougame-libretro's) works unchanged.
//
//   yougame-sandbox --profile NAME [--display TEXT]
//                   [--parent-pid N]     stop the job when this decimal process ID exits
//                   [--runtime PATH]...   read + execute for every YouGame sandbox (the shared
//                                         capability): the host program, the libretro cores
//                   [--read PATH]...      read for this profile only (a game file)
//                   [--exec PATH]...      read + execute for this profile only (a native build's folder)
//                   [--write PATH]...     read + write + delete for this profile only (its saves)
//                   [--net none|internet|internet-server]
//                                         outbound internet (internetClient, S-1-15-3-1), plus
//                                         unsolicited inbound from the internet with
//                                         internet-server (internetClientServer, S-1-15-3-2).
//                                         Never loopback. Default none.
//                   [--require-net-guard] refuse unless this profile has the installed guard
//                   [--net-lan]           reserved; refused while LAN_IN_JAIL is false
//                   [--app-dlls]          the program's own DLLs beside it, not System32's copies
//                                         (no PREFER_SYSTEM32: Orca ships the d3dcompiler its
//                                         shader cache is keyed to, and the CRT it was built with)
//                   [--lpac]              less privileged AppContainer (no ALL APPLICATION PACKAGES)
//                   [--capability NAME]... an extra named capability (LPAC needs some); never the
//                                         network ones, whose derived SIDs the firewall ignores
//                   [--child-processes N] allow 1 or 2 helpers in the same container and job
//                   [--max-memory MB]     job memory limit for the process
//                   [--ui-handles]        experimental: forbid USER handles outside the job
//                   [--isolated-ui]       test-only noninteractive station/desktop; no embedding
//                   [--env KEY=VALUE]...  added to the program's minimal environment
//                   [--cwd PATH]
//                   [--embed-parent HWND --embed-class CLASS --embed-title TITLE]
//                                         make the program's CLASS window captioned TITLE a
//                                         child of HWND
//                                         (see "embedding" below)
//                   [--embed-keep-style]  adopt it with its own style: only WS_POPUP becomes
//                                         WS_CHILD, and WS_EX_NOPARENTNOTIFY is kept (Orca)
//                   [--embed-timeout-ms N] stop looking for that window N ms after the launch
//                                         (Orca's comes within seconds or never); without it, as
//                                         long as the program runs
//                   -- PROGRAM [ARGS...]
//   yougame-sandbox --grant-only --profile NAME [--runtime P]... [--read P]... [--exec P]... [--write P]...
//                                         only the grants, then exit 0 ("sandbox: granted"):
//                                         the app grants Orca's program folder once, when it is
//                                         installed, instead of walking its 2,800 files on a Play
//   yougame-sandbox --reset-profile --profile NAME
//                                         deletes the profile and its own storage (Windows' folder
//                                         for it under Packages), then exit 0 ("sandbox: profile
//                                         reset"): Help > Reset Orca files. The grants on files stay
//                                         (the profile's SID is its name's, so a new one is the same)
//
//   yougame-sandbox --install-net-guard|--remove-net-guard|--net-guard-status --profile NAME
//                                         install/remove require elevation; status never does
//   yougame-sandbox --request-net-guard --profile NAME --owner-hwnd N
//                                         app consent helper: run this executable's installer with
//                                         ShellExecuteEx runas, wait, return its result (no shell)
//
// Grants: a folder must be at least two levels below a drive root, a file may sit in the root
// itself (E:\Brawl.iso). Nothing on a network drive is granted (an AppContainer cannot open it
// anyway). On a drive without permissions (FAT32, exFAT) there is nothing to grant: the grant is
// skipped and said, and the program opens the file as any program can.
//
// Exit code: the program's own (122 when that is 120, 121 or 123), 120 when the sandbox could not be
// set up here (a grant, the job, the attributes; nothing ran), or 121 when this Windows cannot
// make an AppContainer at all (nothing ran), so the app can tell those apart from a game that
// failed; 123 means the required home-network guard is missing. The emulator runs the game unsandboxed (logged) only on 121 and refuses on 120; native
// builds and Orca refuse on both. Everything the launcher says goes to stderr, prefixed "sandbox:":
// "running pid N ..." before the program's first instruction, and "exit N, peak memory M MB" once
// it is gone (the program shares stderr, so the app trusts the first running line and the last
// exit line only).
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <cstring>
#include <iterator>
#include <userenv.h>
#include <cstdio>
#include <bit>
#include <cwctype>
#include <cerrno>
#include <limits>
#include <string>
#include <vector>
#include "network.hpp"

static const int SETUP_FAILED = 120;
static const int UNSUPPORTED = 121;
// The capability every YouGame sandbox carries: ACEs for it on the program and core folders let
// any game's container load them without a grant per game.
static const wchar_t *RUNTIME_CAPABILITY = L"yougameSandboxRuntime";

static void say(const wchar_t *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  std::fwprintf(stderr, L"sandbox: ");
  std::vfwprintf(stderr, fmt, ap);
  std::fwprintf(stderr, L"\n");
  std::fflush(stderr);
  va_end(ap);
}

static int fail(const wchar_t *what, DWORD err) {
  say(L"%ls failed (error %lu)", what, err);
  return SETUP_FAILED;
}

// ---------------------------------------------------------------- SIDs
static std::wstring sidString(PSID sid) {
  LPWSTR s = nullptr;
  if (!ConvertSidToStringSidW(sid, &s)) return L"?";
  std::wstring r = s;
  LocalFree(s);
  return r;
}

typedef BOOL(WINAPI *DeriveCapsFn)(LPCWSTR, PSID **, DWORD *, PSID **, DWORD *);

// A named capability's SID (the "capability SID", not the group SID). Windows 10 1607+.
static PSID capabilitySid(const wchar_t *name) {
  auto derive = std::bit_cast<DeriveCapsFn>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "DeriveCapabilitySidsFromName"));
  if (!derive) return nullptr;
  PSID *groups = nullptr, *caps = nullptr;
  DWORD ng = 0, nc = 0;
  if (!derive(name, &groups, &ng, &caps, &nc)) return nullptr;
  PSID out = nullptr;
  if (nc > 0) {
    DWORD len = GetLengthSid(caps[0]);
    out = (PSID)LocalAlloc(LPTR, len);
    if (out) CopySid(len, out, caps[0]);
  }
  for (DWORD i = 0; i < ng; i++) LocalFree(groups[i]);
  for (DWORD i = 0; i < nc; i++) LocalFree(caps[i]);
  LocalFree(groups);
  LocalFree(caps);
  return out;
}

static bool validProfileName(const std::wstring &n) {
  if (n.empty() || n.size() > 64) return false;
  for (wchar_t c : n)
    if (!(iswalnum(c) || c == L'.' || c == L'-' || c == L'_')) return false;
  return true;
}

// ---------------------------------------------------------------- file grants
static std::wstring fullPath(const std::wstring &p) {
  wchar_t buf[MAX_PATH * 4];
  DWORD n = GetFullPathNameW(p.c_str(), (DWORD)(sizeof buf / sizeof buf[0]), buf, nullptr);
  std::wstring r = n && n < sizeof buf / sizeof buf[0] ? std::wstring(buf, n) : std::wstring();
  // "C:\a\" is the folder C:\a, one level down, not two.
  while (r.size() > 3 && (r.back() == L'\\' || r.back() == L'/')) r.pop_back();
  return r;
}

// A grant on a drive root, or on anything that is not there, is refused: the app only ever grants
// its own folders and files. A folder sits at least two levels below a root; a file may sit in a
// root itself (a disc image at E:\Brawl.iso).
static bool grantable(const std::wstring &p, bool &isDir) {
  DWORD attrs = GetFileAttributesW(p.c_str());
  if (attrs == INVALID_FILE_ATTRIBUTES) return false;
  isDir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
  size_t seps = 0;
  for (wchar_t c : p) seps += (c == L'\\' || c == L'/');
  return p.size() > 3 && seps >= (isDir ? 2u : 1u);
}

// The volume a path is on: whether it is a network drive (never granted) and whether it keeps
// permissions at all (FAT32 and exFAT do not: nothing to grant there).
struct Volume {
  bool remote = false;
  bool acls = true;
};
static Volume volumeOf(const std::wstring &p) {
  Volume v;
  // \\server\share and \\?\UNC\server\share are remote; \\?\C:\... and \\.\... are local.
  if (p.rfind(L"\\\\?\\UNC\\", 0) == 0 || (p.rfind(L"\\\\", 0) == 0 && p.rfind(L"\\\\?\\", 0) != 0 && p.rfind(L"\\\\.\\", 0) != 0)) v.remote = true;
  wchar_t root[MAX_PATH * 4];
  if (!GetVolumePathNameW(p.c_str(), root, (DWORD)(sizeof root / sizeof root[0]))) return v;
  if (GetDriveTypeW(root) == DRIVE_REMOTE) v.remote = true;
  DWORD flags = 0;
  if (GetVolumeInformationW(root, nullptr, 0, nullptr, nullptr, &flags, nullptr, 0) && !(flags & FILE_PERSISTENT_ACLS)) v.acls = false;
  return v;
}

// Adds an allow ACE for `sid` with `mask` (inherited by everything inside when a folder), unless
// one that already covers it is there: a launch must not rewrite a tree's ACLs every time.
// noExecute replaces a legacy write ACE instead of merging its execute right back in.
static bool grant(const std::wstring &path, PSID sid, DWORD mask, const wchar_t *what, bool noExecute = false) {
  bool isDir = false;
  std::wstring p = fullPath(path);
  if (p.empty() || !grantable(p, isDir)) {
    say(L"refusing to grant %ls on %ls", what, path.c_str());
    return false;
  }
  Volume vol = volumeOf(p);
  if (vol.remote) {
    say(L"refusing to grant %ls on %ls: a network drive", what, p.c_str());
    return false;
  }
  if (!vol.acls) {
    if (noExecute) {
      say(L"refusing non-executable write on %ls: its drive keeps no ACLs", p.c_str());
      return false;
    }
    say(L"no permissions to grant %ls on %ls: its drive keeps none (FAT32, exFAT)", what, p.c_str());
    return true;
  }
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;
  DWORD err = GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd);
  if (err != ERROR_SUCCESS) {
    say(L"cannot read the ACL of %ls (error %lu)", p.c_str(), err);
    return false;
  }
  const BYTE inherit = isDir ? (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) : 0;
  DWORD allowed = 0;
  bool denied = false, executable = false, inheritedExecute = false;
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  // Read-only fast path, including generic masks and split RX ACEs installed by an admin.
  // Never request WRITE_DAC when the fixed capability already has the required file rights.
  for (DWORD i = 0; dacl && i < dacl->AceCount; i++) {
    ACE_HEADER *h = nullptr;
    if (!GetAce(dacl, i, (void **)&h) || (h->AceFlags & INHERIT_ONLY_ACE)) continue;
    if (h->AceType != ACCESS_ALLOWED_ACE_TYPE && h->AceType != ACCESS_DENIED_ACE_TYPE) continue;
    auto *a = (ACCESS_ALLOWED_ACE *)h;
    if (!EqualSid((PSID)&a->SidStart, sid)) continue;
    DWORD rights = a->Mask;
    MapGenericMask(&rights, &mapping);
    if (h->AceType == ACCESS_DENIED_ACE_TYPE && (rights & mask)) denied = true;
    if (h->AceType == ACCESS_ALLOWED_ACE_TYPE) {
      if ((h->AceFlags & inherit) == inherit) allowed |= rights;
      executable = executable || (rights & FILE_EXECUTE);
      inheritedExecute = inheritedExecute || ((h->AceFlags & INHERITED_ACE) && (rights & FILE_EXECUTE));
    }
  }
  // A NULL DACL already lets everyone in; merging into it would lock everyone else out.
  // SET_ACCESS can replace our explicit legacy ACE, but cannot remove inherited execute.
  // Fail closed rather than silently retain it (or accept a NULL DACL).
  if (noExecute && (!dacl || inheritedExecute)) {
    LocalFree(sd);
    say(L"refusing non-executable write on %ls: unrestricted or inherited execute access", p.c_str());
    return false;
  }
  const bool present = !dacl || (!denied && (allowed & mask) == mask && !(noExecute && executable));
  if (denied) {
    LocalFree(sd);
    say(L"cannot grant %ls on %ls: capability has an explicit deny", what, p.c_str());
    return false;
  }
  if (!present) {
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = mask;
    ea.grfAccessMode = noExecute ? SET_ACCESS : GRANT_ACCESS;
    ea.grfInheritance = isDir ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)sid;
    PACL next = nullptr;
    err = SetEntriesInAclW(1, &ea, dacl, &next);
    if (err == ERROR_SUCCESS)
      err = SetNamedSecurityInfoW((LPWSTR)p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, next, nullptr);
    if (next) LocalFree(next);
  }
  LocalFree(sd);
  if (err != ERROR_SUCCESS) {
    say(L"cannot grant %ls on %ls (error %lu); install-time capability RX grant is required for administrator-owned files", what, p.c_str(), err);
    return false;
  }
  return true;
}

// ---------------------------------------------------------------- command line and environment
// One argument quoted the way CommandLineToArgvW and the CRT read it back.
static std::wstring quote(const std::wstring &a) {
  if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) return a;
  std::wstring r = L"\"";
  for (size_t i = 0;; i++) {
    size_t slashes = 0;
    while (i < a.size() && a[i] == L'\\') i++, slashes++;
    if (i == a.size()) {
      r.append(slashes * 2, L'\\');
      break;
    }
    if (a[i] == L'"') r.append(slashes * 2 + 1, L'\\');
    else r.append(slashes, L'\\');
    r.push_back(a[i]);
  }
  r.push_back(L'"');
  return r;
}

static std::wstring envVar(const wchar_t *name) {
  wchar_t buf[2048];
  DWORD n = GetEnvironmentVariableW(name, buf, 2048);
  return n && n < 2048 ? std::wstring(buf, n) : std::wstring();
}

// ---------------------------------------------------------------- embedding
// A sandboxed program (low integrity) may not attach its window to the app's window (medium
// integrity): Windows' UI privilege isolation refuses SetParent across that line. The launcher
// is on the app's side of it, so with --embed-parent it waits for the program's top-level
// window of the given class and caption and makes it a child of the app's window, exactly what
// yougame-libretro does itself when it runs unsandboxed. The program waits for that (it polls
// GetParent while answering messages) before it shows the window. Nothing else is touched.
struct Embed {
  HANDLE process;
  DWORD pid;
  HWND parent;
  std::wstring cls, title;
  // Orca (--embed-keep-style): its window keeps its own style bits; only WS_POPUP becomes WS_CHILD.
  bool keepStyle = false;
  // --embed-timeout-ms: stop looking this long after the launch (0: as long as the program runs).
  unsigned long long timeoutMs = 0;
  HWND found = nullptr;
};

static BOOL CALLBACK findWindow(HWND h, LPARAM l) {
  auto *e = (Embed *)l;
  DWORD pid = 0;
  GetWindowThreadProcessId(h, &pid);
  if (pid != e->pid) return TRUE;
  // Class and title both: SDL also makes short-lived windows of its class (a WGL probe).
  // GetWindowTextW reads another process's caption without sending it a message.
  wchar_t cls[128], title[128];
  if (GetClassNameW(h, cls, 128) && e->cls == cls && GetWindowTextW(h, title, 128) && e->title == title) {
    e->found = h;
    return FALSE;
  }
  return TRUE;
}

static DWORD WINAPI adoptWindow(LPVOID p) {
  auto *e = (Embed *)p;
  const ULONGLONG start = GetTickCount64();
  HWND styled = nullptr;
  ULONGLONG firstAttempt = 0;
  DWORD pendingError = ERROR_SUCCESS;
  // The window comes after the core loaded the game: wait as long as the program lives, or until
  // --embed-timeout-ms (a program that never shows the window is not scanned for every 5 ms).
  while (WaitForSingleObject(e->process, 5) == WAIT_TIMEOUT) {
    if (e->timeoutMs && GetTickCount64() - start >= e->timeoutMs) {
      if (pendingError) say(L"could not adopt the program's window (error %lu)", pendingError);
      else say(L"no window to adopt after %llu ms: stopped looking", e->timeoutMs);
      return 0;
    }
    EnumWindows(findWindow, (LPARAM)e);
    if (!e->found) continue;
    if (styled != e->found) {
      firstAttempt = GetTickCount64();
      LONG_PTR style = GetWindowLongPtrW(e->found, GWL_STYLE);
      if (e->keepStyle) {
        // The program drew its window for this (Orca's --embed-adopted: a hidden WS_POPUP with
        // WS_CLIPSIBLINGS | WS_CLIPCHILDREN): it only stops being a top-level window. Its extended
        // style stays as it set it, and WS_EX_NOPARENTNOTIFY is made sure of, so it never sends a
        // synchronous WM_PARENTNOTIFY into the app's UI thread.
        style = (style & ~WS_POPUP) | WS_CHILD;
        LONG_PTR ex = GetWindowLongPtrW(e->found, GWL_EXSTYLE);
        if (!(ex & WS_EX_NOPARENTNOTIFY)) SetWindowLongPtrW(e->found, GWL_EXSTYLE, ex | WS_EX_NOPARENTNOTIFY);
      } else {
        style &= ~(WS_POPUP | WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU);
        style |= WS_CHILD | WS_CLIPSIBLINGS;
      }
      SetWindowLongPtrW(e->found, GWL_STYLE, style);
      styled = e->found;
    }
    SetLastError(ERROR_SUCCESS);
    HWND previous = SetParent(e->found, e->parent);
    DWORD err = GetLastError();
    SetLastError(ERROR_SUCCESS);
    // GetAncestor, not GetParent: GetParent answers the owner for a window that still has WS_POPUP.
    HWND parent = GetAncestor(e->found, GA_PARENT);
    DWORD parentErr = GetLastError();
    if (parent == e->parent) {
      say(L"adopted the program's window into the app's window");
      return 0;
    }
    // A window can be found before the cross-process handoff is ready: Windows can return
    // null with no error and leave it on the desktop. Keep trying the same live window,
    // without rewriting its styles or claiming success, for at most the native wait's 30 s.
    if (err == ERROR_SUCCESS && parentErr == ERROR_SUCCESS && parent == GetDesktopWindow() &&
        IsWindow(e->found) && IsWindow(e->parent) && GetTickCount64() - firstAttempt < 30000) {
      pendingError = ERROR_INVALID_STATE;
      continue;
    }
    // A null previous parent with no error is success; still verify the resulting parent.
    if (previous || err == ERROR_SUCCESS) err = parentErr ? parentErr : ERROR_INVALID_STATE;
    if (err != ERROR_INVALID_WINDOW_HANDLE || IsWindow(e->found)) {
      say(L"could not adopt the program's window (error %lu)", err);
      return 0;
    }
    e->found = nullptr; // gone before it could be adopted: look again
    styled = nullptr;
    pendingError = ERROR_SUCCESS;
  }
  return 0;
}

// Experimental isolation for the containment harness only. A separate desktop in WinSta0 still
// shares its screen-reading rights. Use a noninteractive window station instead; it cannot be
// switched onto the user's screen. Cross-station SetParent/input cannot support today's embedded
// Orca, so --isolated-ui refuses --embed-parent and is NEVER added by the app's play policy.
class IsolatedUi {
  HWINSTA station_ = nullptr;
  HDESK desktop_ = nullptr;
 public:
  std::wstring path;
  ~IsolatedUi() {
    if (desktop_) CloseDesktop(desktop_);
    if (station_) CloseWindowStation(station_);
  }
  DWORD create(PSID appSid) {
    std::wstring name = L"YouGameJail-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    std::wstring acl = L"D:(A;;GA;;;OW)(A;;GA;;;" + sidString(appSid) + L")S:(ML;;NW;;;LW)";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return GetLastError();
    SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), sd, FALSE};
    station_ = CreateWindowStationW(name.c_str(), 0, WINSTA_ALL_ACCESS, &sa);
    DWORD error = station_ ? ERROR_SUCCESS : GetLastError();
    HWINSTA original = GetProcessWindowStation();
    if (error == ERROR_SUCCESS) {
      if (!SetProcessWindowStation(station_)) error = GetLastError();
      else {
        // Desktop objects map GENERIC_ALL to their complete desktop-specific access mask.
        desktop_ = CreateDesktopW(L"Jail", nullptr, nullptr, 0, GENERIC_ALL, &sa);
        if (!desktop_) error = GetLastError();
        if (!SetProcessWindowStation(original)) error = GetLastError();
      }
    }
    LocalFree(sd);
    if (error == ERROR_SUCCESS) path = name + L"\\Jail";
    return error;
  }
};

// The non-elevated consent helper invokes only this bundled executable and a validated profile.
// SEE_MASK_FLAG_NO_UI suppresses ShellExecute error boxes; the Windows UAC consent UI is intended.
// Small installer result codes survive the elevated child's separate stderr/console session.
static int netGuardResultCode(DWORD error) {
  if (error == ERROR_SUCCESS) return 0;
  if (HRESULT_FACILITY(static_cast<HRESULT>(error)) == FACILITY_WIN32) error = HRESULT_CODE(error);
  if (error == ERROR_ACCESS_DENIED) return 2;
  if (error == ERROR_ELEVATION_REQUIRED) return 3;
  if (error == ERROR_SERVICE_NOT_ACTIVE || error == RPC_S_SERVER_UNAVAILABLE || error == EPT_S_NOT_REGISTERED) return 4;
  if (error == ERROR_INVALID_DATA || error == ERROR_INVALID_SID || error == ERROR_REVISION_MISMATCH) return 5;
  if (error == ERROR_DISK_FULL || error == ERROR_WRITE_FAULT) return 6;
  if (error == ERROR_TOO_MANY_CMDS) return 8;
  if (error == ERROR_TIMEOUT) return 9;
  if (HRESULT_FACILITY(static_cast<HRESULT>(error)) == FACILITY_FWP) return 7;
  return 1;
}
static DWORD netGuardResultError(DWORD result) {
  switch (result) {
    case 0: return ERROR_SUCCESS;
    case 2: return ERROR_ACCESS_DENIED;
    case 3: return ERROR_ELEVATION_REQUIRED;
    case 4: return ERROR_SERVICE_NOT_ACTIVE;
    case 5: return ERROR_INVALID_DATA;
    case 6: return ERROR_WRITE_FAULT;
    case 7: return ERROR_GEN_FAILURE; // the helper logs the distinct policy result above
    case 8: return ERROR_TOO_MANY_CMDS;
    case 9: return ERROR_TIMEOUT;
    default: return ERROR_GEN_FAILURE;
  }
}
static DWORD requestNetGuard(const std::wstring &profile, HWND owner) {
  if (!IsWindow(owner)) return ERROR_INVALID_WINDOW_HANDLE;
  wchar_t executable[32768]{};
  const DWORD length = GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable)));
  if (!length || length >= std::size(executable)) return ERROR_INSUFFICIENT_BUFFER;
  const HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(initialized)) return static_cast<DWORD>(initialized);
  const std::wstring parameters = L"--install-net-guard --profile \"" + profile + L"\"";
  SHELLEXECUTEINFOW request{};
  request.cbSize = sizeof request;
  request.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
  request.hwnd = owner;
  request.lpVerb = L"runas";
  request.lpFile = executable;
  request.lpParameters = parameters.c_str();
  request.nShow = SW_HIDE;
  DWORD error = ERROR_SUCCESS;
  if (!ShellExecuteExW(&request)) error = GetLastError();
  else if (!request.hProcess) error = ERROR_INVALID_HANDLE;
  else {
    if (WaitForSingleObject(request.hProcess, INFINITE) != WAIT_OBJECT_0) error = GetLastError();
    else {
      DWORD result = 0;
      if (!GetExitCodeProcess(request.hProcess, &result)) error = GetLastError();
      else {
        say(L"home-network guard installer result %lu", result);
        error = netGuardResultError(result);
      }
    }
    CloseHandle(request.hProcess);
  }
  CoUninitialize();
  return error;
}

// ---------------------------------------------------------------- main
int wmain(int argc, wchar_t **argv) {
  if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) return fail(L"system library policy", GetLastError());
  // Inherited by the child (CREATE_DEFAULT_ERROR_MODE is deliberately absent). Application
  // messages and MessageBox calls remain available; this suppresses OS fault/open-file UI only.
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  std::wstring profile, display = L"YouGame game", cwd, net = L"none";
  std::vector<std::wstring> runtime, reads, execs, writes, capNames, extraEnv;
  bool isolatedUi = false, requireNetGuard = false;
#ifdef YG_DIRECT_BROKER
  bool brokerProcess = false, linksHelper = false;
#endif
  std::wstring guardMode;
  bool guardModeRepeated = false;
  bool lpac = false, uiHandles = false, netLan = false, appDlls = false, grantOnly = false, keepStyle = false, resetProfile = false;
  unsigned long long embedTimeoutMs = 0;
  HWND embedParent = nullptr;
  HWND ownerHwnd = nullptr;
  bool ownerSpecified = false;
  std::wstring embedClass, embedTitle;
  unsigned long long maxMemoryMb = 0;
  DWORD parentPid = 0;
  DWORD childProcesses = 0;
  int programAt = -1;
  for (int i = 1; i < argc; i++) {
    std::wstring a = argv[i];
    auto next = [&]() -> std::wstring { return i + 1 < argc ? std::wstring(argv[++i]) : std::wstring(); };
    if (a == L"--") {
      programAt = i + 1;
      break;
    } else if (a == L"--profile") profile = next();
    else if (a == L"--owner-hwnd") {
      const std::wstring value = next();
      wchar_t *end = nullptr;
      errno = 0;
      const unsigned long long number = _wcstoui64(value.c_str(), &end, 10);
      if (ownerSpecified || value.empty() || value.find_first_not_of(L"0123456789") != std::wstring::npos ||
          !end || *end || errno == ERANGE || !number)
        return fail(L"owner window", ERROR_INVALID_PARAMETER);
      if constexpr (sizeof(uintptr_t) < sizeof(unsigned long long)) {
        if (number > std::numeric_limits<uintptr_t>::max()) return fail(L"owner window", ERROR_INVALID_PARAMETER);
      }
      ownerSpecified = true;
      ownerHwnd = reinterpret_cast<HWND>(static_cast<uintptr_t>(number));
    }
    else if (a == L"--display") display = next();
    else if (a == L"--parent-pid") {
      const std::wstring value = next();
      wchar_t *end = nullptr;
      errno = 0;
      const unsigned long long number = _wcstoui64(value.c_str(), &end, 10);
      if (parentPid || value.empty() || value.find_first_not_of(L"0123456789") != std::wstring::npos ||
          !end || *end || errno == ERANGE || !number || number > std::numeric_limits<DWORD>::max())
        return fail(L"parent process ID", ERROR_INVALID_PARAMETER);
      parentPid = static_cast<DWORD>(number);
    }
#ifdef YG_DIRECT_BROKER
    else if (a == L"--broker-process") brokerProcess = true;
    else if (a == L"--links-helper") { linksHelper = true; brokerProcess = true; uiHandles = true; }
#endif
    else if (a == L"--runtime") runtime.push_back(next());
    else if (a == L"--read") reads.push_back(next());
    else if (a == L"--exec") execs.push_back(next());
    else if (a == L"--write") writes.push_back(next());
    else if (a == L"--net") net = next();
    else if (a == L"--net-lan") netLan = true;
    else if (a == L"--require-net-guard") requireNetGuard = true;
    else if (a == L"--install-net-guard" || a == L"--remove-net-guard" ||
             a == L"--net-guard-status" || a == L"--request-net-guard") {
      if (!guardMode.empty()) guardModeRepeated = true;
      guardMode = a;
    }
    else if (a == L"--app-dlls") appDlls = true;
    else if (a == L"--grant-only") grantOnly = true;
    else if (a == L"--lpac") lpac = true;
    else if (a == L"--capability") capNames.push_back(next());
    else if (a == L"--child-processes") {
      const std::wstring value = next();
      if (childProcesses || (value != L"1" && value != L"2"))
        return fail(L"--child-processes must be 1 or 2, once", ERROR_INVALID_PARAMETER);
      childProcesses = value == L"1" ? 1u : 2u;
    }
    else if (a == L"--max-memory") maxMemoryMb = _wcstoui64(next().c_str(), nullptr, 10);
    else if (a == L"--ui-handles") uiHandles = true;
    else if (a == L"--isolated-ui") isolatedUi = true;
    else if (a == L"--embed-parent") embedParent = (HWND)(uintptr_t)_wcstoui64(next().c_str(), nullptr, 10);
    else if (a == L"--embed-class") embedClass = next();
    else if (a == L"--embed-title") embedTitle = next();
    else if (a == L"--embed-keep-style") keepStyle = true;
    else if (a == L"--embed-timeout-ms") embedTimeoutMs = _wcstoui64(next().c_str(), nullptr, 10);
    else if (a == L"--reset-profile") resetProfile = true;
    else if (a == L"--env") extraEnv.push_back(next());
    else if (a == L"--cwd") cwd = next();
    else {
      say(L"unknown option %ls", a.c_str());
      return SETUP_FAILED;
    }
  }
#ifdef YG_DIRECT_BROKER
  // The links helper verifies a one-process job itself; it may never opt out of that boundary.
  if (childProcesses && linksHelper) return fail(L"links helper child processes are forbidden", ERROR_INVALID_PARAMETER);
#endif
  if (!guardMode.empty()) {
    // Only the consent request also accepts its app window handle. No grants/child.
    const bool requesting = guardMode == L"--request-net-guard";
    if (!validProfileName(profile) || argc != (requesting ? 6 : 4) || guardModeRepeated || programAt >= 0 ||
        (requesting ? !ownerSpecified : ownerSpecified) ||
        resetProfile || grantOnly || requireNetGuard) {
      say(L"usage: yougame-sandbox --install-net-guard|--remove-net-guard|--net-guard-status --profile NAME; --request-net-guard also needs --owner-hwnd N");
      return SETUP_FAILED;
    }
    if (requesting && !IsWindow(ownerHwnd)) return fail(L"owner window is gone", ERROR_INVALID_WINDOW_HANDLE);
    if (guardMode == L"--request-net-guard") {
      const DWORD error = requestNetGuard(profile, ownerHwnd);
      if (error == ERROR_INVALID_WINDOW_HANDLE) return fail(L"owner window is gone", error);
      if (error != ERROR_SUCCESS) return fail(L"home-network guard installation", error);
      say(L"home-network guard installed");
      return 0;
    }
    PSID package = nullptr;
    const HRESULT derived = DeriveAppContainerSidFromAppContainerName(profile.c_str(), &package);
    if (FAILED(derived) || !package) {
      const DWORD error = FAILED(derived) ? static_cast<DWORD>(derived) : ERROR_INVALID_SID;
      say(L"home-network guard profile failed (error %lu)", error);
      return guardMode == L"--net-guard-status" ? NET_GUARD_MISSING : netGuardResultCode(error);
    }
    const DWORD error = guardMode == L"--install-net-guard" ? netGuardInstall(profile, package) :
      guardMode == L"--remove-net-guard" ? netGuardRemove(profile, package) : netGuardStatus(profile, package);
    FreeSid(package);
    if (error != ERROR_SUCCESS) {
      if (error == static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_TOO_MANY_CMDS)))
        say(L"home-network guard cleanup limit reached (32 passes)");
      else if (error == ERROR_TIMEOUT)
        say(L"home-network guard management wait timed out (60 s)");
      else say(L"home-network guard %ls failed (error %lu)", guardMode.c_str() + 2, error);
      return guardMode == L"--net-guard-status" ? NET_GUARD_MISSING : netGuardResultCode(error);
    }
    say(L"home-network guard %ls", guardMode == L"--net-guard-status" ? L"present" :
      guardMode == L"--install-net-guard" ? L"installed" : L"removed");
    return 0;
  }
  if (ownerSpecified) return fail(L"owner window mode", ERROR_INVALID_PARAMETER);
  if ((netLan && !LAN_IN_JAIL) || (isolatedUi && embedParent)) {
    say(L"requested sandbox mode is unavailable");
    return SETUP_FAILED;
  }
  if (embedParent && (!IsWindow(embedParent) || embedClass.empty() || embedTitle.empty())) {
    say(L"--embed-parent needs a window, --embed-class and --embed-title");
    return SETUP_FAILED;
  }
  if (resetProfile) {
    if (!validProfileName(profile) || programAt >= 0 || grantOnly) {
      say(L"usage: yougame-sandbox --reset-profile --profile NAME");
      return SETUP_FAILED;
    }
    // Gone already is as good as deleted.
    HRESULT hr = DeleteAppContainerProfile(profile.c_str());
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
      say(L"could not reset AppContainer %ls (error 0x%08lx)", profile.c_str(), (DWORD)hr);
      return SETUP_FAILED;
    }
    say(L"profile reset: AppContainer %ls", profile.c_str());
    return 0;
  }
  const bool netOk = net == L"none" || net == L"internet" || net == L"internet-server";
  if (!validProfileName(profile) || !netOk || (grantOnly ? programAt >= 0 : (programAt < 0 || programAt >= argc))) {
    say(L"usage: yougame-sandbox [--grant-only] --profile NAME [OPTIONS] [-- PROGRAM ARGS]");
    return SETUP_FAILED;
  }
  // The network capabilities have fixed SIDs; DeriveCapabilitySidsFromName gives others, which the
  // firewall does not honour (Chromium maps these names for the same reason). Only by --net.
  for (auto &n : capNames)
    if (_wcsicmp(n.c_str(), L"yougameLinksExecutable") == 0) {
      say(L"the links executable capability is reserved for --links-helper");
      return SETUP_FAILED;
    } else if (_wcsicmp(n.c_str(), L"internetClient") == 0 || _wcsicmp(n.c_str(), L"internetClientServer") == 0 || _wcsicmp(n.c_str(), L"privateNetworkClientServer") == 0) {
      say(L"--capability %ls: use --net and --net-lan for the network", n.c_str());
      return SETUP_FAILED;
    }

  // Read-only check before profile creation, grants or child setup. Native/disc-check launches
  // never request it. There is no policy mutation and no elevation on this launch path.
  if (requireNetGuard) {
    PSID package = nullptr;
    const HRESULT derived = DeriveAppContainerSidFromAppContainerName(profile.c_str(), &package);
    const DWORD error = FAILED(derived) ? static_cast<DWORD>(derived) : !package ? ERROR_INVALID_SID : netGuardStatus(profile, package);
    if (package) FreeSid(package);
    if (error != ERROR_SUCCESS) {
      say(L"home-network guard required (error %lu)", error);
      return NET_GUARD_MISSING;
    }
  }

  // The profile: created once per game, found again afterwards.
  PSID appSid = nullptr;
  HRESULT hr = CreateAppContainerProfile(profile.c_str(), display.c_str(), display.c_str(), nullptr, 0, &appSid);
  if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) hr = DeriveAppContainerSidFromAppContainerName(profile.c_str(), &appSid);
  if (FAILED(hr) || !appSid) {
    say(L"the AppContainer profile failed (error 0x%08lx)", (DWORD)hr);
    return UNSUPPORTED;
  }

#ifdef YG_DIRECT_BROKER
  // A helper gets no shared-runtime capability, extra grants or environment. Only its executable.
  if (linksHelper && (profile.rfind(L"YouGame.Links.", 0) != 0 || maxMemoryMb != 128 || !uiHandles ||
      !parentPid || !runtime.empty() || !reads.empty() || !execs.empty() || !writes.empty() ||
      !capNames.empty() || !extraEnv.empty() || netLan || lpac || grantOnly || embedParent ||
      (net != L"internet" && net != L"internet-server")))
    return fail(L"the links sandbox policy", ERROR_INVALID_PARAMETER);
  struct HelperCleanup {
    std::wstring profile;
    ~HelperCleanup() {
      if (!profile.empty()) DeleteAppContainerProfile(profile.c_str());
    }
  } helperCleanup;
  PSID helperSid = nullptr;
  if (linksHelper) {
    helperCleanup.profile = profile;
    // Stable helper-only capability: one idempotent RX ACE, never per-profile ACL churn.
    // Only this launch path adds it to a token; ordinary --capability requests reject it.
    helperSid = capabilitySid(L"yougameLinksExecutable");
    const auto binary = fullPath(argv[programAt]);
    bool isDir = false;
    if (!helperSid || !grantable(binary, isDir) || isDir ||
        !grant(binary, helperSid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, L"helper executable"))
      return SETUP_FAILED;
  }
  PSID runtimeSid = linksHelper ? nullptr : capabilitySid(RUNTIME_CAPABILITY);
#else
  PSID runtimeSid = capabilitySid(RUNTIME_CAPABILITY);
#endif
  if (!runtimeSid
#ifdef YG_DIRECT_BROKER
      && !linksHelper
#endif
  ) {
    say(L"named capabilities are not available (error %lu)", GetLastError());
    return UNSUPPORTED;
  }

  // Grants: the shared runtime folders to the capability, the game's own to its profile.
  const DWORD READ = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
  // With helpers, data/Documents grants must not become executable code locations.
  // Preserve the exact historical mask for every launch without the opt-in.
  const DWORD WRITE = (childProcesses ? FILE_GENERIC_READ : READ) | FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
  for (auto &p : runtime)
    if (!grant(p, runtimeSid, READ, L"runtime read")) return SETUP_FAILED;
  for (auto &p : reads)
    if (!grant(p, appSid, FILE_GENERIC_READ, L"read")) return SETUP_FAILED;
  for (auto &p : execs)
    if (!grant(p, appSid, READ, L"read and execute")) return SETUP_FAILED;
  for (auto &p : writes)
    if (!grant(p, appSid, WRITE, L"write", childProcesses != 0)) return SETUP_FAILED;
  if (grantOnly) {
    say(L"granted for AppContainer %ls", profile.c_str());
    return 0;
  }

  // Capabilities in the token: the runtime one always, the network ones by their fixed SIDs as
  // asked (internetClient, internetClientServer, privateNetworkClientServer), extras by name.
  std::vector<PSID> capSids;
  if (runtimeSid) capSids.push_back(runtimeSid);
#ifdef YG_DIRECT_BROKER
  if (helperSid) capSids.push_back(helperSid);
#endif
  auto fixedCap = [&](const wchar_t *sid, const wchar_t *what) -> bool {
    PSID c = nullptr;
    if (!ConvertStringSidToSidW(sid, &c)) {
      fail(what, GetLastError());
      return false;
    }
    capSids.push_back(c);
    return true;
  };
  if (net != L"none" && !fixedCap(L"S-1-15-3-1", L"the internetClient capability")) return SETUP_FAILED;
  if (net == L"internet-server" && !fixedCap(L"S-1-15-3-2", L"the internetClientServer capability")) return SETUP_FAILED;
  if constexpr (LAN_IN_JAIL) {
    if (netLan && !fixedCap(L"S-1-15-3-3", L"the privateNetworkClientServer capability")) return SETUP_FAILED;
  }
  for (auto &n : capNames) {
    PSID s = capabilitySid(n.c_str());
    if (!s) return fail(L"a named capability", GetLastError());
    capSids.push_back(s);
  }
  std::vector<SID_AND_ATTRIBUTES> caps;
  for (PSID s : capSids) caps.push_back({s, SE_GROUP_ENABLED});
  SECURITY_CAPABILITIES sc{};
  sc.AppContainerSid = appSid;
  sc.Capabilities = caps.data();
  sc.CapabilityCount = (DWORD)caps.size();

  // The job: the program dies with the launcher (KILL_ON_JOB_CLOSE, no breakaway), defaults to
  // one process, and keeps away from the clipboard, other desktops, display settings, system
  // parameters, global atoms and logoff.
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return fail(L"the job object", GetLastError());
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  // Helpers inherit the same AppContainer token and job. Executables are bounded by existing
  // folder grants: the build folder and the --exec Steam game folder (including its own exes),
  // plus Windows/system locations already executable by the container. Opted-in write grants
  // exclude FILE_EXECUTE, including when replacing a previous launch's legacy write ACE.
  // No new file rights; image-load mitigations below still apply (including no low-label images).
  limits.BasicLimitInformation.ActiveProcessLimit = 1 + childProcesses;
  if (maxMemoryMb) {
    limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.ProcessMemoryLimit = (SIZE_T)(maxMemoryMb * 1024ull * 1024ull);
  }
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits)) return fail(L"the job limits", GetLastError());
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
  ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                           JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
  if (uiHandles) ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
  if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof ui)) return fail(L"the job UI limits", GetLastError());

  // The only external USER handle an embedded child needs: its app-selected parent. A child
  // polls GetParent after adoption; HANDLES would otherwise block that even though the launcher
  // performed SetParent. No other app/desktop window is granted to the job.
  if (uiHandles && embedParent && !UserHandleGrantAccess(reinterpret_cast<HANDLE>(embedParent), job, TRUE))
    return fail(L"the embedded parent handle", GetLastError());

  // Standard handles, passed down as inheritable copies and nothing else (an explicit handle list).
  std::vector<HANDLE> inherit;
  HANDLE std3[3] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
  const DWORD which[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
  for (int k = 0; k < 3; k++) {
    HANDLE h = GetStdHandle(which[k]);
    if (!h || h == INVALID_HANDLE_VALUE) continue;
    HANDLE dup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup, 0, TRUE, DUPLICATE_SAME_ACCESS)) return fail(L"the standard handles", GetLastError());
    std3[k] = dup;
    inherit.push_back(dup);
  }

  // Process attributes: the AppContainer, the handle list, no children unless opted in, mitigations.
  DWORD childPolicy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
  DWORD64 mitigations = PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
                        PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON |
                        PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON |
                        (appDlls ? 0 : PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON);
#ifdef YG_DIRECT_BROKER
  if (linksHelper) mitigations |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON |
      PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
      PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON;
#endif
  DWORD allPackages = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
  DWORD attrCount = 4 - (childProcesses ? 1 : 0) + (lpac ? 1 : 0);
  SIZE_T attrSize = 0;
  InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
  std::vector<char> attrBuf(attrSize);
  auto attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)attrBuf.data();
  if (!InitializeProcThreadAttributeList(attrs, attrCount, 0, &attrSize)) return fail(L"the attribute list", GetLastError());
  bool ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof sc, nullptr, nullptr) &&
            (childProcesses || UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &childPolicy, sizeof childPolicy, nullptr, nullptr)) &&
            UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigations, sizeof mitigations, nullptr, nullptr) &&
            (inherit.empty() || UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit.data(), inherit.size() * sizeof(HANDLE), nullptr, nullptr)) &&
            (!lpac || UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &allPackages, sizeof allPackages, nullptr, nullptr));
  if (!ok) return fail(L"the process attributes", GetLastError());

  // A minimal environment: the system's own variables, temp and app data inside the container's
  // folder, and what the app adds. Never the app's environment (tokens, paths, settings).
  std::wstring acFolder;
  {
    LPWSTR sidStr = nullptr, folder = nullptr;
    if (ConvertSidToStringSidW(appSid, &sidStr) && SUCCEEDED(GetAppContainerFolderPath(sidStr, &folder)) && folder) {
      acFolder = folder;
      CoTaskMemFree(folder);
    }
    if (sidStr) LocalFree(sidStr);
  }
  std::vector<std::wstring> env;
  for (const wchar_t *name : {L"SystemRoot", L"windir", L"SystemDrive", L"PROCESSOR_ARCHITECTURE", L"PROCESSOR_IDENTIFIER", L"PROCESSOR_LEVEL", L"PROCESSOR_REVISION",
                              L"NUMBER_OF_PROCESSORS", L"OS", L"PATHEXT", L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432", L"CommonProgramFiles", L"ProgramData", L"ALLUSERSPROFILE"}) {
    std::wstring v = envVar(name);
    if (!v.empty()) env.push_back(std::wstring(name) + L"=" + v);
  }
  std::wstring sysRoot = envVar(L"SystemRoot");
  if (sysRoot.empty()) sysRoot = L"C:\\Windows";
  env.push_back(L"PATH=" + sysRoot + L"\\System32;" + sysRoot);
  if (!acFolder.empty()) {
    std::wstring temp = acFolder + L"\\Temp";
    CreateDirectoryW(temp.c_str(), nullptr);
    env.push_back(L"TEMP=" + temp);
    env.push_back(L"TMP=" + temp);
    env.push_back(L"LOCALAPPDATA=" + acFolder);
    env.push_back(L"APPDATA=" + acFolder);
    env.push_back(L"USERPROFILE=" + acFolder);
  }
  for (auto &e : extraEnv)
    if (e.find(L'=') != std::wstring::npos && e[0] != L'=') env.push_back(e);
  std::wstring envBlock;
  for (auto &e : env) envBlock += e + L'\0';
  envBlock += L'\0';

  std::wstring cmd;
  for (int i = programAt; i < argc; i++) cmd += (cmd.empty() ? L"" : L" ") + quote(argv[i]);
  IsolatedUi privateUi;
  if (isolatedUi) {
    DWORD error = privateUi.create(appSid);
    if (error != ERROR_SUCCESS) return fail(L"the test desktop", error);
  }
  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof si;
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = std3[0];
  si.StartupInfo.hStdOutput = std3[1];
  si.StartupInfo.hStdError = std3[2];
  si.lpAttributeList = attrs;
  if (isolatedUi) si.StartupInfo.lpDesktop = privateUi.path.data();
  PROCESS_INFORMATION pi{};
  std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
  cmdBuf.push_back(0);
  HANDLE parent = nullptr;
  if (parentPid) {
    parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!parent) return fail(L"YouGame parent process is gone", GetLastError());
    // Hold the process object, not just its PID. A reused PID must not let a new process keep
    // the game alive: the app that launched us necessarily existed before this launcher.
    FILETIME parentCreated{}, launcherCreated{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(parent, &parentCreated, &exited, &kernel, &user) ||
        !GetProcessTimes(GetCurrentProcess(), &launcherCreated, &exited, &kernel, &user)) {
      const DWORD error = GetLastError();
      CloseHandle(parent);
      return fail(L"YouGame parent creation time", error);
    }
    if (CompareFileTime(&parentCreated, &launcherCreated) >= 0 || WaitForSingleObject(parent, 0) != WAIT_TIMEOUT) {
      CloseHandle(parent);
      return fail(L"YouGame parent process is gone", ERROR_INVALID_PARAMETER);
    }
  }
  if (!CreateProcessW(argv[programAt], cmdBuf.data(), nullptr, nullptr, !inherit.empty(),
                      EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS, (LPVOID)envBlock.data(),
                      cwd.empty() ? nullptr : cwd.c_str(), &si.StartupInfo, &pi)) {
    const DWORD error = GetLastError();
    if (parent) CloseHandle(parent);
    return fail(L"starting the program", error);
  }
  DeleteProcThreadAttributeList(attrs);
  if (!AssignProcessToJobObject(job, pi.hProcess)) {
    DWORD err = GetLastError();
    TerminateProcess(pi.hProcess, SETUP_FAILED);
    if (parent) CloseHandle(parent);
    return fail(L"joining the job", err);
  }
#ifdef YG_DIRECT_BROKER
  // This retained process object is duplicated into our verified app parent before the child
  // executes. The app's native broker uses it, never a later OpenProcess by PID.
  if (brokerProcess) {
    HANDLE app = parentPid ? OpenProcess(PROCESS_DUP_HANDLE, FALSE, parentPid) : nullptr;
    HANDLE transferred = nullptr;
    const bool handedOver = app && DuplicateHandle(GetCurrentProcess(), pi.hProcess, app, &transferred,
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0);
    if (app) CloseHandle(app);
    if (!handedOver) {
      TerminateJobObject(job, SETUP_FAILED);
      return fail(L"the app broker process handle", GetLastError());
    }
    say(L"broker process %llu", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(transferred)));
  }
#endif
  for (HANDLE h : inherit) CloseHandle(h);
  say(L"running pid %lu in AppContainer %ls (%ls)%ls, network %ls%ls%ls", pi.dwProcessId, profile.c_str(), sidString(appSid).c_str(), lpac ? L" LPAC" : L"", net.c_str(),
      netLan ? L"+lan" : L"", appDlls ? L", app dlls" : L"");
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
  HANDLE adopter = nullptr;
  Embed embed{pi.hProcess, pi.dwProcessId, embedParent, embedClass, embedTitle, keepStyle, embedTimeoutMs};
  if (embedParent) adopter = CreateThread(nullptr, 0, adoptWindow, &embed, 0, nullptr);
  if (parent) {
    const HANDLE handles[] = {pi.hProcess, parent};
    const DWORD waited = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
    if (waited == WAIT_OBJECT_0 + 1) {
      say(L"YouGame is gone; stopping the game");
      TerminateJobObject(job, 1);
      WaitForSingleObject(pi.hProcess, 5000);
    }
  } else {
    WaitForSingleObject(pi.hProcess, INFINITE);
  }
  if (adopter) {
    WaitForSingleObject(adopter, 2000);
    CloseHandle(adopter);
  }
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION used{};
  if (QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &used, sizeof used, nullptr))
    say(L"exit %lu, peak memory %llu MB", code, (unsigned long long)(used.PeakProcessMemoryUsed / (1024 * 1024)));
  CloseHandle(pi.hProcess);
  if (parent) CloseHandle(parent);
  CloseHandle(job);
  // 120, 121 and 123 are the launcher's own: a program that happens to exit with one must not read as
  // a sandbox that never started.
  return code == SETUP_FAILED || code == UNSUPPORTED || code == NET_GUARD_MISSING ? 122 : (int)code;
}
