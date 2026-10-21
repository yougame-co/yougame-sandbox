// yougame-sandbox: runs one program inside a Windows AppContainer and a job object, so a game,
// an emulator or the ROM it parses gets none of the user's rights: it reads only the folders it
// is granted, writes only its own, has no network unless asked for, cannot start programs, and
// dies with the launcher. The desktop app (src/sandbox-policy.ts) spawns this with the grants
// and the program after "--"; the program's stdin/stdout/stderr are the launcher's own, handed
// down as they are, so a pipe protocol (yougame-libretro's) works unchanged.
//
//   yougame-sandbox --profile NAME [--display TEXT]
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
//                   [--net-lan]           the LAN too (privateNetworkClientServer, S-1-15-3-3).
//                                         Windows already lets an internet program reach the LAN
//                                         on a Public-profile network; this adds it on Private ones
//                   [--app-dlls]          the program's own DLLs beside it, not System32's copies
//                                         (no PREFER_SYSTEM32: Orca ships the d3dcompiler its
//                                         shader cache is keyed to, and the CRT it was built with)
//                   [--lpac]              less privileged AppContainer (no ALL APPLICATION PACKAGES)
//                   [--capability NAME]... an extra named capability (LPAC needs some); never the
//                                         network ones, whose derived SIDs the firewall ignores
//                   [--max-memory MB]     job memory limit for the process
//                   [--ui-handles]        also forbid USER handles of processes outside the job
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
// Grants: a folder must be at least two levels below a drive root, a file may sit in the root
// itself (E:\Brawl.iso). Nothing on a network drive is granted (an AppContainer cannot open it
// anyway). On a drive without permissions (FAT32, exFAT) there is nothing to grant: the grant is
// skipped and said, and the program opens the file as any program can.
//
// Exit code: the program's own (122 when that is 120 or 121), 120 when the sandbox could not be
// set up here (a grant, the job, the attributes; nothing ran), or 121 when this Windows cannot
// make an AppContainer at all (nothing ran), so the app can tell those apart from a game that
// failed: the emulator runs the game unsandboxed (logged) only on 121 and refuses on 120; native
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
#include <userenv.h>
#include <cstdio>
#include <cwctype>
#include <string>
#include <vector>

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
  auto derive = (DeriveCapsFn)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "DeriveCapabilitySidsFromName");
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
static bool grant(const std::wstring &path, PSID sid, DWORD mask, const wchar_t *what) {
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
  bool present = false;
  // A NULL DACL already lets everyone in; merging into it would lock everyone else out.
  if (!dacl) present = true;
  for (DWORD i = 0; dacl && i < dacl->AceCount && !present; i++) {
    ACE_HEADER *h = nullptr;
    if (!GetAce(dacl, i, (void **)&h) || h->AceType != ACCESS_ALLOWED_ACE_TYPE || (h->AceFlags & INHERIT_ONLY_ACE)) continue;
    auto *a = (ACCESS_ALLOWED_ACE *)h;
    if (EqualSid((PSID)&a->SidStart, sid) && (a->Mask & mask) == mask && (h->AceFlags & inherit) == inherit) present = true;
  }
  if (!present) {
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = mask;
    ea.grfAccessMode = GRANT_ACCESS;
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
    say(L"cannot grant %ls on %ls (error %lu)", what, p.c_str(), err);
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
  // The window comes after the core loaded the game: wait as long as the program lives, or until
  // --embed-timeout-ms (a program that never shows the window is not scanned for every 5 ms).
  while (WaitForSingleObject(e->process, 5) == WAIT_TIMEOUT) {
    if (e->timeoutMs && GetTickCount64() - start >= e->timeoutMs) {
      say(L"no window to adopt after %llu ms: stopped looking", e->timeoutMs);
      return 0;
    }
    EnumWindows(findWindow, (LPARAM)e);
    if (!e->found) continue;
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
    if (SetParent(e->found, e->parent)) {
      say(L"adopted the program's window into the app's window");
      return 0;
    }
    DWORD err = GetLastError();
    if (err != ERROR_INVALID_WINDOW_HANDLE) {
      say(L"could not adopt the program's window (error %lu)", err);
      return 0;
    }
    e->found = nullptr; // gone before it could be adopted: look again
  }
  return 0;
}

// ---------------------------------------------------------------- main
int wmain(int argc, wchar_t **argv) {
  std::wstring profile, display = L"YouGame game", cwd, net = L"none";
  std::vector<std::wstring> runtime, reads, execs, writes, capNames, extraEnv;
  bool lpac = false, uiHandles = false, netLan = false, appDlls = false, grantOnly = false, keepStyle = false, resetProfile = false;
  unsigned long long embedTimeoutMs = 0;
  HWND embedParent = nullptr;
  std::wstring embedClass, embedTitle;
  unsigned long long maxMemoryMb = 0;
  int programAt = -1;
  for (int i = 1; i < argc; i++) {
    std::wstring a = argv[i];
    auto next = [&]() -> std::wstring { return i + 1 < argc ? std::wstring(argv[++i]) : std::wstring(); };
    if (a == L"--") {
      programAt = i + 1;
      break;
    } else if (a == L"--profile") profile = next();
    else if (a == L"--display") display = next();
    else if (a == L"--runtime") runtime.push_back(next());
    else if (a == L"--read") reads.push_back(next());
    else if (a == L"--exec") execs.push_back(next());
    else if (a == L"--write") writes.push_back(next());
    else if (a == L"--net") net = next();
    else if (a == L"--net-lan") netLan = true;
    else if (a == L"--app-dlls") appDlls = true;
    else if (a == L"--grant-only") grantOnly = true;
    else if (a == L"--lpac") lpac = true;
    else if (a == L"--capability") capNames.push_back(next());
    else if (a == L"--max-memory") maxMemoryMb = _wcstoui64(next().c_str(), nullptr, 10);
    else if (a == L"--ui-handles") uiHandles = true;
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
    say(L"usage: yougame-sandbox --profile NAME [--runtime P] [--read P] [--exec P] [--write P] [--net none|internet|internet-server] [--net-lan] [--app-dlls] -- PROGRAM [ARGS]");
    say(L"       yougame-sandbox --grant-only --profile NAME [--runtime P] [--read P] [--exec P] [--write P]");
    return SETUP_FAILED;
  }
  // The network capabilities have fixed SIDs; DeriveCapabilitySidsFromName gives others, which the
  // firewall does not honour (Chromium maps these names for the same reason). Only by --net.
  for (auto &n : capNames)
    if (_wcsicmp(n.c_str(), L"internetClient") == 0 || _wcsicmp(n.c_str(), L"internetClientServer") == 0 || _wcsicmp(n.c_str(), L"privateNetworkClientServer") == 0) {
      say(L"--capability %ls: use --net and --net-lan for the network", n.c_str());
      return SETUP_FAILED;
    }

  // The profile: created once per game, found again afterwards.
  PSID appSid = nullptr;
  HRESULT hr = CreateAppContainerProfile(profile.c_str(), display.c_str(), display.c_str(), nullptr, 0, &appSid);
  if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) hr = DeriveAppContainerSidFromAppContainerName(profile.c_str(), &appSid);
  if (FAILED(hr) || !appSid) {
    say(L"the AppContainer profile failed (error 0x%08lx)", (DWORD)hr);
    return UNSUPPORTED;
  }

  PSID runtimeSid = capabilitySid(RUNTIME_CAPABILITY);
  if (!runtimeSid) {
    say(L"named capabilities are not available (error %lu)", GetLastError());
    return UNSUPPORTED;
  }

  // Grants: the shared runtime folders to the capability, the game's own to its profile.
  const DWORD READ = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
  const DWORD WRITE = READ | FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
  for (auto &p : runtime)
    if (!grant(p, runtimeSid, READ, L"runtime read")) return SETUP_FAILED;
  for (auto &p : reads)
    if (!grant(p, appSid, FILE_GENERIC_READ, L"read")) return SETUP_FAILED;
  for (auto &p : execs)
    if (!grant(p, appSid, READ, L"read and execute")) return SETUP_FAILED;
  for (auto &p : writes)
    if (!grant(p, appSid, WRITE, L"write")) return SETUP_FAILED;
  if (grantOnly) {
    say(L"granted for AppContainer %ls", profile.c_str());
    return 0;
  }

  // Capabilities in the token: the runtime one always, the network ones by their fixed SIDs as
  // asked (internetClient, internetClientServer, privateNetworkClientServer), extras by name.
  std::vector<PSID> capSids{runtimeSid};
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
  if (netLan && !fixedCap(L"S-1-15-3-3", L"the privateNetworkClientServer capability")) return SETUP_FAILED;
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

  // The job: the program dies with the launcher (KILL_ON_JOB_CLOSE, no breakaway), starts no other
  // process, and keeps away from the clipboard, other desktops, display settings, system
  // parameters, global atoms and logoff.
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return fail(L"the job object", GetLastError());
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  limits.BasicLimitInformation.ActiveProcessLimit = 1;
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

  // Process attributes: the AppContainer, the handle list, no child processes, mitigations.
  DWORD childPolicy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
  DWORD64 mitigations = PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
                        PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON |
                        PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON |
                        (appDlls ? 0 : PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON);
  DWORD allPackages = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
  DWORD attrCount = 4 + (lpac ? 1 : 0);
  SIZE_T attrSize = 0;
  InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
  std::vector<char> attrBuf(attrSize);
  auto attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)attrBuf.data();
  if (!InitializeProcThreadAttributeList(attrs, attrCount, 0, &attrSize)) return fail(L"the attribute list", GetLastError());
  bool ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof sc, nullptr, nullptr) &&
            UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &childPolicy, sizeof childPolicy, nullptr, nullptr) &&
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
  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof si;
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = std3[0];
  si.StartupInfo.hStdOutput = std3[1];
  si.StartupInfo.hStdError = std3[2];
  si.lpAttributeList = attrs;
  PROCESS_INFORMATION pi{};
  std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
  cmdBuf.push_back(0);
  if (!CreateProcessW(argv[programAt], cmdBuf.data(), nullptr, nullptr, !inherit.empty(),
                      EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS, (LPVOID)envBlock.data(),
                      cwd.empty() ? nullptr : cwd.c_str(), &si.StartupInfo, &pi))
    return fail(L"starting the program", GetLastError());
  DeleteProcThreadAttributeList(attrs);
  if (!AssignProcessToJobObject(job, pi.hProcess)) {
    DWORD err = GetLastError();
    TerminateProcess(pi.hProcess, SETUP_FAILED);
    return fail(L"joining the job", err);
  }
  for (HANDLE h : inherit) CloseHandle(h);
  say(L"running pid %lu in AppContainer %ls (%ls)%ls, network %ls%ls%ls", pi.dwProcessId, profile.c_str(), sidString(appSid).c_str(), lpac ? L" LPAC" : L"", net.c_str(),
      netLan ? L"+lan" : L"", appDlls ? L", app dlls" : L"");
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
  HANDLE adopter = nullptr;
  Embed embed{pi.hProcess, pi.dwProcessId, embedParent, embedClass, embedTitle, keepStyle, embedTimeoutMs};
  if (embedParent) adopter = CreateThread(nullptr, 0, adoptWindow, &embed, 0, nullptr);
  WaitForSingleObject(pi.hProcess, INFINITE);
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
  CloseHandle(job);
  // 120 and 121 are the launcher's own: a program that happens to exit with one must not read as
  // a sandbox that never started.
  return code == SETUP_FAILED || code == UNSUPPORTED ? 122 : (int)code;
}
