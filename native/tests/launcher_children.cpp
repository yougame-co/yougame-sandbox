// Windows integration tests: exercise the actual launcher, token and kernel job limits.
// Include the implementation, as launcher_embed.cpp does; assertions stay enabled in Release.
#undef NDEBUG
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define wmain sandboxLauncherMain
#include "../sandbox/launcher.cpp"
#undef wmain
#include <cassert>
#include <cstdlib>

static std::wstring packageSid() {
  HANDLE token = nullptr;
  assert(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
  DWORD size = 0, container = 0;
  assert(GetTokenInformation(token, TokenIsAppContainer, &container, sizeof container, &size));
  assert(container == 1);
  GetTokenInformation(token, TokenAppContainerSid, nullptr, 0, &size);
  std::vector<char> info(size);
  assert(GetTokenInformation(token, TokenAppContainerSid, info.data(), size, &size));
  const auto sid = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(info.data());
  const std::wstring result = sidString(sid->TokenAppContainer);
  assert(!result.empty());
  CloseHandle(token);
  return result;
}

static void checkJob(DWORD helpers, DWORD parent = 0) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job{};
  assert(QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &job, sizeof job, nullptr));
  const DWORD required = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
      JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  assert((job.BasicLimitInformation.LimitFlags & required) == required);
  assert(!(job.BasicLimitInformation.LimitFlags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)));
  assert(job.BasicLimitInformation.ActiveProcessLimit == 1 + helpers);
  assert(job.ProcessMemoryLimit == 512ull * 1024 * 1024);
  // Query the current job's PID list, rather than merely asking whether the child has *a* job.
  alignas(JOBOBJECT_BASIC_PROCESS_ID_LIST) char storage[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 8 * sizeof(ULONG_PTR)]{};
  auto ids = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(storage);
  assert(QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, ids, sizeof storage, nullptr));
  bool selfFound = false, parentFound = !parent;
  for (DWORD i = 0; i < ids->NumberOfProcessIdsInList; ++i) {
    selfFound = selfFound || ids->ProcessIdList[i] == GetCurrentProcessId();
    parentFound = parentFound || ids->ProcessIdList[i] == parent;
  }
  assert(selfFound && parentFound);
}

static BOOL spawn(const std::wstring &exe, const std::wstring &args, DWORD flags, PROCESS_INFORMATION &pi) {
  std::wstring cmd = quote(exe) + L" " + args;
  STARTUPINFOW si{};
  si.cb = sizeof si;
  return CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, flags, nullptr, nullptr, &si, &pi);
}

static BOOL spawnSelf(const std::wstring &args, DWORD flags, PROCESS_INFORMATION &pi) {
  wchar_t exe[32768];
  const DWORD n = GetModuleFileNameW(nullptr, exe, 32768);
  assert(n && n < 32768);
  return spawn(exe, args, flags, pi);
}

static int inside(DWORD helpers) {
  checkJob(helpers);
  const std::wstring sid = packageSid();
  const std::wstring args = L"--child " + std::to_wstring(helpers) + L" " + sid + L" " + std::to_wstring(GetCurrentProcessId());
  std::vector<PROCESS_INFORMATION> children;
  // Keep every child suspended until the ceiling has been tested; no exit/scheduling race.
  for (DWORD i = 0; i < helpers; ++i) {
    PROCESS_INFORMATION child{};
    assert(spawnSelf(args, CREATE_SUSPENDED, child));
    children.push_back(child);
  }
  PROCESS_INFORMATION refused{};
  assert(!spawnSelf(args, CREATE_SUSPENDED, refused));
  const DWORD error = GetLastError();
  assert(helpers ? error == ERROR_NOT_ENOUGH_QUOTA : error == ERROR_CHILD_PROCESS_BLOCKED);
  assert(!spawnSelf(args, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, refused));
  for (auto &child : children) {
    assert(ResumeThread(child.hThread) != static_cast<DWORD>(-1));
    assert(WaitForSingleObject(child.hProcess, 10000) == WAIT_OBJECT_0);
    DWORD code = 1;
    assert(GetExitCodeProcess(child.hProcess, &code) && code == 0);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
  }
  std::printf("children=%lu: allowed %lu, next refused (%lu), no breakaway\n", helpers, helpers, error);
  return 0;
}

static int insideWrite(const std::wstring &data, const std::wstring &documents) {
  wchar_t exe[32768];
  const DWORD n = GetModuleFileNameW(nullptr, exe, 32768);
  assert(n && n < 32768);
  checkJob(1);
  for (const auto &folder : {data, documents}) {
    const std::wstring subdir = folder + L"\\nested";
    const std::wstring copy = subdir + L"\\written.exe";
    assert(CreateDirectoryW(subdir.c_str(), nullptr));
    assert(CopyFileW(exe, copy.c_str(), TRUE));
    // Test the ACL directly as well as CreateProcess: image mitigations cannot mask a bad grant.
    HANDLE file = CreateFileW(copy.c_str(), FILE_EXECUTE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    assert(file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
    PROCESS_INFORMATION refused{};
    assert(!spawn(copy, L"--child 1 " + packageSid() + L" " + std::to_wstring(GetCurrentProcessId()), CREATE_SUSPENDED, refused));
    assert(GetLastError() == ERROR_ACCESS_DENIED);
    assert(DeleteFileW(copy.c_str()));
    assert(RemoveDirectoryW(subdir.c_str()));
  }
  // Uses the identical probe/arguments from the executable build grant; must succeed.
  return inside(1);
}

static int runLauncher(std::vector<std::wstring> args) {
  std::vector<wchar_t*> argv;
  for (auto &arg : args) argv.push_back(arg.data());
  return sandboxLauncherMain(static_cast<int>(argv.size()), argv.data());
}

int wmain(int argc, wchar_t **argv) {
  if (argc == 5 && std::wstring(argv[1]) == L"--child") {
    const DWORD helpers = static_cast<DWORD>(_wtoi(argv[2]));
    assert(packageSid() == argv[3]);
    checkJob(helpers, static_cast<DWORD>(_wtoi(argv[4])));
    return 0;
  }
  if (argc == 4 && std::wstring(argv[1]) == L"--inside-write") return insideWrite(argv[2], argv[3]);
  if (argc == 3 && std::wstring(argv[1]) == L"--inside") return inside(static_cast<DWORD>(_wtoi(argv[2])));
  assert(argc == 2);
  if (std::wstring(argv[1]) == L"options") {
    assert(runLauncher({L"test", L"--child-processes"}) == SETUP_FAILED);
    for (const wchar_t *value : {L"", L"0", L"3", L"-1", L"+1", L"01", L"1.5", L"1x", L"x", L"999999999999999999999999"})
      assert(runLauncher({L"test", L"--child-processes", value}) == SETUP_FAILED);
    assert(runLauncher({L"test", L"--child-processes", L"1", L"--child-processes", L"2"}) == SETUP_FAILED);
    // A valid grant-only command would return 0. These must be refused before any profile/grant.
    {
      const wchar_t *mode = L"--links-helper";
      for (const wchar_t *count : {L"1", L"2"}) {
        assert(runLauncher({L"test", mode, L"--child-processes", count, L"--grant-only", L"--profile", L"YouGame.Children.Forbidden"}) == SETUP_FAILED);
        assert(runLauncher({L"test", L"--child-processes", count, mode, L"--grant-only", L"--profile", L"YouGame.Children.Forbidden"}) == SETUP_FAILED);
      }
    }
    return 0;
  }
  const bool writeTest = std::wstring(argv[1]) == L"write-execute";
  assert(writeTest || std::wstring(argv[1]) == L"0" || std::wstring(argv[1]) == L"1" || std::wstring(argv[1]) == L"2");
  wchar_t temp[32768], exe[32768];
  const DWORD n = GetTempPathW(32768, temp);
  assert(n && n < 32768);
  const DWORD m = GetModuleFileNameW(nullptr, exe, 32768);
  assert(m && m < 32768);
  const std::wstring unique = std::to_wstring(GetCurrentProcessId()) + L"." + argv[1];
  const std::wstring dir = std::wstring(temp) + L"yg-children-" + unique;
  const std::wstring build = dir + L"\\build";
  const std::wstring data = dir + L"\\data";
  const std::wstring documents = dir + L"\\documents";
  const std::wstring copy = build + L"\\children.exe";
  const std::wstring profile = L"YouGame.Children." + unique;
  assert(CreateDirectoryW(dir.c_str(), nullptr));
  assert(CreateDirectoryW(build.c_str(), nullptr));
  assert(CopyFileW(exe, copy.c_str(), TRUE));
  std::vector<std::wstring> args{L"test", L"--profile", profile, L"--exec", build, L"--cwd", build, L"--max-memory", L"512"};
  int code = 0;
  if (writeTest) {
    assert(CreateDirectoryW(data.c_str(), nullptr));
    assert(CreateDirectoryW(documents.c_str(), nullptr));
    const std::vector<std::wstring> grants{L"test", L"--profile", profile, L"--grant-only", L"--write", data, L"--write", documents};
    args.insert(args.end(), {L"--child-processes", L"1", L"--write", data, L"--write", documents,
        L"--", copy, L"--inside-write", data, documents});
    for (int legacy = 0; legacy < 2; ++legacy) {
      // Cover both a fresh profile and a previous non-opted-in launch's executable write ACEs.
      if (legacy) assert(runLauncher(grants) == 0);
      code = runLauncher(args);
      assert(code == 0);
      std::printf("write-execute: %s grants; data/Documents copies denied (5), build child allowed\n", legacy ? "legacy" : "fresh");
    }
    assert(RemoveDirectoryW(data.c_str()));
    assert(RemoveDirectoryW(documents.c_str()));
  } else {
    if (std::wstring(argv[1]) != L"0") args.insert(args.end(), {L"--child-processes", argv[1]});
    args.insert(args.end(), {L"--", copy, L"--inside", argv[1]});
    code = runLauncher(args);
  }
  PSID profileSid = nullptr;
  assert(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(profile.c_str(), &profileSid)));
  PWSTR storage = nullptr;
  const std::wstring profileSidText = sidString(profileSid);
  assert(SUCCEEDED(GetAppContainerFolderPath(profileSidText.c_str(), &storage)));
  assert(SUCCEEDED(DeleteAppContainerProfile(profile.c_str())));
  assert(GetFileAttributesW(storage) == INVALID_FILE_ATTRIBUTES);
  const DWORD storageError = GetLastError();
  assert(storageError == ERROR_FILE_NOT_FOUND || storageError == ERROR_PATH_NOT_FOUND);
  std::printf("profile cleanup: deleted %ls; storage absent\n", profile.c_str());
  CoTaskMemFree(storage);
  FreeSid(profileSid);
  assert(DeleteFileW(copy.c_str()));
  assert(RemoveDirectoryW(build.c_str()));
  assert(RemoveDirectoryW(dir.c_str()));
  assert(code == 0);
  return code;
}
