// Test-only, never installed. No Steam APIs or network. The app already supplies YOUGAME_BASE_DIR
// and YOUGAME_DATA. --base/--data may override those; --documents names the exact granted folder,
// e.g. the resolved documents/My Games/YG Steam Probe. This avoids AppContainer folder redirection.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define PATH_CAP 32768

static void report(const char *check, int allowed, DWORD error, DWORD bytes) {
  printf("{\"check\":\"%s\",\"allowed\":%s,\"error\":%lu,\"bytes\":%lu}\n",
         check, allowed ? "true" : "false", error, bytes);
  fflush(stdout);
}

static int join_path(wchar_t *out, const wchar_t *dir, const wchar_t *leaf) {
  return dir && *dir && swprintf_s(out, PATH_CAP, L"%ls\\%ls", dir, leaf) >= 0;
}

static int read_base(const wchar_t *base) {
  wchar_t file[PATH_CAP];
  char buf[64];
  DWORD bytes = 0, error;
  HANDLE h;
  BOOL ok;
  if (!join_path(file, base, L"halo3\\halo3.dll")) {
    report("base_read", 0, ERROR_BAD_PATHNAME, 0);
    return 0;
  }
  h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    report("base_read", 0, GetLastError(), 0);
    return 0;
  }
  ok = ReadFile(h, buf, (DWORD)sizeof buf, &bytes, NULL);
  error = ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(h);
  report("base_read", ok != FALSE, error, bytes);
  return ok && bytes == (DWORD)sizeof buf;
}

// CREATE_NEW never overwrites an existing file. Remove only the file this process created.
static int write_probe(const char *check, const wchar_t *dir, int expected) {
  wchar_t file[PATH_CAP], leaf[80];
  DWORD bytes = 0, error;
  HANDLE h;
  BOOL ok;
  if (swprintf_s(leaf, 80, L"yg-steam-probe-%lu.tmp", GetCurrentProcessId()) < 0 ||
      !join_path(file, dir, leaf)) {
    report(check, 0, ERROR_BAD_PATHNAME, 0);
    return 0;
  }
  h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    report(check, 0, error, 0);
    return !expected && error == ERROR_ACCESS_DENIED;
  }
  ok = WriteFile(h, "probe", 5, &bytes, NULL);
  error = ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(h);
  if (!DeleteFileW(file) && error == ERROR_SUCCESS) error = GetLastError();
  // A successful create already demonstrates write access, even if WriteFile later fails.
  report(check, 1, error, bytes);
  return expected && ok && bytes == 5 && error == ERROR_SUCCESS;
}

static int start_child(void) {
  wchar_t exe[PATH_CAP], cmd[PATH_CAP + 32];
  DWORD length = GetModuleFileNameW(NULL, exe, PATH_CAP), code = 1;
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  if (!length || length >= PATH_CAP ||
      swprintf_s(cmd, PATH_CAP + 32, L"\"%ls\" --child", exe) < 0) {
    report("spawn_child", 0, ERROR_BAD_PATHNAME, 0);
    return 0;
  }
  si.cb = (DWORD)sizeof si;
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  if (!CreateProcessW(exe, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
    const DWORD error = GetLastError();
    report("spawn_child", 0, error, 0);
    // Child restriction (default) or the active-process ceiling is an expected probe outcome.
    return error == ERROR_CHILD_PROCESS_BLOCKED || error == ERROR_NOT_ENOUGH_QUOTA;
  }
  report("spawn_child", 1, ERROR_SUCCESS, 0);
  if (WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0) {
    GetExitCodeProcess(pi.hProcess, &code);
  } else {
    // This exact process was created above; never enumerate or stop unrelated processes.
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 5000);
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return code == 0;
}

int wmain(int argc, wchar_t **argv) {
  wchar_t base_env[PATH_CAP], data_env[PATH_CAP], halo[PATH_CAP];
  const wchar_t *base = NULL, *data = NULL, *documents = NULL;
  int i, ok;
  DWORD n;
  if (argc == 2 && wcscmp(argv[1], L"--child") == 0) {
    report("child", 1, ERROR_SUCCESS, 0);
    return 0;
  }
  n = GetEnvironmentVariableW(L"YOUGAME_BASE_DIR", base_env, PATH_CAP);
  if (n && n < PATH_CAP) base = base_env;
  n = GetEnvironmentVariableW(L"YOUGAME_DATA", data_env, PATH_CAP);
  if (n && n < PATH_CAP) data = data_env;
  for (i = 1; i < argc; ++i) {
    if (i + 1 < argc && wcscmp(argv[i], L"--base") == 0) base = argv[++i];
    else if (i + 1 < argc && wcscmp(argv[i], L"--data") == 0) data = argv[++i];
    else if (i + 1 < argc && wcscmp(argv[i], L"--documents") == 0) documents = argv[++i];
    else { report("arguments", 0, ERROR_INVALID_PARAMETER, 0); return 2; }
  }
  ok = read_base(base);
  if (!join_path(halo, base, L"halo3")) halo[0] = L'\0';
  ok = write_probe("base_write", halo, 0) && ok;
  ok = write_probe("data_write", data, 1) && ok;
  ok = write_probe("documents_write", documents, 1) && ok;
  ok = start_child() && ok;
  return ok ? 0 : 1;
}
