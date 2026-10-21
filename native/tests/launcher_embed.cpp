// Windows only. Exercise the launcher's actual adopter, including its styles and log output.
// Seed the stale error after the style API, immediately before the launcher's SetLastError /
// SetParent sequence. No sandbox/profile or elevation needed.
// From the repository root on Windows with the installed MSVC toolchain:
//   cmake -S desktop/native/sandbox -B desktop/native/build-sandbox-x64 -A x64
//   cmake --build desktop/native/build-sandbox-x64 --config Release --target yougame-sandbox launcher-embed-test
//   ctest --test-dir desktop/native/build-sandbox-x64 -C Release -R "^launcher-embed$" --output-on-failure
#undef NDEBUG
// tmpfile is scoped to this test; no fixture path or production file is opened.
#define _CRT_SECURE_NO_WARNINGS
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

static HWND previousParent;
static DWORD parentingError;
static unsigned noParentAttempts, parentCalls, styleWrites;
static bool leaveOnDesktop;
static LONG_PTR WINAPI seededSetWindowLongPtrW(HWND window, int index, LONG_PTR value) {
  if (index == GWL_STYLE) ++styleWrites;
  LONG_PTR previous = ::SetWindowLongPtrW(window, index, value);
  SetLastError(ERROR_INVALID_PARAMETER);
  return previous;
}
static HWND WINAPI seededSetParent(HWND child, HWND parent) {
  ++parentCalls;
  if (leaveOnDesktop || noParentAttempts) {
    if (noParentAttempts) --noParentAttempts;
    previousParent = nullptr;
    parentingError = ERROR_SUCCESS;
    SetLastError(ERROR_SUCCESS);
    return nullptr;
  }
  previousParent = ::SetParent(child, parent);
  parentingError = GetLastError();
  return previousParent;
}

// Include rather than copy the implementation; the production entry point is never run.
#define SetParent seededSetParent
#define SetWindowLongPtrW seededSetWindowLongPtrW
#define wmain sandboxLauncherMain
#include "../sandbox/launcher.cpp"
#undef wmain
#undef SetParent
#undef SetWindowLongPtrW
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <io.h>

static std::string runAdopter(Embed &e) {
  FILE *capture = std::tmpfile();
  assert(capture);
  std::fflush(stderr);
  int saved = _dup(_fileno(stderr));
  assert(saved >= 0);
  assert(_dup2(_fileno(capture), _fileno(stderr)) == 0);
  // tmpfile() is binary and _dup2 hands that mode to stderr, where the CRT's wide output would be
  // raw UTF-16; text mode writes the launcher's lines as the app's pipe receives them.
  assert(_setmode(_fileno(stderr), _O_TEXT) != -1);
  assert(adoptWindow(&e) == 0);
  std::fflush(stderr);
  assert(_dup2(saved, _fileno(stderr)) == 0);
  _close(saved);
  std::rewind(capture);
  std::string log;
  char buf[512];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), capture)) != 0) log.append(buf, n);
  assert(!std::ferror(capture));
  std::fclose(capture);
  return log;
}

int main() {
  const wchar_t *cls = L"YouGameLauncherEmbedTest";
  WNDCLASSW wc{};
  wc.lpfnWndProc = DefWindowProcW;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.lpszClassName = cls;
  assert(RegisterClassW(&wc));
  // Hidden windows on this thread: the adopter can change them without a UI message pump.
  HWND parent = CreateWindowExW(0, cls, L"parent", WS_OVERLAPPEDWINDOW,
                               0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);
  assert(parent);
  HANDLE alive = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  assert(alive);
  for (bool keepStyle : {false, true}) {
    HWND child = CreateWindowExW(WS_EX_TOOLWINDOW, cls, L"game",
        WS_POPUP | WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX |
        WS_SYSMENU | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
        0, 0, 50, 50, nullptr, nullptr, wc.hInstance, nullptr);
    assert(child && GetParent(child) == nullptr);
    LONG_PTR style = GetWindowLongPtrW(child, GWL_STYLE);
    LONG_PTR ex = GetWindowLongPtrW(child, GWL_EXSTYLE);
    Embed e{alive, GetCurrentProcessId(), parent, cls, L"game"};
    e.keepStyle = keepStyle;
    e.timeoutMs = 250;
    std::string log = runAdopter(e);
    // SetParent hands back the old parent: the desktop window for a top-level window on the user's
    // desktop (seen on Windows 11, 0.13.0 gate), null elsewhere. Success is the new parent below.
    assert((previousParent == nullptr || previousParent == GetDesktopWindow()) &&
           parentingError == ERROR_SUCCESS);
    assert(GetAncestor(child, GA_PARENT) == parent);
    LONG_PTR expected = keepStyle ? (style & ~WS_POPUP) | WS_CHILD :
        (style & ~(WS_POPUP | WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX |
                   WS_MAXIMIZEBOX | WS_SYSMENU)) | WS_CHILD | WS_CLIPSIBLINGS;
    assert(GetWindowLongPtrW(child, GWL_STYLE) == expected);
    // Windows keeps WS_EX_WINDOWEDGE in step with the caption and frame bits, so it goes when they
    // are stripped; the adopter itself only ever adds WS_EX_NOPARENTNOTIFY.
    LONG_PTR exNow = GetWindowLongPtrW(child, GWL_EXSTYLE);
    LONG_PTR exWant = keepStyle ? ex | WS_EX_NOPARENTNOTIFY : ex;
    if ((exNow & ~WS_EX_WINDOWEDGE) != (exWant & ~WS_EX_WINDOWEDGE))
      fprintf(stderr, "keepStyle=%d exstyle 0x%llx, expected 0x%llx (before 0x%llx)\n", (int)keepStyle,
              (unsigned long long)exNow, (unsigned long long)exWant, (unsigned long long)ex);
    assert((exNow & ~WS_EX_WINDOWEDGE) == (exWant & ~WS_EX_WINDOWEDGE));
    assert(log.find("sandbox: adopted the program's window into the app's window") != std::string::npos);
    assert(log.find("could not adopt") == std::string::npos);
    assert(log.find("no window to adopt") == std::string::npos);
    assert(DestroyWindow(child));
  }
  for (bool keepStyle : {false, true}) {
    HWND pending = CreateWindowExW(0, cls, L"game", WS_POPUP,
        0, 0, 50, 50, nullptr, nullptr, wc.hInstance, nullptr);
    assert(pending);
    Embed retry{alive, GetCurrentProcessId(), parent, cls, L"game"};
    retry.keepStyle = keepStyle;
    retry.timeoutMs = 250;
    noParentAttempts = 1;
    parentCalls = styleWrites = 0;
    std::string retryLog = runAdopter(retry);
    if (GetAncestor(pending, GA_PARENT) != parent) {
      // The unpatched launcher exits cleanly with a distinctive expected-red result.
      std::puts("RETRY_REGRESSION: one NULL/zero-error result was treated as final");
      DestroyWindow(pending); DestroyWindow(parent); CloseHandle(alive);
      UnregisterClassW(cls, wc.hInstance);
      return 42;
    }
    assert(noParentAttempts == 0 && parentCalls == 2 && styleWrites == 1);
    assert(retryLog.find("sandbox: adopted") != std::string::npos);
    assert(retryLog.find("could not adopt") == std::string::npos);
    assert(DestroyWindow(pending));
  }
  for (bool keepStyle : {false, true}) {
    HWND pending = CreateWindowExW(0, cls, L"game", WS_POPUP,
        0, 0, 50, 50, nullptr, nullptr, wc.hInstance, nullptr);
    assert(pending);
    Embed retry{alive, GetCurrentProcessId(), parent, cls, L"game"};
    retry.keepStyle = keepStyle;
    retry.timeoutMs = 250;
    leaveOnDesktop = true;
    parentCalls = styleWrites = 0;
    std::string retryLog = runAdopter(retry);
    leaveOnDesktop = false;
    assert(parentCalls > 1 && styleWrites == 1);
    assert(GetAncestor(pending, GA_PARENT) == GetDesktopWindow());
    assert(GetParent(pending) == GetDesktopWindow()); // not a successful native handshake
    assert(!IsChild(parent, pending));
    assert(retryLog.find("sandbox: adopted") == std::string::npos);
    assert(retryLog.find("could not adopt the program's window (error " +
                         std::to_string(ERROR_INVALID_STATE) + ")") != std::string::npos);
    assert(retryLog.find("no window to adopt") == std::string::npos);
    assert(DestroyWindow(pending));
  }
  HWND child = CreateWindowExW(0, cls, L"game", WS_POPUP,
                              0, 0, 50, 50, nullptr, nullptr, wc.hInstance, nullptr);
  assert(child);
  // Destroy last, after creating the child, so the invalid parent handle cannot be reused.
  assert(DestroyWindow(parent));
  assert(!IsWindow(parent));
  Embed e{alive, GetCurrentProcessId(), parent, cls, L"game"};
  e.timeoutMs = 250;
  std::string log = runAdopter(e);
  assert(previousParent == nullptr && parentingError == ERROR_INVALID_WINDOW_HANDLE);
  assert(GetAncestor(child, GA_PARENT) != parent);
  assert(log.find("sandbox: could not adopt the program's window (error " +
                  std::to_string(parentingError) + ")") != std::string::npos);
  assert(log.find("sandbox: adopted") == std::string::npos);
  assert(log.find("no window to adopt") == std::string::npos);
  assert(DestroyWindow(child));
  assert(CloseHandle(alive));
  assert(UnregisterClassW(cls, wc.hInstance));
  std::puts("launcher embed ok");
}
