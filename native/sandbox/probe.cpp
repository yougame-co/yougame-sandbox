// sandbox-probe: a test program (never shipped) that the containment test runs through
// yougame-sandbox with the same grants the app gives yougame-libretro, to show what a game that
// took over its emulator could and could not do. Each argument is one attempt; each prints one
// line on stdout: "<attempt> allowed <detail>" or "<attempt> denied <error>".
//
//   read=PATH  write=PATH  list=DIR  connect=HOST:PORT  spawn=PROGRAM  regwrite=HKCU\KEY
//   clipboard  screen  keys=MS  openprocess=PID  alloc=MB  token
//   udp=HOST:PORT    a datagram out (denied: the sandbox refused the send)
//   stun=HOST:PORT   a STUN binding request and its reply (UDP out and back in, as a direct link needs)
//   plantdll=PATH    copies System32's version.dll to PATH, then loads it: a program that writes its
//                    own library and runs it (Orca under --app-dlls still may not)
// tests/sandbox-containment.mjs runs it for the emulator, tests/orca-sandbox-containment.mjs for Orca.
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static void report(const std::string &what, bool allowed, const std::string &detail) {
  std::printf("%s %s %s\n", what.c_str(), allowed ? "allowed" : "denied", detail.c_str());
  std::fflush(stdout);
}
static std::string err(DWORD e) { return "error " + std::to_string(e); }

static void tryRead(const std::string &p) {
  HANDLE h = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE) return report("read " + p, false, err(GetLastError()));
  char buf[16];
  DWORD n = 0;
  BOOL ok = ReadFile(h, buf, sizeof buf, &n, nullptr);
  CloseHandle(h);
  report("read " + p, ok != 0, ok ? std::to_string(n) + " bytes" : err(GetLastError()));
}

static void tryWrite(const std::string &p) {
  HANDLE h = CreateFileA(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE) return report("write " + p, false, err(GetLastError()));
  DWORD n = 0;
  BOOL ok = WriteFile(h, "probe", 5, &n, nullptr);
  CloseHandle(h);
  report("write " + p, ok != 0, ok ? "wrote" : err(GetLastError()));
}

static void tryList(const std::string &dir) {
  WIN32_FIND_DATAA d;
  HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &d);
  if (h == INVALID_HANDLE_VALUE) return report("list " + dir, false, err(GetLastError()));
  int n = 0;
  do n++;
  while (FindNextFileA(h, &d));
  FindClose(h);
  report("list " + dir, true, std::to_string(n) + " entries");
}

static void tryConnect(const std::string &hostPort) {
  size_t colon = hostPort.rfind(':');
  std::string host = hostPort.substr(0, colon), port = hostPort.substr(colon + 1);
  addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return report("connect " + hostPort, false, "resolve " + err(WSAGetLastError()));
  SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (s == INVALID_SOCKET) {
    freeaddrinfo(res);
    return report("connect " + hostPort, false, "socket " + err(WSAGetLastError()));
  }
  // Non-blocking with a 3 s limit: a firewall that drops instead of refusing must not hang the probe.
  u_long nb = 1;
  ioctlsocket(s, FIONBIO, &nb);
  int r = connect(s, res->ai_addr, (int)res->ai_addrlen);
  bool ok = r == 0;
  int e = ok ? 0 : WSAGetLastError();
  if (!ok && e == WSAEWOULDBLOCK) {
    fd_set w, x;
    FD_ZERO(&w);
    FD_ZERO(&x);
    FD_SET(s, &w);
    FD_SET(s, &x);
    timeval tv{3, 0};
    int sel = select(0, nullptr, &w, &x, &tv);
    if (sel > 0 && FD_ISSET(s, &w)) ok = true;
    else if (sel == 0) e = WSAETIMEDOUT;
    else {
      int so = 0, len = sizeof so;
      getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so, &len);
      e = so;
    }
  }
  closesocket(s);
  freeaddrinfo(res);
  report("connect " + hostPort, ok, ok ? "connected" : err(e));
}

// Name resolution goes through the DNS client service, not the program's own socket, so it could
// work without internetClient and carry data out in the names it asks for (a slow covert channel).
// Ask for a name that exists: inside an AppContainer without the network, Windows answers "no
// such name" itself and sends nothing (measured with pktmon, docs/DESKTOP_SANDBOX.md).
static void tryDns(const std::string &host) {
  addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_UNSPEC;
  int r = getaddrinfo(host.c_str(), nullptr, &hints, &res);
  int e = r == 0 ? 0 : WSAGetLastError();
  if (res) freeaddrinfo(res);
  if (r == 0) return report("dns " + host, true, "resolved");
  report("dns " + host, false, e == WSAHOST_NOT_FOUND ? "no such name" : err(e));
}

static bool resolveUdp(const std::string &hostPort, addrinfo **res) {
  size_t colon = hostPort.rfind(':');
  if (colon == std::string::npos) return false;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  return getaddrinfo(hostPort.substr(0, colon).c_str(), hostPort.substr(colon + 1).c_str(), &hints, res) == 0 && *res;
}

static void tryUdp(const std::string &hostPort) {
  addrinfo *res = nullptr;
  if (!resolveUdp(hostPort, &res)) return report("udp " + hostPort, false, "resolve " + err(WSAGetLastError()));
  SOCKET s = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
  int n = sendto(s, "x", 1, 0, res->ai_addr, (int)res->ai_addrlen);
  int e = n == 1 ? 0 : WSAGetLastError();
  closesocket(s);
  freeaddrinfo(res);
  report("udp " + hostPort, n == 1, n == 1 ? "sent" : err(e));
}

static void tryStun(const std::string &hostPort) {
  addrinfo *res = nullptr;
  if (!resolveUdp(hostPort, &res)) return report("stun " + hostPort, false, "resolve " + err(WSAGetLastError()));
  SOCKET s = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
  unsigned char req[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
  for (int i = 8; i < 20; ++i) req[i] = (unsigned char)(GetTickCount64() * 31 + i * 17);
  DWORD timeout = 3000;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);
  int n = sendto(s, (const char *)req, sizeof req, 0, res->ai_addr, (int)res->ai_addrlen);
  int e = n == (int)sizeof req ? 0 : WSAGetLastError();
  unsigned char resp[512];
  int r = n == (int)sizeof req ? recv(s, (char *)resp, sizeof resp, 0) : -1;
  int e2 = r < 0 ? WSAGetLastError() : 0;
  closesocket(s);
  freeaddrinfo(res);
  bool ok = r >= 20 && resp[0] == 0x01 && resp[1] == 0x01 && std::memcmp(resp + 8, req + 8, 12) == 0;
  report("stun " + hostPort, ok, ok ? "binding success" : e ? "send " + err(e) : "reply " + err(e2));
}

static void tryPlantDll(const std::string &p) {
  char sys[MAX_PATH];
  GetSystemDirectoryA(sys, MAX_PATH);
  std::string from = std::string(sys) + "\\version.dll";
  if (!CopyFileA(from.c_str(), p.c_str(), FALSE)) return report("plantdll " + p, false, "copy " + err(GetLastError()));
  HMODULE m = LoadLibraryExA(p.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
  DWORD e = m ? 0 : GetLastError();
  if (m) FreeLibrary(m);
  DeleteFileA(p.c_str());
  report("plantdll " + p, m != nullptr, m ? "written and loaded" : "written, load " + err(e));
}

static void trySpawn(const std::string &program) {
  STARTUPINFOA si{sizeof si};
  PROCESS_INFORMATION pi{};
  std::string cmd = "\"" + program + "\" /c exit 0";
  std::vector<char> buf(cmd.begin(), cmd.end());
  buf.push_back(0);
  if (!CreateProcessA(program.c_str(), buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return report("spawn " + program, false, err(GetLastError()));
  TerminateProcess(pi.hProcess, 0);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  report("spawn " + program, true, "started");
}

static void tryRegWrite(const std::string &key) {
  // HKCU\<path>: a value written and removed again.
  std::string sub = key.substr(key.find('\\') + 1);
  HKEY h;
  LSTATUS s = RegOpenKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, KEY_SET_VALUE, &h);
  if (s != ERROR_SUCCESS) return report("regwrite " + key, false, err((DWORD)s));
  s = RegSetValueExA(h, "YouGameSandboxProbe", 0, REG_SZ, (const BYTE *)"x", 2);
  if (s == ERROR_SUCCESS) RegDeleteValueA(h, "YouGameSandboxProbe");
  RegCloseKey(h);
  report("regwrite " + key, s == ERROR_SUCCESS, s == ERROR_SUCCESS ? "written" : err((DWORD)s));
}

static void tryClipboard() {
  if (!OpenClipboard(nullptr)) return report("clipboard", false, err(GetLastError()));
  HANDLE h = GetClipboardData(CF_UNICODETEXT);
  DWORD e = GetLastError();
  CloseClipboard();
  report("clipboard", h != nullptr, h ? "read text" : err(e));
}

// The whole screen through GDI: "allowed" only when the pixels are not all black.
static void tryScreen() {
  HDC screen = GetDC(nullptr);
  if (!screen) return report("screen", false, err(GetLastError()));
  int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
  HDC mem = CreateCompatibleDC(screen);
  BITMAPINFO bi{};
  bi.bmiHeader.biSize = sizeof bi.bmiHeader;
  bi.bmiHeader.biWidth = w;
  bi.bmiHeader.biHeight = -h;
  bi.bmiHeader.biPlanes = 1;
  bi.bmiHeader.biBitCount = 32;
  void *bits = nullptr;
  HBITMAP bmp = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
  HGDIOBJ old = SelectObject(mem, bmp);
  BOOL ok = BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY);
  DWORD e = GetLastError();
  size_t lit = 0;
  if (ok && bits)
    for (size_t i = 0; i < (size_t)w * h; i += 97) lit += (((unsigned *)bits)[i] & 0xffffff) != 0;
  SelectObject(mem, old);
  DeleteObject(bmp);
  DeleteDC(mem);
  ReleaseDC(nullptr, screen);
  if (!ok) return report("screen", false, err(e));
  report("screen", lit > 0, std::to_string(lit) + " lit samples of " + std::to_string((size_t)w * h / 97));
}

// Keys pressed elsewhere while this process is in the background: a low-level hook and
// GetAsyncKeyState polling, for `ms` milliseconds. The test presses F13 meanwhile.
static int hookHits = 0;
static LRESULT CALLBACK llHook(int code, WPARAM wp, LPARAM lp) {
  if (code == HC_ACTION && ((KBDLLHOOKSTRUCT *)lp)->vkCode == VK_F13) hookHits++;
  return CallNextHookEx(nullptr, code, wp, lp);
}
static void tryKeys(int ms) {
  HHOOK hook = SetWindowsHookExA(WH_KEYBOARD_LL, llHook, GetModuleHandleA(nullptr), 0);
  DWORD hookErr = hook ? 0 : GetLastError();
  int polled = 0;
  ULONGLONG end = GetTickCount64() + ms;
  while (GetTickCount64() < end) {
    MSG m;
    while (PeekMessageA(&m, nullptr, 0, 0, PM_REMOVE)) DispatchMessageA(&m);
    if (GetAsyncKeyState(VK_F13) & 0x8001) polled++;
    Sleep(5);
  }
  if (hook) UnhookWindowsHookEx(hook);
  report("keyhook", hook && hookHits > 0, hook ? std::to_string(hookHits) + " F13 events" : "install " + err(hookErr));
  report("keypoll", polled > 0, std::to_string(polled) + " F13 samples");
}

static void tryOpenProcess(DWORD pid) {
  HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!h) return report("openprocess " + std::to_string(pid), false, err(GetLastError()));
  CloseHandle(h);
  report("openprocess " + std::to_string(pid), true, "opened for reading");
}

// Commit `mb` megabytes in 64 MB pieces: "denied" when the job's memory limit stops it first.
static void tryAlloc(int mb) {
  std::vector<void *> blocks;
  int got = 0;
  for (; got < mb; got += 64) {
    void *b = VirtualAlloc(nullptr, 64ull << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!b) break;
    blocks.push_back(b);
  }
  DWORD e = GetLastError();
  for (void *b : blocks) VirtualFree(b, 0, MEM_RELEASE);
  report("alloc " + std::to_string(mb) + "MB", got >= mb, got >= mb ? "committed" : "stopped at " + std::to_string(got) + " MB, " + err(e));
}

static void tryToken() {
  HANDLE t;
  OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t);
  DWORD isAc = 0, len = 0;
  GetTokenInformation(t, TokenIsAppContainer, &isAc, sizeof isAc, &len);
  char buf[256];
  DWORD il = 0;
  if (GetTokenInformation(t, TokenIntegrityLevel, buf, sizeof buf, &len)) {
    auto *ml = (TOKEN_MANDATORY_LABEL *)buf;
    il = *GetSidSubAuthority(ml->Label.Sid, *GetSidSubAuthorityCount(ml->Label.Sid) - 1);
  }
  CloseHandle(t);
  PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strict{};
  GetProcessMitigationPolicy(GetCurrentProcess(), ProcessStrictHandleCheckPolicy, &strict, sizeof strict);
  report("strict-handles", strict.RaiseExceptionOnInvalidHandleReference != 0, strict.HandleExceptionsPermanentlyEnabled ? "permanent" : "-");
  report("token", true, std::string("appcontainer=") + (isAc ? "yes" : "no") + " integrity=0x" + [&] { char b[16]; std::snprintf(b, sizeof b, "%lx", il); return std::string(b); }());
}

// A topmost window anywhere on screen (a 1-pixel tool window at the screen's corner, shown for 200 ms):
// what a taken-over program would draw a fake prompt with.
static void tryTopmost() {
  HWND w = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"STATIC", L"AGENT TEST containment probe",
                           WS_POPUP, 0, 0, 1, 1, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
  if (!w) return report("topmost", false, "create " + err(GetLastError()));
  ShowWindow(w, SW_SHOWNOACTIVATE);
  ULONGLONG end = GetTickCount64() + 200;
  while (GetTickCount64() < end) {
    MSG m;
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
    Sleep(10);
  }
  const bool shown = IsWindowVisible(w) && (GetWindowLongPtrW(w, GWL_EXSTYLE) & WS_EX_TOPMOST);
  DestroyWindow(w);
  report("topmost", shown, shown ? "a topmost window was shown" : "not shown topmost");
}

// The title of another process's window (the test's hidden decoy, decoywin): read, or not.
static std::wstring g_title;
static bool g_found = false;
static BOOL CALLBACK findTitle(HWND h, LPARAM) {
  DWORD pid = 0;
  GetWindowThreadProcessId(h, &pid);
  if (pid == GetCurrentProcessId()) return TRUE;
  wchar_t buf[256];
  if (GetWindowTextW(h, buf, 256) && g_title == buf) {
    g_found = true;
    return FALSE;
  }
  return TRUE;
}
static void tryWinTitle(const std::string &title) {
  g_title.assign(title.begin(), title.end());
  g_found = false;
  EnumWindows(findTitle, 0);
  report("wintitle " + title, g_found, g_found ? "read another process's window title" : "not found");
}

// A hidden window titled `title` held for 60 s (the decoy wintitle looks for; run outside the sandbox).
static void holdDecoy(const std::string &title) {
  std::wstring t(title.begin(), title.end());
  HWND w = CreateWindowExW(0, L"STATIC", t.c_str(), WS_OVERLAPPED, 0, 0, 1, 1, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
  report("decoywin", w != nullptr, w ? "holding" : err(GetLastError()));
  std::fflush(stdout);
  ULONGLONG end = GetTickCount64() + 60000;
  while (w && GetTickCount64() < end) {
    MSG m;
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
    Sleep(20);
  }
  if (w) DestroyWindow(w);
}

int main(int argc, char **argv) {
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i], v;
    size_t eq = a.find('=');
    if (eq != std::string::npos) v = a.substr(eq + 1), a = a.substr(0, eq);
    if (a == "read") tryRead(v);
    else if (a == "write") tryWrite(v);
    else if (a == "list") tryList(v);
    else if (a == "connect") tryConnect(v);
    else if (a == "dns") tryDns(v);
    else if (a == "spawn") trySpawn(v);
    else if (a == "regwrite") tryRegWrite(v);
    else if (a == "clipboard") tryClipboard();
    else if (a == "screen") tryScreen();
    else if (a == "keys") tryKeys(std::atoi(v.c_str()));
    else if (a == "openprocess") tryOpenProcess((DWORD)std::strtoul(v.c_str(), nullptr, 10));
    else if (a == "token") tryToken();
    else if (a == "alloc") tryAlloc(std::atoi(v.c_str()));
    else if (a == "udp") tryUdp(v);
    else if (a == "stun") tryStun(v);
    else if (a == "plantdll") tryPlantDll(v);
    else if (a == "sleep") Sleep((DWORD)std::strtoul(v.c_str(), nullptr, 10)), report("sleep", true, "slept");
    else if (a == "topmost") tryTopmost();
    else if (a == "wintitle") tryWinTitle(v);
    else if (a == "decoywin") holdDecoy(v);
    else report(a, false, "unknown probe");
  }
  WSACleanup();
  return 0;
}
