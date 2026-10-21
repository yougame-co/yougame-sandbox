// Persistent, package-scoped home-network guard. Only the explicit install/remove modes write
// machine policy. Launch/status read the marker and, when the BFE ACL permits it, the filter keys.
#pragma once
#include <initguid.h>
#include <fwpmu.h>
#include <rpc.h>
#include <netfw.h>
#include <bcrypt.h>
#include <array>

static constexpr bool LAN_IN_JAIL = false;
static constexpr DWORD NET_GUARD_VERSION = 2;
static constexpr int NET_GUARD_MISSING = 123; // 120/121 and child remapping (122) already exist.
// Fixed ownership and key namespace; never use a dynamic WFP session for these objects.
static const GUID NET_GUARD_PROVIDER = {0x68f14a24, 0x7252, 0x4aad, {0xa5, 0xee, 0x63, 0x18, 0x25, 0xd0, 0x53, 0xcf}};
static const GUID NET_GUARD_SUBLAYER = {0x2a6eaa9b, 0xa432, 0x4ee8, {0xa3, 0xf3, 0x96, 0xeb, 0x5a, 0xba, 0x20, 0x18}};
static const GUID NET_GUARD_FILTER_NAMESPACE = {0x7efa2f0a, 0x89b3, 0x493f, {0x82, 0x2a, 0x79, 0xd6, 0xe3, 0xf3, 0x44, 0xb2}};
static const std::array<FWP_V4_ADDR_AND_MASK, 7> NET_GUARD_V4{{
  {0x0a000000u, 0xff000000u}, // 10/8
  {0xac100000u, 0xfff00000u}, // 172.16/12
  {0xc0a80000u, 0xffff0000u}, // 192.168/16
  {0xa9fe0000u, 0xffff0000u}, // 169.254/16
  {0x64400000u, 0xffc00000u}, // 100.64/10
  {0xe0000000u, 0xf0000000u}, // 224/4
  {0xffffffffu, 0xffffffffu}, // limited broadcast
}};
static std::array<FWP_V6_ADDR_AND_MASK, 5> netGuardV6() {
  std::array<FWP_V6_ADDR_AND_MASK, 5> ranges{};
  ranges[0].addr[0] = 0xfc; ranges[0].prefixLength = 7;
  ranges[1].addr[0] = 0xfe; ranges[1].addr[1] = 0x80; ranges[1].prefixLength = 10;
  ranges[2].addr[0] = 0xfe; ranges[2].addr[1] = 0xc0; ranges[2].prefixLength = 10;
  ranges[3].addr[1] = 0x64; ranges[3].addr[2] = 0xff; ranges[3].addr[3] = 0x9b;
  ranges[3].addr[5] = 1; ranges[3].prefixLength = 48; // 64:ff9b:1::/48
  ranges[4].addr[0] = 0xff; ranges[4].prefixLength = 8; // ff00::/8
  return ranges;
}

// Hash the fixed namespace, package SID and ordinal: keys survive launches, repairs and app
// updates, but separate fixture profiles never replace the shared app profile's filters.
static DWORD netGuardKey(PSID package, UINT32 ordinal, GUID &key) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  NTSTATUS result = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (result >= 0) result = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
  if (result >= 0) result = BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<GUID *>(&NET_GUARD_FILTER_NAMESPACE)), sizeof(GUID), 0);
  if (result >= 0) result = BCryptHashData(hash, static_cast<PUCHAR>(package), GetLengthSid(package), 0);
  if (result >= 0) result = BCryptHashData(hash, reinterpret_cast<PUCHAR>(&ordinal), sizeof ordinal, 0);
  std::array<UCHAR, 32> digest{};
  if (result >= 0) result = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (result < 0) return ERROR_GEN_FAILURE;
  memcpy(&key, digest.data(), sizeof key);
  key.Data3 = static_cast<USHORT>((key.Data3 & 0x0fff) | 0x5000);
  key.Data4[0] = static_cast<UCHAR>((key.Data4[0] & 0x3f) | 0x80);
  return ERROR_SUCCESS;
}

// Also cover IPv4-mapped addresses at v6 layers, without adding loopback to the static list.
// Each callback consumes its address synchronously; pointers never outlive their stack storage.
template <typename Fn> static DWORD netGuardFilters(PSID package, Fn fn) {
  UINT32 ordinal = 0;
  auto visit = [&](const GUID &layer, FWP_CONDITION_VALUE0 address) -> DWORD {
    GUID key{};
    const DWORD error = netGuardKey(package, ordinal++, key);
    return error == ERROR_SUCCESS ? fn(key, layer, address) : error;
  };
  for (auto range : NET_GUARD_V4) {
    FWP_CONDITION_VALUE0 address{};
    address.type = FWP_V4_ADDR_MASK; address.v4AddrMask = &range;
    for (const GUID &layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
      const DWORD error = visit(layer, address);
      if (error != ERROR_SUCCESS) return error;
    }
    FWP_V6_ADDR_AND_MASK mapped{};
    mapped.addr[10] = 0xff; mapped.addr[11] = 0xff;
    for (unsigned i = 0; i < 4; ++i) mapped.addr[12 + i] = static_cast<UINT8>(range.addr >> (24 - i * 8));
    unsigned prefix = 0;
    for (UINT32 mask = range.mask; mask; mask <<= 1) ++prefix;
    mapped.prefixLength = static_cast<UINT8>(96 + prefix);
    address.type = FWP_V6_ADDR_MASK; address.v6AddrMask = &mapped;
    for (const GUID &layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
      const DWORD error = visit(layer, address);
      if (error != ERROR_SUCCESS) return error;
    }
    // The well-known NAT64 prefix embeds the same IPv4 destinations in its final 32 bits.
    FWP_V6_ADDR_AND_MASK nat64 = mapped;
    nat64.addr[10] = 0; nat64.addr[11] = 0;
    nat64.addr[1] = 0x64; nat64.addr[2] = 0xff; nat64.addr[3] = 0x9b;
    address.v6AddrMask = &nat64;
    for (const GUID &layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
      const DWORD error = visit(layer, address);
      if (error != ERROR_SUCCESS) return error;
    }
  }
  for (auto &range : netGuardV6()) {
    FWP_CONDITION_VALUE0 address{};
    address.type = FWP_V6_ADDR_MASK; address.v6AddrMask = &range;
    for (const GUID &layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
      const DWORD error = visit(layer, address);
      if (error != ERROR_SUCCESS) return error;
    }
  }
  return ERROR_SUCCESS;
}

class NetGuardEngine {
 public:
  HANDLE handle = nullptr;
  NetGuardEngine() = default;
  NetGuardEngine(const NetGuardEngine &) = delete;
  NetGuardEngine &operator=(const NetGuardEngine &) = delete;
  ~NetGuardEngine() { if (handle) FwpmEngineClose0(handle); }
  DWORD open() { return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &handle); }
};

static std::wstring netGuardMarker(const std::wstring &profile) {
  return L"Software\\YouGame\\NetGuard\\" + profile;
}
static DWORD netGuardReadMarker(const std::wstring &profile, bool &firewallOff) {
  DWORD version = 0, bytes = sizeof version;
  const LSTATUS error = RegGetValueW(HKEY_LOCAL_MACHINE, netGuardMarker(profile).c_str(), L"version",
    RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &version, &bytes);
  if (error != ERROR_SUCCESS) return static_cast<DWORD>(error);
  if (version != NET_GUARD_VERSION) return ERROR_REVISION_MISMATCH;
  DWORD off = 0;
  bytes = sizeof off;
  const LSTATUS read = RegGetValueW(HKEY_LOCAL_MACHINE, netGuardMarker(profile).c_str(), L"firewallOff",
    RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &off, &bytes);
  if (read != ERROR_SUCCESS) return static_cast<DWORD>(read);
  if (off > 1) return ERROR_INVALID_DATA;
  firewallOff = off == 1;
  return ERROR_SUCCESS;
}
static DWORD netGuardDeleteMarker(const std::wstring &profile) {
  HKEY key = nullptr;
  LSTATUS error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, netGuardMarker(profile).c_str(), 0,
    KEY_SET_VALUE | KEY_WOW64_64KEY, &key);
  if (error == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
  if (error != ERROR_SUCCESS) return static_cast<DWORD>(error);
  LSTATUS first = ERROR_SUCCESS;
  for (const wchar_t *value : {L"version", L"firewallOff", L"firewallError"}) {
    error = RegDeleteValueW(key, value);
    if (error != ERROR_SUCCESS && error != ERROR_FILE_NOT_FOUND && first == ERROR_SUCCESS) first = error;
  }
  RegCloseKey(key);
  return static_cast<DWORD>(first);
}
static DWORD netGuardWriteMarker(const std::wstring &profile, bool firewallOff, DWORD firewallError) {
  // Explicit Builtin Users KEY_READ: status needs no elevation even if parent inheritance differs.
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
    L"D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", SDDL_REVISION_1, &descriptor, nullptr)) return GetLastError();
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  HKEY key = nullptr;
  LSTATUS error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, netGuardMarker(profile).c_str(), 0, nullptr, 0,
    KEY_SET_VALUE | WRITE_DAC | KEY_WOW64_64KEY, &security, &key, nullptr);
  // RegCreateKeyEx ignores the descriptor for an existing key; repair its DACL too.
  if (error == ERROR_SUCCESS) error = RegSetKeySecurity(key, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
  const DWORD off = firewallOff ? 1u : 0u;
  if (error == ERROR_SUCCESS) error = RegSetValueExW(key, L"firewallOff", 0, REG_DWORD,
    reinterpret_cast<const BYTE *>(&off), sizeof off);
  if (error == ERROR_SUCCESS) error = RegSetValueExW(key, L"firewallError", 0, REG_DWORD,
    reinterpret_cast<const BYTE *>(&firewallError), sizeof firewallError);
  // Publish the receipt last, after recording the optional Firewall component's result.
  if (error == ERROR_SUCCESS) error = RegSetValueExW(key, L"version", 0, REG_DWORD,
    reinterpret_cast<const BYTE *>(&NET_GUARD_VERSION), sizeof NET_GUARD_VERSION);
  if (key) RegCloseKey(key);
  LocalFree(descriptor);
  return static_cast<DWORD>(error);
}

// Small RAII holders avoid COM/automation leaks on every failure path.
template <typename T> class NetGuardCom {
 public:
  T *ptr = nullptr;
  NetGuardCom() = default;
  NetGuardCom(const NetGuardCom &) = delete;
  NetGuardCom &operator=(const NetGuardCom &) = delete;
  ~NetGuardCom() { if (ptr) ptr->Release(); }
};
class NetGuardBstr {
 public:
  BSTR text;
  explicit NetGuardBstr(const wchar_t *value) : text(SysAllocString(value)) {}
  NetGuardBstr(const NetGuardBstr &) = delete;
  NetGuardBstr &operator=(const NetGuardBstr &) = delete;
  ~NetGuardBstr() { SysFreeString(text); }
};
static std::wstring netGuardRuleName(PSID package) {
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(package, &sid)) return {};
  std::wstring name = L"YouGame home-network guard " + std::wstring(sid);
  LocalFree(sid);
  return name;
}
static bool netGuardFirewallMissing(DWORD error) {
  return error == static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) ||
    error == static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_NOT_FOUND));
}
static bool netGuardFirewallUnavailable(DWORD error) {
  return error == static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE)) ||
    error == static_cast<DWORD>(HRESULT_FROM_WIN32(RPC_S_SERVER_UNAVAILABLE)) ||
    error == static_cast<DWORD>(HRESULT_FROM_WIN32(EPT_S_NOT_REGISTERED));
}
static DWORD netGuardFirewallServiceOff(bool &off) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return GetLastError();
  SC_HANDLE service = OpenServiceW(manager, L"MpsSvc", SERVICE_QUERY_STATUS);
  DWORD error = service ? ERROR_SUCCESS : GetLastError();
  if (service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE *>(&status), sizeof status, &bytes))
      error = GetLastError();
    else off = status.dwCurrentState == SERVICE_STOPPED;
    CloseServiceHandle(service);
  }
  CloseServiceHandle(manager);
  return error;
}
enum class NetGuardFirewallMode { Status, Install, Remove };
static DWORD netGuardFirewall(PSID package, NetGuardFirewallMode mode) {
  const HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(initialized)) return static_cast<DWORD>(initialized);
  HRESULT result = S_OK;
  {
    NetGuardCom<INetFwPolicy2> policy;
    NetGuardCom<INetFwRules> rules;
    NetGuardCom<INetFwRule3> rule;
    NetGuardBstr name(netGuardRuleName(package).c_str());
    LPWSTR sid = nullptr;
    if (!name.text || !ConvertSidToStringSidW(package, &sid)) result = E_OUTOFMEMORY;
    NetGuardBstr packageId(sid ? sid : L"");
    if (sid) LocalFree(sid);
    NetGuardBstr addresses(L"LocalSubnet,DefaultGateway");
    NetGuardBstr group(L"YouGame home-network guard");
    if (!packageId.text || !addresses.text || !group.text) result = E_OUTOFMEMORY;
    if (SUCCEEDED(result)) result = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
      __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&policy.ptr));
    if (SUCCEEDED(result)) result = policy.ptr->get_Rules(&rules.ptr);
    if (SUCCEEDED(result) && mode == NetGuardFirewallMode::Status) {
      NetGuardCom<INetFwRule> existing;
      result = rules.ptr->Item(name.text, &existing.ptr);
    }
    if (SUCCEEDED(result) && mode != NetGuardFirewallMode::Status) {
      // Firewall permits duplicate names. Bound each repair/removal to 32 removals.
      for (unsigned pass = 0; pass < 32; ++pass) {
        NetGuardCom<INetFwRule> existing;
        result = rules.ptr->Item(name.text, &existing.ptr);
        if (netGuardFirewallMissing(static_cast<DWORD>(result))) { result = S_OK; break; }
        if (FAILED(result)) break;
        result = rules.ptr->Remove(name.text);
        if (FAILED(result)) break;
      }
      if (SUCCEEDED(result)) {
        NetGuardCom<INetFwRule> remaining;
        result = rules.ptr->Item(name.text, &remaining.ptr);
        if (netGuardFirewallMissing(static_cast<DWORD>(result))) result = S_OK;
        else if (SUCCEEDED(result)) result = HRESULT_FROM_WIN32(ERROR_TOO_MANY_CMDS);
      }
    }
    if (SUCCEEDED(result) && mode == NetGuardFirewallMode::Install) {
      result = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule3), reinterpret_cast<void **>(&rule.ptr));
      if (SUCCEEDED(result)) result = rule.ptr->put_Name(name.text);
      if (SUCCEEDED(result)) result = rule.ptr->put_Grouping(group.text);
      if (SUCCEEDED(result)) result = rule.ptr->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
      if (SUCCEEDED(result)) result = rule.ptr->put_Direction(NET_FW_RULE_DIR_OUT);
      if (SUCCEEDED(result)) result = rule.ptr->put_LocalAppPackageId(packageId.text);
      if (SUCCEEDED(result)) result = rule.ptr->put_RemoteAddresses(addresses.text);
      if (SUCCEEDED(result)) result = rule.ptr->put_Profiles(NET_FW_PROFILE2_ALL);
      if (SUCCEEDED(result)) result = rule.ptr->put_Action(NET_FW_ACTION_BLOCK);
      if (SUCCEEDED(result)) result = rule.ptr->put_Enabled(VARIANT_TRUE);
      if (SUCCEEDED(result)) result = rules.ptr->Add(rule.ptr);
    }
  }
  CoUninitialize();
  return SUCCEEDED(result) ? ERROR_SUCCESS : static_cast<DWORD>(result);
}

static bool netGuardAddressMatches(const FWPM_FILTER_CONDITION0 &condition, FWP_CONDITION_VALUE0 wanted) {
  if (!IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS) ||
      condition.matchType != FWP_MATCH_EQUAL || condition.conditionValue.type != wanted.type) return false;
  const FWP_CONDITION_VALUE0 &value = condition.conditionValue;
  if (wanted.type == FWP_V4_ADDR_MASK)
    return value.v4AddrMask && value.v4AddrMask->addr == wanted.v4AddrMask->addr && value.v4AddrMask->mask == wanted.v4AddrMask->mask;
  if (wanted.type == FWP_V6_ADDR_MASK)
    return value.v6AddrMask && value.v6AddrMask->prefixLength == wanted.v6AddrMask->prefixLength &&
      memcmp(value.v6AddrMask->addr, wanted.v6AddrMask->addr, sizeof value.v6AddrMask->addr) == 0;
  return false;
}

static bool netGuardConditionsMatch(const FWPM_FILTER0 &filter, PSID package, FWP_CONDITION_VALUE0 address) {
  if (filter.numFilterConditions != 2 || !filter.filterCondition) return false;
  bool packageMatches = false, addressMatches = false;
  // BFE may return conditions in canonical order, rather than the insertion order.
  for (UINT32 i = 0; i < filter.numFilterConditions; ++i) {
    const FWPM_FILTER_CONDITION0 &condition = filter.filterCondition[i];
    if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_ALE_PACKAGE_ID))
      packageMatches = condition.matchType == FWP_MATCH_EQUAL && condition.conditionValue.type == FWP_SID &&
        condition.conditionValue.sid && EqualSid(condition.conditionValue.sid, package);
    else if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS))
      addressMatches = netGuardAddressMatches(condition, address);
  }
  return packageMatches && addressMatches;
}

static DWORD netGuardStatus(const std::wstring &profile, PSID package) {
  bool firewallOff = false;
  DWORD error = netGuardReadMarker(profile, firewallOff);
  if (error != ERROR_SUCCESS) return error;
  error = netGuardFirewall(package, NetGuardFirewallMode::Status);
  if (error != ERROR_SUCCESS) {
    if (!firewallOff || !(netGuardFirewallMissing(error) || netGuardFirewallUnavailable(error))) return error;
    bool serviceOff = false;
    const DWORD serviceError = netGuardFirewallServiceOff(serviceOff);
    if (serviceError != ERROR_SUCCESS) return serviceError;
    if (!serviceOff) return error;
  }
  NetGuardEngine engine;
  error = engine.open();
  // Managed BFE ACLs may withhold read access. The HKLM marker is the elevated install's receipt;
  // skip only ACCESS_DENIED, never a missing filter, service failure or other query error.
  if (error == ERROR_ACCESS_DENIED) return ERROR_SUCCESS;
  if (error != ERROR_SUCCESS) return error;
  return netGuardFilters(package, [&](const GUID &key, const GUID &layer, FWP_CONDITION_VALUE0 address) -> DWORD {
    FWPM_FILTER0 *filter = nullptr;
    DWORD found = FwpmFilterGetByKey0(engine.handle, &key, &filter);
    if (found == ERROR_ACCESS_DENIED) return ERROR_SUCCESS;
    if (found != ERROR_SUCCESS) return found;
    const bool valid = filter && filter->providerKey && IsEqualGUID(*filter->providerKey, NET_GUARD_PROVIDER) &&
      IsEqualGUID(filter->subLayerKey, NET_GUARD_SUBLAYER) && IsEqualGUID(filter->layerKey, layer) &&
      (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) && (filter->flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) &&
      !(filter->flags & FWPM_FILTER_FLAG_DISABLED) && filter->action.type == FWP_ACTION_BLOCK &&
      netGuardConditionsMatch(*filter, package, address);
    FwpmFreeMemory0(reinterpret_cast<void **>(&filter));
    return valid ? ERROR_SUCCESS : ERROR_INVALID_DATA;
  });
}
static bool netGuardElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD bytes = 0;
  const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &bytes);
  CloseHandle(token);
  return ok && elevation.TokenIsElevated;
}
class NetGuardMutex {
 public:
  NetGuardMutex() = default;
  NetGuardMutex(const NetGuardMutex &) = delete;
  NetGuardMutex &operator=(const NetGuardMutex &) = delete;
  ~NetGuardMutex() {
    if (owned) ReleaseMutex(handle);
    if (handle) CloseHandle(handle);
  }
  DWORD acquire() {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) return GetLastError();
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    handle = CreateMutexExW(&security, L"Global\\YouGameNetGuard", 0, SYNCHRONIZE | MUTEX_MODIFY_STATE);
    const DWORD error = handle ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    if (error != ERROR_SUCCESS) return error;
    const DWORD waited = WaitForSingleObject(handle, 60'000);
    owned = waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;
    if (owned) return ERROR_SUCCESS;
    return waited == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
  }
 private:
  HANDLE handle = nullptr;
  bool owned = false;
};
static DWORD netGuardInstall(const std::wstring &profile, PSID package) {
  if (!netGuardElevated()) return ERROR_ELEVATION_REQUIRED;
  NetGuardMutex mutex;
  DWORD error = mutex.acquire();
  if (error != ERROR_SUCCESS) return error;
  error = netGuardDeleteMarker(profile);
  if (error != ERROR_SUCCESS) return error;
  NetGuardEngine engine;
  error = engine.open();
  if (error != ERROR_SUCCESS) return error;
  error = FwpmTransactionBegin0(engine.handle, 0);
  if (error != ERROR_SUCCESS) return error;
  // Explicit read access to our WFP objects, without granting policy mutation to ordinary users.
  PSECURITY_DESCRIPTOR security = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)",
    SDDL_REVISION_1, &security, nullptr)) error = GetLastError();
  FWPM_PROVIDER0 provider{};
  provider.providerKey = NET_GUARD_PROVIDER;
  provider.displayData.name = const_cast<wchar_t *>(L"YouGame home-network guard");
  provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
  if (error == ERROR_SUCCESS) {
    error = FwpmProviderAdd0(engine.handle, &provider, security);
    if (error == static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) error = ERROR_SUCCESS;
  }
  FWPM_SUBLAYER0 sublayer{};
  sublayer.subLayerKey = NET_GUARD_SUBLAYER;
  sublayer.providerKey = const_cast<GUID *>(&NET_GUARD_PROVIDER);
  sublayer.displayData.name = provider.displayData.name;
  sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
  sublayer.weight = 0xffff;
  if (error == ERROR_SUCCESS) {
    error = FwpmSubLayerAdd0(engine.handle, &sublayer, security);
    if (error == static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) error = ERROR_SUCCESS;
  }
  if (error == ERROR_SUCCESS) error = netGuardFilters(package, [&](const GUID &key, const GUID &layer, FWP_CONDITION_VALUE0 address) -> DWORD {
    DWORD added = FwpmFilterDeleteByKey0(engine.handle, &key);
    if (added != ERROR_SUCCESS && added != static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) return added;
    FWPM_FILTER_CONDITION0 conditions[2]{};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_SID;
    conditions[0].conditionValue.sid = static_cast<SID *>(package);
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue = address;
    FWPM_FILTER0 filter{};
    filter.filterKey = key;
    filter.displayData.name = provider.displayData.name;
    filter.providerKey = const_cast<GUID *>(&NET_GUARD_PROVIDER);
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    filter.layerKey = layer;
    filter.subLayerKey = NET_GUARD_SUBLAYER;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_UINT8; filter.weight.uint8 = 15;
    filter.numFilterConditions = 2; filter.filterCondition = conditions;
    return FwpmFilterAdd0(engine.handle, &filter, security, nullptr);
  });
  if (security) LocalFree(security);
  if (error == ERROR_SUCCESS) error = FwpmTransactionCommit0(engine.handle);
  if (error != ERROR_SUCCESS) { FwpmTransactionAbort0(engine.handle); return error; }
  bool firewallOff = false;
  error = netGuardFirewallServiceOff(firewallOff);
  if (error != ERROR_SUCCESS) return error;
  const DWORD firewallError = netGuardFirewall(package, NetGuardFirewallMode::Install);
  if (firewallError == static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_TOO_MANY_CMDS))) return firewallError;
  if (firewallError != ERROR_SUCCESS && !firewallOff) return firewallError;
  return netGuardWriteMarker(profile, firewallOff, firewallError);
}
static DWORD netGuardRemove(const std::wstring &profile, PSID package) {
  if (!netGuardElevated()) return ERROR_ELEVATION_REQUIRED;
  NetGuardMutex mutex;
  const DWORD locked = mutex.acquire();
  if (locked != ERROR_SUCCESS) return locked;
  DWORD first = netGuardDeleteMarker(profile);
  auto remember = [&](DWORD error) { if (first == ERROR_SUCCESS && error != ERROR_SUCCESS) first = error; };
  remember(netGuardFirewall(package, NetGuardFirewallMode::Remove));
  NetGuardEngine engine;
  DWORD error = engine.open();
  remember(error);
  if (error == ERROR_SUCCESS) {
    // Continue cleanup after a failed deletion so remove attempts all three components.
    remember(netGuardFilters(package, [&](const GUID &key, const GUID &, FWP_CONDITION_VALUE0) -> DWORD {
      const DWORD removed = FwpmFilterDeleteByKey0(engine.handle, &key);
      remember(removed == static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND) ? ERROR_SUCCESS : removed);
      return ERROR_SUCCESS;
    }));
    error = FwpmSubLayerDeleteByKey0(engine.handle, &NET_GUARD_SUBLAYER);
    if (error != static_cast<DWORD>(FWP_E_IN_USE) && error != static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) remember(error);
    error = FwpmProviderDeleteByKey0(engine.handle, &NET_GUARD_PROVIDER);
    if (error != static_cast<DWORD>(FWP_E_IN_USE) && error != static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND)) remember(error);
  }
  // Remove the now-empty profile key in the same 64-bit registry view. Never delete other profiles.
  HKEY parent = nullptr;
  const LSTATUS opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\YouGame\\NetGuard", 0,
    KEY_WRITE | KEY_WOW64_64KEY, &parent);
  if (opened == ERROR_SUCCESS) {
    const LSTATUS deleted = RegDeleteKeyExW(parent, profile.c_str(), KEY_WOW64_64KEY, 0);
    if (deleted != ERROR_FILE_NOT_FOUND) remember(static_cast<DWORD>(deleted));
    RegCloseKey(parent);
  } else if (opened != ERROR_FILE_NOT_FOUND) remember(static_cast<DWORD>(opened));
  return first;
}
