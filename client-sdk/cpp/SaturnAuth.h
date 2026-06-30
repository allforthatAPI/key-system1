// SaturnAuth.h
// ---------------------------------------------------------------------------
// Saturn License Client (C++ / Windows)
//
// HOW TO USE:
//   1. #include "SaturnAuth.h"
//   2. Link against winhttp.lib (and bcrypt.lib for hashing)
//   3. Call Saturn::Authenticate("YOUR-KEY-HERE", "https://your-app.onrender.com")
//      at program startup, before any protected logic runs.
//   4. If it returns false, exit/lock the program. Do NOT let the program
//      continue running protected features if Authenticate() fails.
//
// IMPORTANT — READ THIS:
//   This client-side check is a deterrent, not a guarantee. A sufficiently
//   determined reverse engineer can patch the binary to always return true,
//   regardless of what this file does. The actual security boundary is the
//   SERVER (it independently re-validates key + HWID on every call). This
//   client check exists to (a) avoid sending requests when there's obviously
//   no key entered, (b) make naive cracking (e.g. just deleting the call)
//   require actually finding and patching the call site, and (c) keep the
//   HWID computation out of easy reach of a network sniffer alone.
//
//   For real resilience, consider: code obfuscation/packing, periodic
//   re-validation (not just at startup), and integrity-checking critical
//   functions server-side (e.g. fetch a config/feature-flag the server
//   only returns to validated sessions).
// ---------------------------------------------------------------------------

#pragma once
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <intrin.h>
#include <string>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace Saturn {

// ---------------------------------------------------------------------------
// HWID generation: combine CPU ID + motherboard/volume serial + machine GUID,
// then SHA-256 hash so the raw hardware identifiers are never transmitted.
// ---------------------------------------------------------------------------
inline std::string Sha256Hex(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return result;

    DWORD hashLen = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(DWORD), &cbData, 0);

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) >= 0) {
        BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.size(), 0);
        std::string hash(hashLen, '\0');
        BCryptFinishHash(hHash, (PUCHAR)hash.data(), hashLen, 0);
        BCryptDestroyHash(hHash);

        std::ostringstream oss;
        for (unsigned char c : hash)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        result = oss.str();
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

inline std::string GetCpuId() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    std::ostringstream oss;
    for (int i : cpuInfo) oss << std::hex << i;
    return oss.str();
}

inline std::string GetVolumeSerial() {
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
    std::ostringstream oss;
    oss << std::hex << serial;
    return oss.str();
}

inline std::string GetMachineGuid() {
    HKEY hKey;
    char buffer[64] = { 0 };
    DWORD bufferSize = sizeof(buffer);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
        KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        RegCloseKey(hKey);
    }
    return std::string(buffer);
}

// Public: returns a stable, hashed hardware ID for this machine.
inline std::string GetHWID() {
    std::string combined = GetCpuId() + "|" + GetVolumeSerial() + "|" + GetMachineGuid();
    return Sha256Hex(combined);
}

// ---------------------------------------------------------------------------
// HTTP call to your Saturn backend's /api/validate endpoint
// ---------------------------------------------------------------------------
struct ValidationResult {
    bool valid = false;
    bool firstActivation = false;
    std::string error;
    std::string expiresAt;
};

inline ValidationResult ValidateKey(const std::string& licenseKey, const std::string& baseUrl) {
    ValidationResult result;

    // Parse host from baseUrl, e.g. "https://your-app.onrender.com"
    std::wstring wUrl(baseUrl.begin(), baseUrl.end());
    URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
    wchar_t hostName[256] = { 0 };
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.dwSchemeLength = (DWORD)-1;
    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.size(), 0, &urlComp)) {
        result.error = "Invalid base URL";
        return result;
    }

    HINTERNET hSession = WinHttpOpen(L"SaturnClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { result.error = "Could not open session"; return result; }

    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
    HINTERNET hConnect = WinHttpConnect(hSession, hostName, isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) { result.error = "Could not connect"; WinHttpCloseHandle(hSession); return result; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/validate", nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { result.error = "Could not open request"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }

    std::string hwid = GetHWID();
    std::string body = "{\"key\":\"" + licenseKey + "\",\"hwid\":\"" + hwid + "\"}";

    LPCWSTR headers = L"Content-Type: application/json";
    BOOL sent = WinHttpSendRequest(hRequest, headers, (DWORD)-1,
        (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);

    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        std::string response;
        DWORD size = 0;
        do {
            DWORD downloaded = 0;
            WinHttpQueryDataAvailable(hRequest, &size);
            if (size == 0) break;
            std::string buffer(size, '\0');
            WinHttpReadData(hRequest, (LPVOID)buffer.data(), size, &downloaded);
            response += buffer.substr(0, downloaded);
        } while (size > 0);

        // Minimal JSON field extraction (avoids pulling in a JSON lib dependency).
        // For production, swap in nlohmann/json or similar.
        auto findBool = [&](const std::string& field) -> bool {
            auto pos = response.find("\"" + field + "\"");
            if (pos == std::string::npos) return false;
            auto truePos = response.find("true", pos);
            auto falsePos = response.find("false", pos);
            auto commaPos = response.find(",", pos);
            auto bracePos = response.find("}", pos);
            auto endPos = (commaPos < bracePos) ? commaPos : bracePos;
            return (truePos != std::string::npos && truePos < endPos);
        };
        auto findString = [&](const std::string& field) -> std::string {
            auto pos = response.find("\"" + field + "\"");
            if (pos == std::string::npos) return "";
            auto colon = response.find(":", pos);
            auto quote1 = response.find("\"", colon);
            if (quote1 == std::string::npos) return "";
            auto quote2 = response.find("\"", quote1 + 1);
            if (quote2 == std::string::npos) return "";
            return response.substr(quote1 + 1, quote2 - quote1 - 1);
        };

        result.valid = findBool("valid");
        result.firstActivation = findBool("firstActivation");
        result.error = findString("error");
        result.expiresAt = findString("expiresAt");
    } else {
        result.error = "Network request failed";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

// Convenience wrapper for app startup.
inline bool Authenticate(const std::string& licenseKey, const std::string& baseUrl) {
    ValidationResult r = ValidateKey(licenseKey, baseUrl);
    return r.valid;
}

} // namespace Saturn

/* ---------------------------------------------------------------------------
EXAMPLE USAGE in your main():

    #include "SaturnAuth.h"

    int main() {
        std::string key = "SATURN-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-ABCD"; // get from your user, e.g. via input box
        Saturn::ValidationResult result = Saturn::ValidateKey(key, "https://your-app.onrender.com");

        if (!result.valid) {
            MessageBoxA(nullptr, result.error.c_str(), "License Error", MB_ICONERROR);
            return 1;
        }

        if (result.firstActivation) {
            MessageBoxA(nullptr, "License activated and locked to this device.", "Saturn", MB_OK);
        }

        // ... continue running your protected application ...
        return 0;
    }
--------------------------------------------------------------------------- */
