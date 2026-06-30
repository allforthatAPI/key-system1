// SaturnAuth.cs
// ---------------------------------------------------------------------------
// Saturn License Client (C# / .NET)
//
// HOW TO USE:
//   1. Drop this file into your project (Saturn namespace).
//   2. At app startup, call:
//        var result = await Saturn.SaturnAuth.ValidateKeyAsync(licenseKey, "https://your-app.onrender.com");
//        if (!result.Valid) { /* show error, exit */ }
//   3. Optionally re-validate periodically (e.g. every 30 min) for long-running apps,
//      so a revoked/expired key gets caught mid-session, not just at launch.
//
// IMPORTANT — READ THIS:
//   Like any client-side check, this can be bypassed by someone willing to
//   decompile and patch the assembly (this is especially true for .NET, since
//   IL decompiles cleanly with tools like dnSpy). The server is the actual
//   source of truth — it independently re-checks key validity, expiry, and
//   HWID match on every request. This client code exists to gate normal
//   usage and make naive tampering require real effort, not to make cracking
//   impossible. Consider tools like ConfuserEx or .NET Reactor for additional
//   obfuscation, and avoid putting your core program logic in a single
//   easily-patched "if (valid)" branch — better to have validated server
//   responses unlock actual functionality/data, not just a boolean gate.
// ---------------------------------------------------------------------------

using System;
using System.Management;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Saturn
{
    public class ValidationResult
    {
        public bool Valid { get; set; }
        public bool FirstActivation { get; set; }
        public string Error { get; set; }
        public string ExpiresAt { get; set; }
    }

    public static class SaturnAuth
    {
        private static readonly HttpClient http = new HttpClient();

        // ---------------------------------------------------------------
        // HWID: combine CPU ID + motherboard serial + disk serial, hash it.
        // Requires System.Management (add via NuGet: System.Management).
        // ---------------------------------------------------------------
        public static string GetHWID()
        {
            string cpuId = GetWmiProperty("Win32_Processor", "ProcessorId");
            string boardSerial = GetWmiProperty("Win32_BaseBoard", "SerialNumber");
            string diskSerial = GetWmiProperty("Win32_DiskDrive", "SerialNumber");

            string combined = $"{cpuId}|{boardSerial}|{diskSerial}";
            return Sha256Hex(combined);
        }

        private static string GetWmiProperty(string wmiClass, string property)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var val = obj[property];
                    if (val != null) return val.ToString();
                }
            }
            catch
            {
                // WMI can fail in locked-down environments; fall back gracefully.
            }
            return "unknown";
        }

        private static string Sha256Hex(string input)
        {
            using var sha = SHA256.Create();
            byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            var sb = new StringBuilder();
            foreach (byte b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        // ---------------------------------------------------------------
        // Calls POST /api/validate on your Saturn backend.
        // ---------------------------------------------------------------
        public static async Task<ValidationResult> ValidateKeyAsync(string licenseKey, string baseUrl)
        {
            var result = new ValidationResult();
            try
            {
                string hwid = GetHWID();
                var payload = JsonSerializer.Serialize(new { key = licenseKey, hwid = hwid });
                var content = new StringContent(payload, Encoding.UTF8, "application/json");

                var response = await http.PostAsync($"{baseUrl.TrimEnd('/')}/api/validate", content);
                var responseBody = await response.Content.ReadAsStringAsync();

                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                result.Valid = root.TryGetProperty("valid", out var validEl) && validEl.GetBoolean();
                result.FirstActivation = root.TryGetProperty("firstActivation", out var faEl) && faEl.GetBoolean();
                result.Error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() : null;
                result.ExpiresAt = root.TryGetProperty("expiresAt", out var expEl) && expEl.ValueKind != JsonValueKind.Null
                    ? expEl.GetString() : null;
            }
            catch (Exception ex)
            {
                result.Valid = false;
                result.Error = "Network or parsing error: " + ex.Message;
            }
            return result;
        }
    }
}

/* ---------------------------------------------------------------------------
EXAMPLE USAGE:

    using Saturn;

    class Program
    {
        static async Task Main(string[] args)
        {
            string key = "SATURN-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-ABCD"; // get from your user
            var result = await SaturnAuth.ValidateKeyAsync(key, "https://your-app.onrender.com");

            if (!result.Valid)
            {
                Console.WriteLine("License error: " + result.Error);
                Environment.Exit(1);
            }

            if (result.FirstActivation)
                Console.WriteLine("License activated and locked to this device.");

            // ... continue running your protected application ...
        }
    }
--------------------------------------------------------------------------- */
