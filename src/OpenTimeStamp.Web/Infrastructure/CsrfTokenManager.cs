using System;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Security;
using OpenTimeStamp.Cryptography;

namespace OpenTimeStamp.Web.Infrastructure;

internal static class CsrfTokenManager
{
    private const string CookieName = "OpenTimeStamp.AdminCsrf";
    private const string ProtectionPurpose = "OpenTimeStamp.AdminCsrf.v1";
    private const byte PayloadVersion = 1;
    private const int IdentityDigestLength = 32;
    private const int NonceLength = 32;
    private const int PayloadLength = 1 + sizeof(long) + IdentityDigestLength + NonceLength;
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(1);
    private static readonly TimeSpan FutureClockTolerance = TimeSpan.FromMinutes(5);

    public static string GetOrCreate(HttpContext context, RequestIdentity identity)
    {
        var existing = context.Request.Cookies[CookieName]?.Value;
        if (!TryDecode(existing, out var protectedToken) ||
            !TryUnprotect(protectedToken, out var payload) ||
            !ValidatePayload(payload, identity, DateTime.UtcNow))
        {
            payload = CreatePayload(identity, DateTime.UtcNow);
            existing = Encode(MachineKey.Protect(payload, ProtectionPurpose));
            var cookie = new HttpCookie(CookieName, existing)
            {
                HttpOnly = true,
                Secure = context.Request.IsSecureConnection,
                SameSite = SameSiteMode.Strict,
                Path = AdminPath(context.Request)
            };
            context.Response.Cookies.Add(cookie);
        }

        return existing;
    }

    public static bool Validate(HttpContext context, string submitted, RequestIdentity identity)
    {
        if (!TryDecode(context.Request.Cookies[CookieName]?.Value, out var cookie) ||
            !TryDecode(submitted, out var form) || !WindowsHash.FixedTimeEquals(cookie, form) ||
            !TryUnprotect(cookie, out var payload)) return false;

        return ValidatePayload(payload, identity, DateTime.UtcNow);
    }

    internal static byte[] CreatePayload(RequestIdentity identity, DateTime issuedUtc)
    {
        issuedUtc = issuedUtc.ToUniversalTime();
        var payload = new byte[PayloadLength];
        payload[0] = PayloadVersion;
        Buffer.BlockCopy(BitConverter.GetBytes(issuedUtc.Ticks), 0, payload, 1, sizeof(long));
        var identityDigest = GetIdentityDigest(identity);
        Buffer.BlockCopy(identityDigest, 0, payload, 1 + sizeof(long), identityDigest.Length);
        var nonce = new byte[NonceLength];
        using (var generator = RandomNumberGenerator.Create())
        {
            generator.GetBytes(nonce);
        }
        Buffer.BlockCopy(nonce, 0, payload, 1 + sizeof(long) + IdentityDigestLength, nonce.Length);

        return payload;
    }

    internal static bool ValidatePayload(byte[] payload, RequestIdentity identity, DateTime utcNow)
    {
        if (payload == null || payload.Length != PayloadLength || payload[0] != PayloadVersion) return false;

        long issuedTicks;
        try
        {
            issuedTicks = BitConverter.ToInt64(payload, 1);
            if (issuedTicks < DateTime.MinValue.Ticks || issuedTicks > DateTime.MaxValue.Ticks) return false;
        }
        catch (ArgumentException)
        {
            return false;
        }

        utcNow = utcNow.ToUniversalTime();
        var issuedUtc = new DateTime(issuedTicks, DateTimeKind.Utc);
        var latestIssuedTicks = utcNow.Ticks > DateTime.MaxValue.Ticks - FutureClockTolerance.Ticks
            ? DateTime.MaxValue.Ticks
            : utcNow.Ticks + FutureClockTolerance.Ticks;
        if (issuedUtc.Ticks > latestIssuedTicks || utcNow - issuedUtc > TokenLifetime) return false;

        var expectedIdentity = GetIdentityDigest(identity);
        var difference = 0;
        var identityOffset = 1 + sizeof(long);
        for (var index = 0; index < IdentityDigestLength; index++)
            difference |= payload[identityOffset + index] ^ expectedIdentity[index];
        return difference == 0;
    }

    private static bool TryUnprotect(byte[] protectedToken, out byte[] payload)
    {
        payload = null;
        try
        {
            payload = MachineKey.Unprotect(protectedToken, ProtectionPurpose);
            return payload != null;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    private static byte[] GetIdentityDigest(RequestIdentity identity)
    {
        var identityKey = !string.IsNullOrWhiteSpace(identity?.Sid)
            ? "sid:" + identity.Sid.Trim().ToUpperInvariant()
            : "name:" + (identity?.Name ?? string.Empty).Trim().ToUpperInvariant() +
              "|auth:" + (identity?.AuthenticationType ?? string.Empty).Trim().ToUpperInvariant();
        return WindowsHash.ComputeSha256(Encoding.UTF8.GetBytes(identityKey));
    }

    internal static string AdminPath(HttpRequest request)
    {
        var applicationPath = request.ApplicationPath == "/" ? string.Empty : request.ApplicationPath.TrimEnd('/');
        return applicationPath + "/admin";
    }

    private static string Encode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryDecode(string value, out byte[] decoded)
    {
        decoded = null;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512) return false;

        try
        {
            var normalized = value.Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight(((normalized.Length + 3) / 4) * 4, '=');
            decoded = Convert.FromBase64String(normalized);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
