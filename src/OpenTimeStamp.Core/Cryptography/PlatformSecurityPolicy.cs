using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace OpenTimeStamp.Cryptography;

public static class PlatformSecurityPolicy
{
    private const string PolicyKey = @"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy";
    private static readonly Lazy<bool> fipsEnabled = new(ReadFipsEnabled, true);

    public static bool IsFipsEnabled => fipsEnabled.Value;

    internal static bool InterpretFipsRegistryValue(object value)
    {
        if (value is null) return false;

        // The documented REG_DWORD value is the only representation which can disable
        // the policy. Treat a present value of any unexpected type as enabled.
        return value is not int enabled || enabled != 0;
    }

    private static bool ReadFipsEnabled()
    {
        // Prefer the runtime's effective policy view because it includes framework enforcement.
        try
        {
            if (CryptoConfig.AllowOnlyFipsAlgorithms) return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException or
                                   System.Security.SecurityException or UnauthorizedAccessException)
        {
            return true;
        }

        // Check the Windows policy value directly and fail closed when it cannot be read.
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(PolicyKey, false);
            return InterpretFipsRegistryValue(key?.GetValue("Enabled"));
        }
        catch (Exception ex) when (ex is IOException or System.Security.SecurityException or
                                   UnauthorizedAccessException)
        {
            return true;
        }
    }

    public static bool IsRequestHashAllowed(TimestampHashAlgorithm algorithm)
    {
        if (algorithm is null) return false;

        return !IsFipsEnabled || !algorithm.IsLegacy;
    }

    public static bool IsSigningHashAllowed(TimestampHashAlgorithm algorithm) =>
        algorithm is not null && algorithm.CmsSigningSupported && (!IsFipsEnabled || !algorithm.IsLegacy);

    public static bool IsMldsaSupported => MLDsa.IsSupported;

    public static bool IsLegacyAuthenticodeAllowed => !IsFipsEnabled;
}
