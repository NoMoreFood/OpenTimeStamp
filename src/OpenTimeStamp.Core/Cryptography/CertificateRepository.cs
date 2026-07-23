using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Configuration;

namespace OpenTimeStamp.Cryptography;

public sealed class CertificateDescriptor
{
    public StoreLocation StoreLocation { get; internal set; }

    public string Thumbprint { get; internal set; }

    public string Subject { get; internal set; }

    public string Issuer { get; internal set; }

    public DateTime NotBefore { get; internal set; }

    public DateTime NotAfter { get; internal set; }

    public string KeyAlgorithm { get; internal set; }

    public bool IsEligible { get; internal set; }

    public string IneligibilityReason { get; internal set; }
}

public sealed class CertificateRepository : IDisposable
{
    private static readonly TimeSpan ChainUrlRetrievalTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan SelectionCacheDuration = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SelectionRefreshSchedulingMargin = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan SelectionRefreshWaitTimeout =
        ChainUrlRetrievalTimeout + SelectionRefreshSchedulingMargin;
    private static readonly TimeSpan SelectionFailureBackoff = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan SelectionValidationHorizon =
        SelectionCacheDuration + SelectionRefreshWaitTimeout;
    private readonly object selectionCacheLock = new();
    private X509Certificate2 cachedSelection;
    private string cachedSelectionKey;
    private DateTime cachedSelectionExpiresUtc;
    private DateTime cachedSelectionValidatedUntilUtc;
    private bool selectionRefreshInProgress;
    private long selectionCacheGeneration;
    private string cachedSelectionFailureKey;
    private string cachedSelectionFailureReason;
    private DateTime cachedSelectionFailureExpiresUtc;
    private long cachedSelectionFailureGeneration;

    public const string TimeStampingEkuOid = KnownOids.TimeStampingEkuValue;

    public static DateTime GetSelectionValidationTimeUtc(DateTime utcNow, TimeSpan requiredHorizon)
    {
        if (requiredHorizon < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(requiredHorizon));

        utcNow = utcNow.ToUniversalTime();
        var horizon = requiredHorizon > SelectionValidationHorizon
            ? requiredHorizon
            : SelectionValidationHorizon;
        var maximumUtc = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc);
        var remainingTicks = maximumUtc.Ticks - utcNow.Ticks;
        return horizon.Ticks >= remainingTicks ? maximumUtc : utcNow.AddTicks(horizon.Ticks);
    }

    public IReadOnlyList<CertificateDescriptor> ListCertificates(
        bool includeIneligible,
        string signingDigestAlgorithm,
        bool authenticodeEnabled)
    {
        // Enumerate both stores visible to the worker identity and rank usable certificates first.
        List<CertificateDescriptor> result = new();
        AddStore(result, StoreLocation.LocalMachine, includeIneligible, signingDigestAlgorithm, authenticodeEnabled);
        AddStore(result, StoreLocation.CurrentUser, includeIneligible, signingDigestAlgorithm, authenticodeEnabled);
        return OrderCertificates(result);
    }

    internal static IReadOnlyList<CertificateDescriptor> OrderCertificates(IEnumerable<CertificateDescriptor> certificates) =>
        certificates.OrderByDescending(item => item.IsEligible)
            .ThenByDescending(item => item.NotAfter)
            .ThenBy(item => item.StoreLocation == StoreLocation.LocalMachine ? 0 : 1)
            .ThenBy(item => item.Thumbprint, StringComparer.Ordinal)
            .ThenBy(item => item.Subject, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public X509Certificate2 GetSelectedCertificate(ServiceConfiguration configuration) =>
        GetSelectedCertificate(configuration, null, CancellationToken.None);

    public X509Certificate2 GetSelectedCertificate(
        ServiceConfiguration configuration,
        CancellationToken cancellationToken) =>
        GetSelectedCertificate(configuration, null, cancellationToken);

    internal X509Certificate2 GetSelectedCertificate(
        ServiceConfiguration configuration,
        Func<ServiceConfiguration, DateTime, DateTime, X509Certificate2> loadSelection) =>
        GetSelectedCertificate(configuration, loadSelection, CancellationToken.None);

    internal X509Certificate2 GetSelectedCertificate(
        ServiceConfiguration configuration,
        Func<ServiceConfiguration, DateTime, DateTime, X509Certificate2> loadSelection,
        CancellationToken cancellationToken)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var cacheKey = BuildSelectionCacheKey(configuration);
        using var cancellationRegistration = cancellationToken.Register(() =>
        {
            lock (selectionCacheLock) Monitor.PulseAll(selectionCacheLock);
        });
        long requestGeneration;
        lock (selectionCacheLock) requestGeneration = selectionCacheGeneration;
        Stopwatch refreshWait = null;
        DateTime now;
        long refreshGeneration;
        while (true)
        {
            lock (selectionCacheLock)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (requestGeneration != selectionCacheGeneration)
                {
                    throw new CertificateSelectionException(
                        "Certificate settings changed during validation. Refresh the page and try again.");
                }

                now = DateTime.UtcNow;
                if (cachedSelection is not null && now < cachedSelectionExpiresUtc &&
                    string.Equals(cacheKey, cachedSelectionKey, StringComparison.Ordinal))
                {
                    return new X509Certificate2(cachedSelection);
                }

                if (now < cachedSelectionFailureExpiresUtc &&
                    cachedSelectionFailureGeneration == selectionCacheGeneration &&
                    string.Equals(cacheKey, cachedSelectionFailureKey, StringComparison.Ordinal))
                {
                    throw new CertificateSelectionException(cachedSelectionFailureReason);
                }

                if (selectionRefreshInProgress)
                {
                    if (CanServeCachedSelectionDuringRefresh(
                            cachedSelection is not null,
                            cacheKey,
                            cachedSelectionKey,
                            now,
                            cachedSelectionExpiresUtc,
                            cachedSelectionValidatedUntilUtc))
                    {
                        return new X509Certificate2(cachedSelection);
                    }

                    refreshWait ??= Stopwatch.StartNew();
                    var remaining = SelectionRefreshWaitTimeout - refreshWait.Elapsed;
                    if (remaining <= TimeSpan.Zero)
                    {
                        throw new CertificateSelectionException(
                            "Timed out waiting for timestamp signing certificate validation.");
                    }

                    Monitor.Wait(selectionCacheLock, remaining);
                    continue;
                }

                selectionRefreshInProgress = true;
                refreshGeneration = requestGeneration;
                break;
            }
        }

        X509Certificate2 loaded = null;
        try
        {
            var validationHorizonUtc = GetSelectionValidationTimeUtc(now, TimeSpan.Zero);
            loaded = loadSelection is null
                ? LoadSelectedCertificate(configuration, now, validationHorizonUtc)
                : loadSelection(configuration, now, validationHorizonUtc);
            if (loaded is null)
                throw new CertificateSelectionException(
                    "Timestamp signing certificate validation returned no certificate.");
            lock (selectionCacheLock)
            {
                if (refreshGeneration != selectionCacheGeneration)
                {
                    throw new CertificateSelectionException(
                        "Certificate settings changed during validation. Refresh the page and try again.");
                }

                if (DateTime.UtcNow >= validationHorizonUtc)
                {
                    throw new CertificateSelectionException(
                        "Timestamp signing certificate validation did not complete before its validation horizon.");
                }

                cachedSelection?.Dispose();
                cachedSelection = loaded;
                loaded = null;
                cachedSelectionKey = cacheKey;
                cachedSelectionExpiresUtc = now.Add(SelectionCacheDuration);
                cachedSelectionValidatedUntilUtc = validationHorizonUtc;
                ClearSelectionFailure();
                return new X509Certificate2(cachedSelection);
            }
        }
        catch (Exception ex) when (ex is CertificateSelectionException or CryptographicException or
                                   System.IO.IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException)
        {
            lock (selectionCacheLock)
            {
                if (refreshGeneration == selectionCacheGeneration)
                {
                    cachedSelectionFailureKey = cacheKey;
                    cachedSelectionFailureReason = ex.Message;
                    cachedSelectionFailureExpiresUtc = DateTime.UtcNow.Add(SelectionFailureBackoff);
                    cachedSelectionFailureGeneration = selectionCacheGeneration;
                }
            }

            throw;
        }
        finally
        {
            loaded?.Dispose();
            lock (selectionCacheLock)
            {
                selectionRefreshInProgress = false;
                Monitor.PulseAll(selectionCacheLock);
            }
        }
    }

    public void InvalidateSelectionCache()
    {
        lock (selectionCacheLock)
        {
            cachedSelection?.Dispose();
            cachedSelection = null;
            cachedSelectionKey = null;
            cachedSelectionExpiresUtc = DateTime.MinValue;
            cachedSelectionValidatedUntilUtc = DateTime.MinValue;
            ClearSelectionFailure();
            selectionCacheGeneration++;
            Monitor.PulseAll(selectionCacheLock);
        }
    }

    public void Dispose() => InvalidateSelectionCache();

    private void ClearSelectionFailure()
    {
        cachedSelectionFailureKey = null;
        cachedSelectionFailureReason = null;
        cachedSelectionFailureExpiresUtc = DateTime.MinValue;
        cachedSelectionFailureGeneration = 0;
    }

    private X509Certificate2 LoadSelectedCertificate(
        ServiceConfiguration configuration,
        DateTime signingTimeUtc,
        DateTime? trustValidationTimeUtc)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));
        signingTimeUtc = signingTimeUtc.ToUniversalTime();
        return configuration.UsesAutomaticCertificateSelection
            ? LoadAutomaticCertificate(configuration, signingTimeUtc, trustValidationTimeUtc)
            : LoadManualCertificate(configuration, signingTimeUtc, trustValidationTimeUtc);
    }

    private X509Certificate2 LoadAutomaticCertificate(
        ServiceConfiguration configuration,
        DateTime signingTimeUtc,
        DateTime? trustValidationTimeUtc)
    {
        var validationTimeUtc = (trustValidationTimeUtc ?? signingTimeUtc).ToUniversalTime();
        var candidates = ListCertificates(
            false,
            configuration.SigningDigestAlgorithm,
            configuration.AuthenticodeEnabled);
        foreach (var candidate in candidates)
        {
            ServiceConfiguration manual = configuration.Clone();
            manual.CertificateSelectionMode = ServiceConfiguration.ManualCertificateSelection;
            manual.CertificateStoreLocation = candidate.StoreLocation.ToString();
            manual.CertificateStoreName = StoreName.My.ToString();
            manual.CertificateThumbprint = candidate.Thumbprint;
            X509Certificate2 certificate = null;
            try
            {
                certificate = LoadManualCertificate(manual, signingTimeUtc, trustValidationTimeUtc);
                if (!ValidateCertificate(
                    certificate,
                    configuration.SigningDigestAlgorithm,
                    validationTimeUtc,
                    configuration.AuthenticodeEnabled,
                    out _)) continue;

                var selected = certificate;
                certificate = null;
                return selected;
            }
            catch (Exception ex) when (ex is CertificateSelectionException or CryptographicException or
                                       System.IO.IOException or UnauthorizedAccessException or
                                       System.Security.SecurityException)
            {
                // Continue through the ranked candidates so one inaccessible longer-lived key
                // cannot block a usable certificate with a slightly shorter lifetime.
            }
            finally
            {
                certificate?.Dispose();
            }
        }

        throw new CertificateSelectionException(
            "No eligible timestamp signing certificate is available. Install a valid certificate with an " +
            "accessible private key in Local Computer\\Personal or the service account’s Current User\\Personal store.");
    }

    private static X509Certificate2 LoadManualCertificate(
        ServiceConfiguration configuration,
        DateTime signingTimeUtc,
        DateTime? trustValidationTimeUtc)
    {

        // Resolve the configured certificate by normalized thumbprint in exactly one store.
        var thumbprint = ConfigurationStore.NormalizeThumbprint(configuration.CertificateThumbprint);
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new CertificateSelectionException("No timestamp signing certificate has been selected.");
        }

        if (!Enum.TryParse(configuration.CertificateStoreLocation, true, out StoreLocation location))
        {
            throw new CertificateSelectionException("The certificate store must be Local Computer or Current User.");
        }

        using X509Store store = new(StoreName.My, location);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        var certificates = store.Certificates;
        X509Certificate2Collection matches = null;
        try
        {
            matches = certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            if (matches.Count != 1)
            {
                throw new CertificateSelectionException(
                    "The selected certificate was not found in the configured Personal certificate store.");
            }

            var certificate = new X509Certificate2(matches[0]);
            if (!IsEligible(
                    certificate,
                    false,
                    configuration.SigningDigestAlgorithm,
                    configuration.AuthenticodeEnabled,
                    signingTimeUtc,
                    out var reason))
            {
                certificate.Dispose();
                throw new CertificateSelectionException("The selected certificate cannot be used: " + reason);
            }

            if (trustValidationTimeUtc.HasValue &&
                (!IsEligible(
                     certificate,
                     false,
                     configuration.SigningDigestAlgorithm,
                     configuration.AuthenticodeEnabled,
                     trustValidationTimeUtc.Value.ToUniversalTime(),
                     out reason) ||
                 !ValidateCertificateTrust(
                     certificate,
                     trustValidationTimeUtc.Value,
                     configuration.AllowUntrustedDevelopmentCertificate,
                     out reason)))
            {
                certificate.Dispose();
                throw new CertificateSelectionException(
                    "The selected certificate cannot be used for the next health-check interval: " + reason);
            }

            return certificate;
        }
        finally
        {
            DisposeCertificates(matches);
            DisposeCertificates(certificates);
        }
    }

    public bool ValidateSelection(ServiceConfiguration configuration, DateTime signingTimeUtc, out string reason)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        try
        {
            // Automatic resolution validates each candidate's profile, private key, and trust
            // through the requested horizon before returning the highest-ranked usable one.
            if (configuration.UsesAutomaticCertificateSelection)
            {
                using var automatic = LoadSelectedCertificate(configuration, DateTime.UtcNow, signingTimeUtc);
                reason = null;
                return true;
            }

            // Manual resolution first checks current usability, then performs private-key access,
            // association, and trust checks exactly once at the requested health or save horizon.
            using var certificate = LoadSelectedCertificate(configuration, DateTime.UtcNow, null);
            if (!ValidateCertificate(
                    certificate,
                    configuration.SigningDigestAlgorithm,
                    signingTimeUtc,
                    configuration.AuthenticodeEnabled,
                    out reason))
            {
                return false;
            }

            if (!ValidateCertificateTrust(
                    certificate,
                    signingTimeUtc,
                    configuration.AllowUntrustedDevelopmentCertificate,
                    out reason))
            {
                return false;
            }

            reason = null;
            return true;
        }
        catch (Exception ex) when (ex is CertificateSelectionException or CryptographicException or
                                   System.IO.IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException)
        {
            reason = ex.Message;
            return false;
        }
    }

    private static void AddStore(
        ICollection<CertificateDescriptor> output,
        StoreLocation location,
        bool includeIneligible,
        string signingDigestAlgorithm,
        bool authenticodeEnabled)
    {
        try
        {
            using X509Store store = new(StoreName.My, location);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            var certificates = store.Certificates;
            try
            {
                foreach (var certificate in certificates)
                {
                    try
                    {
                        // Enumeration stays metadata-only; save and health checks open and compare the private key.
                        var eligible = IsEligible(
                            certificate,
                            false,
                            signingDigestAlgorithm,
                            authenticodeEnabled,
                            DateTime.UtcNow,
                            out var reason);
                        if (eligible || includeIneligible)
                        {
                            output.Add(new CertificateDescriptor
                            {
                                StoreLocation = location,
                                Thumbprint = ConfigurationStore.NormalizeThumbprint(certificate.Thumbprint),
                                Subject = certificate.Subject,
                                Issuer = certificate.Issuer,
                                NotBefore = certificate.NotBefore,
                                NotAfter = certificate.NotAfter,
                                KeyAlgorithm = certificate.PublicKey?.Oid?.FriendlyName ??
                                    certificate.PublicKey?.Oid?.Value ?? "Unknown",
                                IsEligible = eligible,
                                IneligibilityReason = reason
                            });
                        }
                    }
                    catch (Exception ex) when (ex is CryptographicException or ArgumentException or
                                                  InvalidOperationException or System.IO.IOException or
                                                  UnauthorizedAccessException or System.Security.SecurityException)
                    {
                        if (includeIneligible)
                        {
                            output.Add(new CertificateDescriptor
                            {
                                StoreLocation = location,
                                Subject = "(certificate metadata unavailable)",
                                IsEligible = false,
                                IneligibilityReason = ex.Message
                            });
                        }
                    }
                }
            }
            finally
            {
                DisposeCertificates(certificates);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or System.IO.IOException or
                                   UnauthorizedAccessException or System.Security.SecurityException)
        {
            if (includeIneligible)
            {
                output.Add(new CertificateDescriptor
                {
                    StoreLocation = location,
                    Subject = "(store unavailable)",
                    IsEligible = false,
                    IneligibilityReason = ex.Message
                });
            }
        }
    }

    internal static bool ValidateCertificate(
        X509Certificate2 certificate,
        string signingDigestAlgorithm,
        DateTime signingTimeUtc,
        out string reason) =>
        ValidateCertificate(certificate, signingDigestAlgorithm, signingTimeUtc, false, out reason);

    internal static bool ValidateCertificate(
        X509Certificate2 certificate,
        string signingDigestAlgorithm,
        DateTime signingTimeUtc,
        bool authenticodeEnabled,
        out string reason)
    {
        if (certificate is null)
        {
            reason = "No timestamp signing certificate was supplied.";
            return false;
        }

        return IsEligible(
            certificate,
            true,
            signingDigestAlgorithm,
            authenticodeEnabled,
            signingTimeUtc.ToUniversalTime(),
            out reason);
    }

    internal static bool ValidateCertificateProfile(
        X509Certificate2 certificate,
        string signingDigestAlgorithm,
        DateTime signingTimeUtc,
        bool authenticodeEnabled,
        out string reason)
    {
        if (certificate is null)
        {
            reason = "No timestamp signing certificate was supplied.";
            return false;
        }

        return IsEligible(
            certificate,
            false,
            signingDigestAlgorithm,
            authenticodeEnabled,
            signingTimeUtc.ToUniversalTime(),
            out reason);
    }

    internal static bool ValidateCertificateTrust(
        X509Certificate2 certificate,
        DateTime validationTimeUtc,
        bool allowUntrustedDevelopmentCertificate,
        out string reason)
    {
        if (certificate is null)
        {
            reason = "No timestamp signing certificate was supplied.";
            return false;
        }

        if (allowUntrustedDevelopmentCertificate)
        {
            reason = null;
            return true;
        }

        try
        {
            using X509Chain chain = new();
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TimeStampingEkuOid));
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = validationTimeUtc.ToUniversalTime();
            chain.ChainPolicy.UrlRetrievalTimeout = ChainUrlRetrievalTimeout;
            if (chain.Build(certificate))
            {
                reason = null;
                return true;
            }

            var failures = chain.ChainStatus
                .Select(status => status.Status.ToString())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            reason = "Windows does not trust the certificate chain or could not complete online revocation checks" +
                (failures.Length == 0 ? "." : ": " + string.Join(", ", failures) + ".");
            return false;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException or
                                   UnauthorizedAccessException or System.Security.SecurityException)
        {
            reason = "Windows could not validate the certificate chain: " + ex.Message;
            return false;
        }
    }

    private static void DisposeCertificates(X509Certificate2Collection certificates)
    {
        if (certificates is null) return;
        foreach (var certificate in certificates) certificate?.Dispose();
    }

    private static bool IsEligible(
        X509Certificate2 certificate,
        bool testPrivateKey,
        string signingDigestAlgorithm,
        bool authenticodeEnabled,
        DateTime signingTimeUtc,
        out string reason)
    {
        // Enforce certificate lifetime at the intended signing instant and access to an
        // associated private key. X509Certificate2 exposes lifetime values in local time.
        if (!certificate.HasPrivateKey)
        {
            reason = "The certificate has no private key.";
            return false;
        }

        if (signingTimeUtc < certificate.NotBefore.ToUniversalTime() ||
            signingTimeUtc > certificate.NotAfter.ToUniversalTime())
        {
            reason = "The certificate is not valid for the next timestamp signing time.";
            return false;
        }

        if (!HasValidMldsaCertificateSignatureAlgorithmIdentifiers(certificate.RawData, out reason)) return false;

        // RFC 3161 requires a critical, exclusive timeStamping extended key usage.
        var ekuExtensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToList();
        var hasTimestampingEku = ekuExtensions.Count == 1 &&
            ekuExtensions[0].Critical &&
            ekuExtensions[0].EnhancedKeyUsages.Count == 1 &&
            ekuExtensions[0].EnhancedKeyUsages.Cast<Oid>().Single().Value == KnownOids.TimeStampingEku;
        if (!hasTimestampingEku)
        {
            reason = "The certificate must have a critical Time Stamping EKU and no other EKUs.";
            return false;
        }

        // Reject CA certificates and keys whose key-usage extension forbids signing.
        foreach (var extension in certificate.Extensions.OfType<X509BasicConstraintsExtension>())
        {
            if (extension.CertificateAuthority)
            {
                reason = "A CA certificate cannot be used as a timestamp signer.";
                return false;
            }
        }

        var isMldsaCertificate = IsMldsaCertificate(certificate);
        foreach (var extension in certificate.Extensions.OfType<X509KeyUsageExtension>())
        {
            if (isMldsaCertificate)
            {
                if (!IsMldsaKeyUsageCompatible(extension.KeyUsages, out reason)) return false;
                continue;
            }

            if ((extension.KeyUsages &
                    (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) == 0)
            {
                reason = "The certificate key usage does not allow digital signatures or content commitment.";
                return false;
            }
        }

        var signingAlgorithm = HashAlgorithmCatalog.FindByName(signingDigestAlgorithm);
        if (testPrivateKey && (signingAlgorithm is null || !signingAlgorithm.CmsSigningSupported))
        {
            reason = "The configured timestamp signing hash cannot be used for CMS signing.";
            return false;
        }

        if (!IsSigningKeyCompatible(certificate, signingAlgorithm, authenticodeEnabled, out reason)) return false;
        if (testPrivateKey && !CanAccessAssociatedPrivateKey(certificate, out reason)) return false;

        reason = null;
        return true;
    }

    internal static bool IsMldsaCertificate(X509Certificate2 certificate) =>
        certificate is not null && IsMldsaOid(certificate.PublicKey?.Oid?.Value);

    internal static bool IsSigningKeyCompatible(
        X509Certificate2 certificate,
        TimestampHashAlgorithm signingHash,
        bool authenticodeEnabled,
        out string reason)
    {
        if (certificate is null)
        {
            reason = "No timestamp signing certificate was supplied.";
            return false;
        }

        if (!IsMldsaCertificate(certificate))
        {
            try
            {
                using var rsa = certificate.GetRSAPublicKey();
                if (rsa is null)
                {
                    reason = "The certificate must use RSA or pure ML-DSA-44, ML-DSA-65, or ML-DSA-87.";
                    return false;
                }

                if (rsa.KeySize < 2048)
                {
                    reason = "RSA timestamp signing keys must be at least 2048 bits.";
                    return false;
                }

                reason = null;
                return true;
            }
            catch (Exception ex) when (ex is CryptographicException or NotSupportedException)
            {
                reason = "The certificate public key is not usable: " + ex.Message;
                return false;
            }
        }

        if (!IsMldsaPublicKeyEncodingCompatible(
                certificate.PublicKey.Oid.Value,
                certificate.PublicKey.EncodedParameters?.RawData,
                certificate.PublicKey.EncodedKeyValue?.RawData,
                out reason)) return false;

        if (authenticodeEnabled)
        {
            reason = "ML-DSA timestamp signing is supported only for RFC 3161; " +
                "legacy Authenticode requires an RSA certificate.";
            return false;
        }

        if (!PlatformSecurityPolicy.IsMldsaSupported)
        {
            reason = "The installed Windows cryptography provider does not support ML-DSA.";
            return false;
        }

        return IsMldsaSigningHashCompatible(certificate.PublicKey.Oid.Value, signingHash, out reason);
    }

    internal static bool IsMldsaSigningHashCompatible(
        string algorithmOid,
        TimestampHashAlgorithm signingHash,
        out string reason)
    {
        var minimumDigestLength = algorithmOid switch
        {
            KnownOids.MlDsa44Value => 32,
            KnownOids.MlDsa65Value => 48,
            KnownOids.MlDsa87Value => 64,
            _ => int.MaxValue
        };
        if (signingHash is null || !signingHash.CmsSigningSupported || signingHash.IsLegacy ||
            signingHash.DigestLength < minimumDigestLength)
        {
            reason = minimumDigestLength switch
            {
                32 => "ML-DSA-44 CMS signatures require SHA256, SHA384, or SHA512.",
                48 => "ML-DSA-65 CMS signatures require SHA384 or SHA512.",
                64 => "ML-DSA-87 CMS signatures require SHA512.",
                _ => "The ML-DSA certificate algorithm is not supported."
            };
            return false;
        }

        reason = null;
        return true;
    }

    internal static bool IsMldsaPublicKeyEncodingCompatible(
        string algorithmOid,
        byte[] encodedParameters,
        byte[] encodedKeyValue,
        out string reason)
    {
        var expectedKeyLength = algorithmOid switch
        {
            KnownOids.MlDsa44Value => 1312,
            KnownOids.MlDsa65Value => 1952,
            KnownOids.MlDsa87Value => 2592,
            _ => 0
        };
        if (expectedKeyLength == 0)
        {
            reason = "The ML-DSA public-key algorithm is not supported.";
            return false;
        }

        if (encodedParameters is { Length: > 0 })
        {
            reason = "ML-DSA public-key AlgorithmIdentifier parameters must be absent.";
            return false;
        }

        if (encodedKeyValue is null || encodedKeyValue.Length != expectedKeyLength)
        {
            reason = "The ML-DSA public key does not have the length required by its algorithm identifier.";
            return false;
        }

        reason = null;
        return true;
    }

    internal static bool IsMldsaKeyUsageCompatible(X509KeyUsageFlags keyUsages, out string reason)
    {
        const X509KeyUsageFlags signatureUsages =
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation;
        const X509KeyUsageFlags forbiddenUsages =
            X509KeyUsageFlags.KeyEncipherment |
            X509KeyUsageFlags.DataEncipherment |
            X509KeyUsageFlags.KeyAgreement |
            X509KeyUsageFlags.EncipherOnly |
            X509KeyUsageFlags.DecipherOnly;
        if ((keyUsages & forbiddenUsages) != 0)
        {
            reason = "ML-DSA key usage must not permit key establishment or encryption.";
            return false;
        }

        if ((keyUsages & signatureUsages) == 0)
        {
            reason = "The ML-DSA key usage does not allow timestamp signatures or content commitment.";
            return false;
        }

        reason = null;
        return true;
    }

    internal static bool HasValidMldsaCertificateSignatureAlgorithmIdentifiers(
        byte[] rawCertificate,
        out string reason)
    {
        if (rawCertificate is null || rawCertificate.Length == 0)
        {
            reason = "The certificate encoding is empty.";
            return false;
        }

        try
        {
            DerReader outer = new(rawCertificate);
            var certificate = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            var encodedTbsCertificate = certificate.ReadEncodedValue();
            ReadAlgorithmIdentifier(certificate, out var outerAlgorithm, out var outerHasParameters);
            if (certificate.PeekTag() != 0x03)
            {
                reason = "The certificate signature value is malformed.";
                return false;
            }

            certificate.ReadEncodedValue();
            certificate.ThrowIfNotEmpty();

            DerReader encodedTbs = new(encodedTbsCertificate);
            var tbsCertificate = encodedTbs.ReadSequence();
            encodedTbs.ThrowIfNotEmpty();
            if (tbsCertificate.HasData && tbsCertificate.PeekTag() == 0xa0)
            {
                tbsCertificate.ReadEncodedValue();
            }

            if (!tbsCertificate.HasData || tbsCertificate.PeekTag() != 0x02)
            {
                reason = "The TBSCertificate serial number is malformed.";
                return false;
            }

            tbsCertificate.ReadEncodedValue();
            ReadAlgorithmIdentifier(tbsCertificate, out var innerAlgorithm, out var innerHasParameters);
            if (!IsMldsaOid(innerAlgorithm) && !IsMldsaOid(outerAlgorithm))
            {
                reason = null;
                return true;
            }

            if (!string.Equals(innerAlgorithm, outerAlgorithm, StringComparison.Ordinal))
            {
                reason = "The ML-DSA certificate signature AlgorithmIdentifiers do not match.";
                return false;
            }

            if (innerHasParameters || outerHasParameters)
            {
                reason = "ML-DSA certificate signature AlgorithmIdentifier parameters must be absent.";
                return false;
            }

            reason = null;
            return true;
        }
        catch (Exception ex) when (ex is DerEncodingException or ArgumentException or OverflowException)
        {
            reason = "The certificate signature AlgorithmIdentifiers are malformed: " + ex.Message;
            return false;
        }
    }

    private static void ReadAlgorithmIdentifier(
        DerReader parent,
        out string algorithmOid,
        out bool hasParameters)
    {
        var algorithmIdentifier = parent.ReadSequence();
        algorithmOid = algorithmIdentifier.ReadObjectIdentifier();
        hasParameters = algorithmIdentifier.HasData;
        if (hasParameters) algorithmIdentifier.ReadEncodedValue();
        algorithmIdentifier.ThrowIfNotEmpty();
    }

    internal static bool CanServeCachedSelectionDuringRefresh(
        bool hasCachedSelection,
        string requestedCacheKey,
        string cachedCacheKey,
        DateTime utcNow,
        DateTime cacheExpiresUtc,
        DateTime validationHorizonUtc) =>
        hasCachedSelection &&
        string.Equals(requestedCacheKey, cachedCacheKey, StringComparison.Ordinal) &&
        utcNow >= cacheExpiresUtc &&
        utcNow < validationHorizonUtc;

    private static bool CanAccessAssociatedPrivateKey(X509Certificate2 certificate, out string reason)
    {
        // Ask Windows to open the key silently and compare its public half with the certificate.
        // ML-DSA is CNG-only; RSA remains compatible with both legacy CSP and CNG providers.
        const uint cacheKey = 0x00000001;
        const uint compareKey = 0x00000004;
        const uint silent = 0x00000040;
        const uint allowNCrypt = 0x00010000;
        const uint onlyNCrypt = 0x00040000;
        var flags = cacheKey | compareKey | silent |
            (IsMldsaCertificate(certificate) ? onlyNCrypt : allowNCrypt);
        if (!CryptAcquireCertificatePrivateKey(
                certificate.Handle,
                flags,
                IntPtr.Zero,
                out var keyHandle,
                out var keySpec,
                out var callerFree))
        {
            var error = Marshal.GetLastWin32Error();
            reason = "The service account cannot access a private key matching this certificate: " +
                new Win32Exception(error).Message;
            return false;
        }

        using var acquiredKey = new AcquiredCertificatePrivateKeyHandle(
            keyHandle,
            callerFree,
            keySpec == uint.MaxValue);
        if (acquiredKey.IsInvalid)
        {
            reason = "Windows returned an invalid handle for the certificate's associated private key.";
            return false;
        }

        reason = null;
        return true;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptAcquireCertificatePrivateKey(
        IntPtr certificate,
        uint flags,
        IntPtr parameters,
        out IntPtr key,
        out uint keySpec,
        [MarshalAs(UnmanagedType.Bool)] out bool callerFree);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptReleaseContext(IntPtr provider, uint flags);

    [DllImport("ncrypt.dll", ExactSpelling = true)]
    private static extern int NCryptFreeObject(IntPtr handle);

    private sealed class AcquiredCertificatePrivateKeyHandle : SafeHandle
    {
        private readonly bool isNCrypt;

        internal AcquiredCertificatePrivateKeyHandle(IntPtr value, bool ownsHandle, bool isNCrypt)
            : base(IntPtr.Zero, ownsHandle)
        {
            this.isNCrypt = isNCrypt;
            SetHandle(value);
        }

        public override bool IsInvalid => handle == IntPtr.Zero || handle == new IntPtr(-1);

        protected override bool ReleaseHandle() =>
            isNCrypt ? NCryptFreeObject(handle) == 0 : CryptReleaseContext(handle, 0);
    }

    private static bool IsMldsaOid(string oid) =>
        string.Equals(oid, KnownOids.MlDsa44Value, StringComparison.Ordinal) ||
        string.Equals(oid, KnownOids.MlDsa65Value, StringComparison.Ordinal) ||
        string.Equals(oid, KnownOids.MlDsa87Value, StringComparison.Ordinal);

    internal static string BuildSelectionCacheKey(ServiceConfiguration configuration) =>
        (configuration.CertificateSelectionMode ?? string.Empty).Trim().ToUpperInvariant() + "|" +
        (configuration.CertificateStoreLocation ?? string.Empty).Trim().ToUpperInvariant() + "|" +
        (configuration.CertificateStoreName ?? string.Empty).Trim().ToUpperInvariant() + "|" +
        ConfigurationStore.NormalizeThumbprint(configuration.CertificateThumbprint) + "|" +
        HashAlgorithmCatalog.NormalizeName(configuration.SigningDigestAlgorithm) + "|" +
        (configuration.AuthenticodeEnabled ? "1" : "0") + "|" +
        (configuration.AllowUntrustedDevelopmentCertificate ? "1" : "0");

}

public sealed class CertificateSelectionException : Exception
{
    public CertificateSelectionException(string message)
        : base(message)
    {
    }
}
