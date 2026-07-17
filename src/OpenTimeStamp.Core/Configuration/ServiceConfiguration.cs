using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using OpenTimeStamp.Cryptography;

namespace OpenTimeStamp.Configuration;

[DataContract(Name = "OpenTimeStampConfiguration", Namespace = "urn:opentimestamp:configuration:v1")]
public sealed class ServiceConfiguration
{
    public const string ManualCertificateSelection = "Manual";
    public const string AutomaticCertificateSelection = "Automatic";
    public const string DailyLogRollover = "Daily";
    public const string HourlyLogRollover = "Hourly";
    public const string WeeklyLogRollover = "Weekly";

    public ServiceConfiguration()
    {
        // Start disabled with modern digest defaults so setup must explicitly select a certificate and policy.
        SchemaVersion = 1;
        Rfc3161Enabled = false;
        AuthenticodeEnabled = false;
        AuthenticationMode = "Anonymous";
        CertificateStoreLocation = StoreLocation.LocalMachine.ToString();
        CertificateStoreName = StoreName.My.ToString();
        CertificateSelectionMode = AutomaticCertificateSelection;
        AllowedHashAlgorithms = ["SHA256", "SHA384", "SHA512"];
        SigningDigestAlgorithm = "SHA256";
        IncludeCertificateChain = true;
        AccuracySeconds = 0;
        AccuracyMilliseconds = 0;
        Ordering = false;
        MaxRequestBytes = 65536;
        LogRetentionDays = 365;
        LogRolloverInterval = DailyLogRollover;
        PruneAuditLogs = true;
        FailClosedOnAuditError = true;
        LogMessageImprints = true;
        ClockRollbackToleranceSeconds = 2;
        AllowUntrustedDevelopmentCertificate = false;

        AdminAllowedWindowsGroups = ["BUILTIN\\Administrators"];
    }

    [DataMember(Order = 1)]
    public int SchemaVersion { get; set; }

    [DataMember(Order = 2)]
    public bool Rfc3161Enabled { get; set; }

    [DataMember(Order = 3)]
    public bool AuthenticodeEnabled { get; set; }

    [DataMember(Order = 4)]
    public string AuthenticationMode { get; set; }

    [DataMember(Order = 5)]
    public string CertificateStoreLocation { get; set; }

    [DataMember(Order = 6)]
    public string CertificateStoreName { get; set; }

    [DataMember(Order = 7)]
    public string CertificateThumbprint { get; set; }

    [DataMember(Order = 8)]
    public string DefaultPolicyOid { get; set; }

    [DataMember(Order = 9)]
    public List<string> AcceptedPolicyOids { get; set; }

    [DataMember(Order = 10)]
    public List<string> AllowedHashAlgorithms { get; set; }

    [DataMember(Order = 11)]
    public string SigningDigestAlgorithm { get; set; }

    [DataMember(Order = 12)]
    public bool IncludeCertificateChain { get; set; }

    [DataMember(Order = 13)]
    public int AccuracySeconds { get; set; }

    [DataMember(Order = 14)]
    public int AccuracyMilliseconds { get; set; }

    [DataMember(Order = 15)]
    public bool Ordering { get; set; }

    [DataMember(Order = 16)]
    public int MaxRequestBytes { get; set; }

    [DataMember(Order = 17)]
    public int LogRetentionDays { get; set; }

    [DataMember(Order = 18)]
    public List<string> AdminAllowedWindowsGroups { get; set; }

    [DataMember(Order = 19)]
    public bool FailClosedOnAuditError { get; set; }

    [DataMember(Order = 20)]
    public bool LogMessageImprints { get; set; }

    [DataMember(Order = 21)]
    public int ClockRollbackToleranceSeconds { get; set; }

    [DataMember(Order = 22)]
    public bool AllowUntrustedDevelopmentCertificate { get; set; }

    [DataMember(Order = 23)]
    public string CertificateSelectionMode { get; set; }

    [DataMember(Order = 24)]
    public string LogRolloverInterval { get; set; }

    [DataMember(Order = 25)]
    public bool PruneAuditLogs { get; set; }

    public bool UsesAutomaticCertificateSelection =>
        string.Equals(CertificateSelectionMode, AutomaticCertificateSelection, StringComparison.OrdinalIgnoreCase);

    public ServiceConfiguration Clone()
    {
        var clone = (ServiceConfiguration)MemberwiseClone();
        clone.AcceptedPolicyOids = AcceptedPolicyOids is null ? [] : [.. AcceptedPolicyOids];
        clone.AllowedHashAlgorithms = AllowedHashAlgorithms is null ? [] : [.. AllowedHashAlgorithms];
        clone.AdminAllowedWindowsGroups = AdminAllowedWindowsGroups is null ? [] : [.. AdminAllowedWindowsGroups];
        return clone;
    }

    public IList<string> Validate()
    {
        List<string> errors = new();

        // Validate schema, authentication, and certificate-store selectors.
        if (SchemaVersion != 1) errors.Add("The settings file version is not supported by this release.");

        if (!string.Equals(AuthenticationMode, "Anonymous", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(AuthenticationMode, "Windows", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("The IIS authentication mode must be Anonymous or Windows.");
        }

        if (!Enum.TryParse(CertificateStoreLocation, true, out StoreLocation location) ||
            location is not (StoreLocation.LocalMachine or StoreLocation.CurrentUser))
        {
            errors.Add("The certificate store must be Local Computer or Current User.");
        }

        if (!Enum.TryParse(CertificateStoreName, true, out StoreName storeName) || storeName != StoreName.My)
        {
            errors.Add("Only the Personal (My) certificate store is supported.");
        }

        if (!string.Equals(CertificateSelectionMode, ManualCertificateSelection, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(CertificateSelectionMode, AutomaticCertificateSelection, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Certificate selection mode must be Manual or Automatic.");
        }

        // Validate the default and accepted RFC 3161 policy set.
        if (!string.IsNullOrWhiteSpace(DefaultPolicyOid) && !IsValidOid(DefaultPolicyOid))
        {
            errors.Add("The default RFC 3161 policy OID is not valid.");
        }

        if (Rfc3161Enabled && string.IsNullOrWhiteSpace(DefaultPolicyOid))
        {
            errors.Add("Enter a default RFC 3161 policy OID before enabling the RFC 3161 endpoint.");
        }

        var policies = AcceptedPolicyOids ?? [];
        if (policies.Any(policy => !IsValidOid(policy)))
        {
            errors.Add("Every allowed RFC 3161 policy OID must be valid.");
        }

        if (!string.IsNullOrWhiteSpace(DefaultPolicyOid) && !policies.Contains(DefaultPolicyOid, StringComparer.Ordinal))
        {
            errors.Add("The allowed RFC 3161 policy OIDs must include the default policy OID.");
        }

        // Validate request and CMS digest choices against the implemented catalog.
        var hashes = AllowedHashAlgorithms ?? [];
        if (hashes.Count == 0 || hashes.Any(hash => HashAlgorithmCatalog.FindByName(hash) is null))
        {
            errors.Add("Enable at least one supported request hash algorithm.");
        }

        var signingHash = HashAlgorithmCatalog.FindByName(SigningDigestAlgorithm);
        if (signingHash is null || !signingHash.CmsSigningSupported)
        {
            errors.Add("The timestamp signing hash must be SHA-1, SHA-256, SHA-384, or SHA-512.");
        }

        if ((Rfc3161Enabled || AuthenticodeEnabled) && !UsesAutomaticCertificateSelection &&
            string.IsNullOrWhiteSpace(CertificateThumbprint))
        {
            errors.Add("Select a timestamp signing certificate before enabling a timestamp endpoint in Manual mode.");
        }

        // Bound operational settings and keep clock rollback claims internally consistent.
        if (AccuracySeconds is < 0 or > 86400 || AccuracyMilliseconds is < 0 or > 999)
        {
            errors.Add("Published time accuracy must be 0–86,400 seconds and 0–999 milliseconds.");
        }

        if (MaxRequestBytes is < 1024 or > 1048576)
        {
            errors.Add("Maximum request size must be from 1,024 through 1,048,576 bytes.");
        }

        if (LogRetentionDays is < 1 or > 3650)
        {
            errors.Add("Audit log retention must be from 1 through 3,650 days.");
        }

        if (!string.Equals(LogRolloverInterval, DailyLogRollover, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(LogRolloverInterval, HourlyLogRollover, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(LogRolloverInterval, WeeklyLogRollover, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Audit log rotation must be Daily, Hourly, or Weekly.");
        }

        if (ClockRollbackToleranceSeconds is < 0 or > 300)
        {
            errors.Add("Allowed backward clock adjustment must be from 0 through 300 seconds.");
        }

        var claimedAccuracyMilliseconds = ((long)AccuracySeconds * 1000L) + AccuracyMilliseconds;
        if (claimedAccuracyMilliseconds > 0 && ((long)ClockRollbackToleranceSeconds * 1000L) > claimedAccuracyMilliseconds)
        {
            errors.Add("Allowed backward clock adjustment cannot exceed the published time accuracy.");
        }

        if (AdminAllowedWindowsGroups is null || AdminAllowedWindowsGroups.Count == 0)
        {
            errors.Add("Add at least one Windows group or SID allowed to administer OpenTimeStamp.");
        }

        return errors;
    }

    private static bool IsValidOid(string value)
    {
        try
        {
            Asn1.DerWriter writer = new();
            writer.WriteObjectIdentifier((value ?? string.Empty).Trim());
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
