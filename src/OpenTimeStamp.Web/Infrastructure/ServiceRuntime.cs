using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Infrastructure;
using OpenTimeStamp.Issuance;
using ConfigurationErrorsException = OpenTimeStamp.Configuration.ConfigurationErrorsException;

namespace OpenTimeStamp.Web.Infrastructure;

internal sealed class ServiceRuntimeSnapshot(
    ServiceConfiguration configuration,
    string generation,
    long configurationVersion,
    bool fipsEnabled)
{
    internal ServiceConfiguration Configuration { get; } = configuration;

    internal string Generation { get; } = generation;

    internal long ConfigurationVersion { get; } = configurationVersion;

    internal bool FipsEnabled { get; } = fipsEnabled;
}

internal sealed class RecentRequestActivity(
    DateTime timestampUtc,
    string? protocol,
    string? result,
    string? correlationId,
    string? username,
    string? userSid,
    string? authenticationType,
    string? remoteAddress,
    long durationMilliseconds)
{
    internal DateTime TimestampUtc { get; } = timestampUtc;

    internal string? Protocol { get; } = protocol;

    internal string? Result { get; } = result;

    internal string? CorrelationId { get; } = correlationId;

    internal string? Username { get; } = username;

    internal string? UserSid { get; } = userSid;

    internal string? AuthenticationType { get; } = authenticationType;

    internal string? RemoteAddress { get; } = remoteAddress;

    internal long DurationMilliseconds { get; } = durationMilliseconds;
}

internal sealed class RecentRequestTracker
{
    private readonly int capacity;
    private readonly object gate = new();
    private readonly long maximumAgeTicks;
    private readonly Func<long> timestampProvider;
    private readonly Queue<RetainedRequest> records = new();

    internal RecentRequestTracker(
        int capacity,
        TimeSpan maximumAge,
        Func<long>? timestampProvider = null)
    {
        if (capacity is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(capacity));
        if (maximumAge <= TimeSpan.Zero || maximumAge > TimeSpan.FromDays(7))
            throw new ArgumentOutOfRangeException(nameof(maximumAge));

        this.capacity = capacity;
        maximumAgeTicks = ToStopwatchTicks(maximumAge);
        this.timestampProvider = timestampProvider ?? Stopwatch.GetTimestamp;
    }

    internal void Record(AuditRecord record)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        RecentRequestActivity activity = new(
            record.TimestampUtc.ToUniversalTime(),
            record.Protocol,
            record.Result,
            record.CorrelationId,
            record.Username,
            record.UserSid,
            record.AuthenticationType,
            record.RemoteAddress,
            record.DurationMilliseconds);
        lock (gate)
        {
            var observedTimestamp = timestampProvider();
            RemoveExpired(observedTimestamp);
            while (records.Count >= capacity) records.Dequeue();
            records.Enqueue(new RetainedRequest(activity, observedTimestamp));
        }
    }

    internal IReadOnlyList<RecentRequestActivity> Snapshot(int maximum)
    {
        if (maximum < 1 || maximum > capacity) throw new ArgumentOutOfRangeException(nameof(maximum));
        lock (gate)
        {
            var observedTimestamp = timestampProvider();
            RemoveExpired(observedTimestamp);
            return records.Reverse()
                .Select(record => record.Activity)
                .Take(maximum)
                .ToList();
        }
    }

    private void RemoveExpired(long observedTimestamp)
    {
        while (records.Count != 0)
        {
            var elapsed = observedTimestamp - records.Peek().ObservedTimestamp;
            if (elapsed < 0 || elapsed < maximumAgeTicks) return;
            records.Dequeue();
        }
    }

    private static long ToStopwatchTicks(TimeSpan interval) =>
        checked((long)Math.Ceiling(interval.TotalSeconds * Stopwatch.Frequency));

    private sealed class RetainedRequest(RecentRequestActivity activity, long observedTimestamp)
    {
        internal RecentRequestActivity Activity { get; } = activity;

        internal long ObservedTimestamp { get; } = observedTimestamp;
    }
}

internal sealed class WebRuntimeSettings(
    string authenticationMode,
    TimeSpan bodyReadDeadline,
    int bodyIntakeLimit,
    int bodyIntakePerClientLimit,
    int processingLimit,
    int processingPerClientLimit)
{
    internal string AuthenticationMode { get; } = authenticationMode;

    internal TimeSpan BodyReadDeadline { get; } = bodyReadDeadline;

    internal int BodyIntakeLimit { get; } = bodyIntakeLimit;

    internal int BodyIntakePerClientLimit { get; } = bodyIntakePerClientLimit;

    internal int ProcessingLimit { get; } = processingLimit;

    internal int ProcessingPerClientLimit { get; } = processingPerClientLimit;

    internal static WebRuntimeSettings Load()
    {
        var authenticationMode = (ConfigurationManager.AppSettings["AuthenticationMode"] ?? string.Empty).Trim();
        if (!ServiceConfiguration.IsAuthenticationMode(authenticationMode))
        {
            throw new ConfigurationErrorsException(
                "The IIS authentication setting must be Anonymous or Windows and cannot be changed while the service is running.");
        }

        var bodyIntakeLimit = ParseBoundedSetting("TimestampBodyIntakeLimit", 32, 1, 256);
        var processingLimit = ParseBoundedSetting("TimestampProcessingLimit", 4, 1, 64);
        var bodyIntakePerClientLimit = ParseBoundedSetting(
            "TimestampBodyIntakePerClientLimit",
            Math.Min(4, bodyIntakeLimit),
            1,
            bodyIntakeLimit);
        var processingPerClientLimit = ParseBoundedSetting(
            "TimestampProcessingPerClientLimit",
            Math.Min(2, processingLimit),
            1,
            processingLimit);
        return new WebRuntimeSettings(
            authenticationMode,
            TimeSpan.FromSeconds(ParseBoundedSetting("TimestampBodyReadTimeoutSeconds", 10, 1, 25)),
            bodyIntakeLimit,
            bodyIntakePerClientLimit,
            processingLimit,
            processingPerClientLimit);
    }

    internal static int ParseBoundedSetting(string key, int fallback, int minimum, int maximum) =>
        ParseBoundedSetting(key, ConfigurationManager.AppSettings[key], fallback, minimum, maximum);

    internal static int ParseBoundedSetting(
        string key,
        string value,
        int fallback,
        int minimum,
        int maximum)
    {
        if (string.IsNullOrWhiteSpace(value)) return fallback;
        if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) &&
            parsed >= minimum && parsed <= maximum)
        {
            return parsed;
        }

        throw new ConfigurationErrorsException(
            key + " must be an integer between " + minimum.ToString(CultureInfo.InvariantCulture) + " and " +
            maximum.ToString(CultureInfo.InvariantCulture) + ".");
    }
}

internal static class ServiceRuntime
{
    internal const int RecentRequestCapacity = 100;
    internal const int RecentRequestMaximumAgeHours = 24;
    private static readonly object Gate = new();
    private static readonly object ConfigurationGate = new();
    private static readonly long ConfigurationRefreshTicks = Stopwatch.Frequency;
    private static volatile bool initialized;
    private static CachedConfiguration? cachedConfiguration;
    private static long nextConfigurationRefreshTimestamp;
    private static long configurationVersion;
    private static Func<ServiceConfiguration, X509Certificate2>? selectionLoader;
    private static readonly RecentRequestTracker RecentRequests = new(
        RecentRequestCapacity,
        TimeSpan.FromHours(RecentRequestMaximumAgeHours));

    // Start assigns every shared service before the first request is routed. Only shutdown and
    // the application error handler can run earlier, and both check for an absent service.
    public static ConfigurationStore Configuration { get; private set; } = null!;

    public static CertificateRepository Certificates { get; private set; } = null!;

    public static IssuanceStateStore IssuanceState { get; private set; } = null!;

    public static AuditLogger Audit { get; private set; } = null!;

    public static DiagnosticLogger Diagnostics { get; private set; } = null!;

    public static string DataDirectory { get; private set; } = null!;

    internal static DateTime StartedUtc { get; private set; }

    internal static WebRuntimeSettings Settings { get; private set; } = null!;

    internal static long ConfigurationVersion => Interlocked.Read(ref configurationVersion);

    internal static IReadOnlyList<RecentRequestActivity> GetRecentRequests(int maximum) =>
        RecentRequests.Snapshot(maximum);

    internal static void TryRecordRecentRequest(AuditRecord record)
    {
        try
        {
            RecentRequests.Record(record);
        }
        catch (Exception ex) when (ex.IsContainable())
        {
            // Dashboard activity is explicitly non-authoritative and must not affect issuance.
        }
    }

    public static ServiceConfiguration LoadConfiguration() => LoadSnapshot().Configuration;

    public static ServiceConfiguration LoadConfiguration(out string generation)
    {
        var snapshot = LoadSnapshot();
        generation = snapshot.Generation;
        return snapshot.Configuration;
    }

    internal static ServiceRuntimeSnapshot LoadSnapshot()
    {
        EnsureInitialized();
        var now = Stopwatch.GetTimestamp();
        var cached = Volatile.Read(ref cachedConfiguration);
        if (cached is not null && IsBefore(now, Interlocked.Read(ref nextConfigurationRefreshTimestamp)))
            return CreateSnapshot(cached);

        lock (ConfigurationGate)
        {
            now = Stopwatch.GetTimestamp();
            cached = cachedConfiguration;
            if (cached is not null && IsBefore(now, nextConfigurationRefreshTimestamp)) return CreateSnapshot(cached);

            if (cached is not null)
            {
                var currentGeneration = Configuration.GetGeneration();
                if (string.Equals(currentGeneration, cached.Generation, StringComparison.Ordinal))
                {
                    nextConfigurationRefreshTimestamp = AddStopwatchTicks(now, ConfigurationRefreshTicks);
                    return CreateSnapshot(cached);
                }
            }

            var loaded = LoadEffectiveConfiguration(out var generation);
            cached = PublishConfigurationLocked(loaded, generation, now);
            return CreateSnapshot(cached);
        }
    }

    internal static void PublishConfiguration(ServiceConfiguration configuration, string generation)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));
        if (string.IsNullOrWhiteSpace(generation))
            throw new ArgumentException("A generation is required.", nameof(generation));
        EnsureInitialized();
        var effective = configuration.Clone();
        effective.AuthenticationMode = Settings.AuthenticationMode;
        lock (ConfigurationGate)
        {
            PublishConfigurationLocked(effective, generation, Stopwatch.GetTimestamp());
        }
    }

    internal static X509Certificate2 GetSelectedCertificate(
        ServiceRuntimeSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        if (snapshot is null) throw new ArgumentNullException(nameof(snapshot));
        return GetSelectedCertificate(snapshot.Configuration, cancellationToken);
    }

    internal static X509Certificate2 GetSelectedCertificate(
        ServiceConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        return selectionLoader is null
            ? Certificates.GetSelectedCertificate(configuration, cancellationToken)
            : selectionLoader(configuration);
    }

    public static void Initialize(string applicationPath)
    {
        lock (Gate)
        {
            if (initialized) return;
            if (string.IsNullOrWhiteSpace(applicationPath))
                throw new InvalidOperationException("The IIS application path is unavailable.");

            var settings = WebRuntimeSettings.Load();
            var configuredPath = Environment.ExpandEnvironmentVariables(
                ConfigurationManager.AppSettings["DataPath"] ?? string.Empty).Trim();
            var dataDirectory = string.IsNullOrEmpty(configuredPath)
                ? Path.Combine(applicationPath, "App_Data")
                : Path.IsPathRooted(configuredPath) ? configuredPath : Path.Combine(applicationPath, configuredPath);
            Start(dataDirectory, settings, null);
        }
    }

    /// <summary>
    /// Replaces the runtime with one over an explicit data directory, limits, and certificate
    /// loader, so handler tests need neither IIS configuration nor a certificate store.
    /// </summary>
    internal static void Restart(
        string dataDirectory,
        WebRuntimeSettings settings,
        Func<ServiceConfiguration, X509Certificate2>? loadSelection)
    {
        lock (Gate)
        {
            Certificates?.Dispose();
            lock (ConfigurationGate)
            {
                Volatile.Write(ref cachedConfiguration, null);
                nextConfigurationRefreshTimestamp = 0;
            }

            Start(dataDirectory, settings, loadSelection);
        }
    }

    private static void Start(
        string dataDirectory,
        WebRuntimeSettings settings,
        Func<ServiceConfiguration, X509Certificate2>? loadSelection)
    {
        // Build every shared dependency locally before publishing the initialized runtime.
        dataDirectory = Path.GetFullPath(dataDirectory);
        var configuration = new ConfigurationStore(Path.Combine(dataDirectory, "tsa.config"));
        var certificates = new CertificateRepository();
        var issuanceState = new IssuanceStateStore(Path.Combine(dataDirectory, "issuance.state"));
        var diagnostics = new DiagnosticLogger(Path.Combine(dataDirectory, "Diagnostics"), dataDirectory);
        var audit = new AuditLogger(Path.Combine(dataDirectory, "Logs"), diagnostics.Record);

        Settings = settings;
        DataDirectory = dataDirectory;
        Configuration = configuration;
        Certificates = certificates;
        IssuanceState = issuanceState;
        Audit = audit;
        Diagnostics = diagnostics;
        selectionLoader = loadSelection;
        StartedUtc = DateTime.UtcNow;
        initialized = true;

        // Configure diagnostic destinations before the first request can raise an error.
        try
        {
            _ = LoadSnapshot();
        }
        catch (ConfigurationErrorsException ex)
        {
            Diagnostics.Record(new AuditRecord
            {
                EventType = "configuration-load-failure",
                Result = "error",
                Detail = ex.ToString()
            });
        }
    }

    internal static void Shutdown() => Certificates?.Dispose();

    private static CachedConfiguration PublishConfigurationLocked(
        ServiceConfiguration configuration,
        string generation,
        long now)
    {
        var firstConfiguration = cachedConfiguration is null;
        var published = new CachedConfiguration(
            configuration.Clone(),
            generation,
            Interlocked.Increment(ref configurationVersion));
        Volatile.Write(ref cachedConfiguration, published);
        Diagnostics?.Configure(configuration);
        Interlocked.Exchange(
            ref nextConfigurationRefreshTimestamp,
            AddStopwatchTicks(now, ConfigurationRefreshTicks));
        Certificates?.InvalidateSelectionCache();
        if (firstConfiguration)
        {
            // Record worker startup only after its configured diagnostic destinations are known.
            Diagnostics?.Record(new AuditRecord
            {
                EventType = "service-started",
                Result = "information",
                Detail = "The timestamp service worker started."
            });
        }
        return published;
    }

    private static ServiceRuntimeSnapshot CreateSnapshot(CachedConfiguration cached) =>
        new(cached.Configuration.Clone(), cached.Generation, cached.Version, PlatformSecurityPolicy.IsFipsEnabled);

    private static ServiceConfiguration LoadEffectiveConfiguration(out string generation)
    {
        var configuration = Configuration.Load(out generation);
        configuration.AuthenticationMode = Settings.AuthenticationMode;
        return configuration;
    }

    private static bool IsBefore(long timestamp, long deadline)
    {
        var remaining = deadline - timestamp;
        return remaining > 0;
    }

    private static long AddStopwatchTicks(long timestamp, long interval) =>
        timestamp > long.MaxValue - interval ? long.MaxValue : timestamp + interval;

    private static void EnsureInitialized()
    {
        if (!initialized)
            throw new InvalidOperationException("The timestamp service runtime has not been initialized.");
    }

    private sealed class CachedConfiguration(
        ServiceConfiguration configuration,
        string generation,
        long version)
    {
        internal ServiceConfiguration Configuration { get; } = configuration;

        internal string Generation { get; } = generation;

        internal long Version { get; } = version;
    }
}
