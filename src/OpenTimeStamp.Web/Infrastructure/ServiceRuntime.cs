using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Issuance;

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
    string protocol,
    string result,
    string correlationId,
    string username,
    string userSid,
    string authenticationType,
    string remoteAddress,
    long durationMilliseconds)
{
    internal DateTime TimestampUtc { get; } = timestampUtc;

    internal string Protocol { get; } = protocol;

    internal string Result { get; } = result;

    internal string CorrelationId { get; } = correlationId;

    internal string Username { get; } = username;

    internal string UserSid { get; } = userSid;

    internal string AuthenticationType { get; } = authenticationType;

    internal string RemoteAddress { get; } = remoteAddress;

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
        Func<long> timestampProvider = null)
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

internal sealed class WebRuntimeSettings
{
    internal string AuthenticationMode { get; private set; }

    internal TimeSpan BodyReadDeadline { get; private set; }

    internal int BodyIntakeLimit { get; private set; }

    internal int BodyIntakePerClientLimit { get; private set; }

    internal int ProcessingLimit { get; private set; }

    internal int ProcessingPerClientLimit { get; private set; }

    internal static WebRuntimeSettings Load()
    {
        var authenticationMode = (ConfigurationManager.AppSettings["AuthenticationMode"] ?? string.Empty).Trim();
        if (!string.Equals(authenticationMode, "Anonymous", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(authenticationMode, "Windows", StringComparison.OrdinalIgnoreCase))
        {
            throw new OpenTimeStamp.Configuration.ConfigurationErrorsException(
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
        return new WebRuntimeSettings
        {
            AuthenticationMode = authenticationMode,
            BodyReadDeadline = TimeSpan.FromSeconds(ParseBoundedSetting(
                "TimestampBodyReadTimeoutSeconds",
                10,
                1,
                25)),
            BodyIntakeLimit = bodyIntakeLimit,
            BodyIntakePerClientLimit = bodyIntakePerClientLimit,
            ProcessingLimit = processingLimit,
            ProcessingPerClientLimit = processingPerClientLimit
        };
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

        throw new OpenTimeStamp.Configuration.ConfigurationErrorsException(
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
    private static CachedConfiguration cachedConfiguration;
    private static long nextConfigurationRefreshTimestamp;
    private static long configurationVersion;
    private static readonly RecentRequestTracker RecentRequests = new(
        RecentRequestCapacity,
        TimeSpan.FromHours(RecentRequestMaximumAgeHours));

    public static ConfigurationStore Configuration { get; private set; }

    public static CertificateRepository Certificates { get; private set; }

    public static IssuanceStateStore IssuanceState { get; private set; }

    public static AuditLogger Audit { get; private set; }

    public static string DataDirectory { get; private set; }

    internal static DateTime StartedUtc { get; private set; }

    internal static WebRuntimeSettings Settings { get; private set; }

    internal static string AdmissionScopeName { get; private set; }

    internal static long ConfigurationVersion => Interlocked.Read(ref configurationVersion);

    internal static IReadOnlyList<RecentRequestActivity> GetRecentRequests(int maximum) =>
        RecentRequests.Snapshot(maximum);

    internal static void TryRecordRecentRequest(AuditRecord record)
    {
        try
        {
            RecentRequests.Record(record);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and
                                   not StackOverflowException and
                                   not ThreadAbortException)
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
        if (cached != null && IsBefore(now, Interlocked.Read(ref nextConfigurationRefreshTimestamp)))
            return CreateSnapshot(cached);

        lock (ConfigurationGate)
        {
            now = Stopwatch.GetTimestamp();
            cached = cachedConfiguration;
            if (cached != null && IsBefore(now, nextConfigurationRefreshTimestamp)) return CreateSnapshot(cached);

            if (cached != null)
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

    internal static X509Certificate2 GetSelectedCertificate(ServiceRuntimeSnapshot snapshot)
    {
        if (snapshot is null) throw new ArgumentNullException(nameof(snapshot));
        EnsureInitialized();
        return Certificates.GetSelectedCertificate(snapshot.Configuration);
    }

    public static void Initialize(string applicationPath)
    {
        lock (Gate)
        {
            if (initialized) return;
            if (string.IsNullOrWhiteSpace(applicationPath))
                throw new InvalidOperationException("The IIS application path is unavailable.");

            // Build every shared dependency locally before publishing the initialized runtime.
            var settings = WebRuntimeSettings.Load();
            var configuredPath = Environment.ExpandEnvironmentVariables(
                ConfigurationManager.AppSettings["DataPath"] ?? string.Empty).Trim();
            var dataDirectory = string.IsNullOrEmpty(configuredPath)
                ? Path.Combine(applicationPath, "App_Data")
                : Path.IsPathRooted(configuredPath) ? configuredPath : Path.Combine(applicationPath, configuredPath);
            dataDirectory = Path.GetFullPath(dataDirectory);
            var configuration = new ConfigurationStore(Path.Combine(dataDirectory, "tsa.config"));
            var certificates = new CertificateRepository();
            var issuanceState = new IssuanceStateStore(Path.Combine(dataDirectory, "issuance.state"));
            var audit = new AuditLogger(Path.Combine(dataDirectory, "Logs"));

            Settings = settings;
            DataDirectory = dataDirectory;
            Configuration = configuration;
            Certificates = certificates;
            IssuanceState = issuanceState;
            Audit = audit;
            AdmissionScopeName = CreateAdmissionScopeName(dataDirectory);
            StartedUtc = DateTime.UtcNow;
            initialized = true;
        }
    }

    internal static void Shutdown() => Certificates?.Dispose();

    private static CachedConfiguration PublishConfigurationLocked(
        ServiceConfiguration configuration,
        string generation,
        long now)
    {
        var published = new CachedConfiguration(
            configuration.Clone(),
            generation,
            Interlocked.Increment(ref configurationVersion));
        Volatile.Write(ref cachedConfiguration, published);
        Interlocked.Exchange(
            ref nextConfigurationRefreshTimestamp,
            AddStopwatchTicks(now, ConfigurationRefreshTicks));
        Certificates?.InvalidateSelectionCache();
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

    private static string CreateAdmissionScopeName(string dataDirectory)
    {
        var canonicalPath = Path.GetFullPath(dataDirectory).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
        var digest = WindowsHash.ComputeSha256(Encoding.Unicode.GetBytes(canonicalPath));
        var builder = new StringBuilder(32);
        for (var index = 0; index < 16; index++)
            builder.Append(digest[index].ToString("x2", CultureInfo.InvariantCulture));
        return "Local\\OpenTimeStamp-" + builder;
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
