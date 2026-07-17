using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Hosting;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Web.Infrastructure;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Issuance;

namespace OpenTimeStamp.Web.Handlers;

internal static class HealthRefreshScheduler
{
    internal static void Queue(
        Action<CancellationToken> refresh,
        Action timeout,
        Action completed,
        TimeSpan timeoutDelay)
    {
        Func<CancellationToken, Task> workItem = cancellationToken =>
            RunAsync(refresh, timeout, completed, timeoutDelay, Task.Delay, cancellationToken);
        HostingEnvironment.QueueBackgroundWorkItem(workItem);
    }

    internal static async Task RunAsync(
        Action<CancellationToken> refresh,
        Action timeout,
        Action completed,
        TimeSpan timeoutDelay,
        Func<TimeSpan, CancellationToken, Task> delayAsync,
        CancellationToken shutdownToken)
    {
        var missingCallback = refresh is null ? nameof(refresh) : timeout is null ? nameof(timeout) :
            completed is null ? nameof(completed) : delayAsync is null ? nameof(delayAsync) : null;
        if (missingCallback != null) throw new ArgumentNullException(missingCallback);
        if (timeoutDelay <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeoutDelay));

        await Task.Yield();
        try
        {
            using var timeoutCancellation = new CancellationTokenSource();
            var timeoutTask = PublishTimeoutAsync(timeout, timeoutDelay, delayAsync, timeoutCancellation.Token);
            try
            {
                refresh(shutdownToken);
            }
            finally
            {
                timeoutCancellation.Cancel();
                await timeoutTask.ConfigureAwait(false);
            }
        }
        finally
        {
            completed();
        }
    }

    private static async Task PublishTimeoutAsync(
        Action timeout,
        TimeSpan timeoutDelay,
        Func<TimeSpan, CancellationToken, Task> delayAsync,
        CancellationToken cancellationToken)
    {
        try
        {
            await delayAsync(timeoutDelay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        if (!cancellationToken.IsCancellationRequested) timeout();
    }
}

internal sealed class HealthHandler : IHttpHandler
{
    internal const int CacheDurationSeconds = 30;
    internal const int StaleGraceSeconds = 15;
    private const int ProbeTimeoutSeconds = 15;
    private static readonly long CacheDurationTicks = Stopwatch.Frequency * CacheDurationSeconds;
    private static readonly long StaleGraceTicks = Stopwatch.Frequency * StaleGraceSeconds;
    private static HealthSnapshot cachedHealth;
    private static long invalidationVersion;
    private static int refreshInProgress;

    public bool IsReusable => false;

    public void ProcessRequest(HttpContext context)
    {
        // Expose only a minimal liveness result through safe retrieval methods.
        if (!string.Equals(context.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(context.Request.HttpMethod, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers["Allow"] = "GET, HEAD";
            HttpSupport.WritePlainError(context, 405, "Method not allowed.");
            return;
        }

        var health = GetHealth();
        context.Response.StatusCode = health.Healthy ? 200 : 503;
        context.Response.TrySkipIisCustomErrors = true;
        context.Response.ContentType = "application/json; charset=utf-8";
        if (!string.Equals(context.Request.HttpMethod, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Write("{\"status\":\"" + (health.Healthy ? "healthy" : "degraded") +
                "\",\"fipsPolicy\":" + (health.FipsEnabled ? "true" : "false") + "}");
        }
    }

    internal static void Invalidate() => Interlocked.Increment(ref invalidationVersion);

    internal static HealthResult GetHealth()
    {
        var now = Stopwatch.GetTimestamp();
        var fipsEnabled = PlatformSecurityPolicy.IsFipsEnabled;
        var configurationVersion = ServiceRuntime.ConfigurationVersion;
        var currentInvalidation = Interlocked.Read(ref invalidationVersion);
        var cached = Volatile.Read(ref cachedHealth);
        var cacheKeyMatches = cached != null && cached.FipsEnabled == fipsEnabled &&
            cached.ConfigurationVersion == configurationVersion &&
            cached.InvalidationVersion == currentInvalidation;
        if (cacheKeyMatches && IsFresh(now, cached.Timestamp))
        {
            return new HealthResult(
                cached.Healthy,
                cached.FipsEnabled,
                true,
                false,
                Volatile.Read(ref refreshInProgress) != 0,
                cached.Detail);
        }

        StartRefresh();
        var refreshing = Volatile.Read(ref refreshInProgress) != 0;
        if (ShouldServeStale(cacheKeyMatches, now, cached?.Timestamp ?? 0))
            return new HealthResult(cached.Healthy, cached.FipsEnabled, true, true, refreshing, cached.Detail);
        return new HealthResult(false, fipsEnabled, false, false, refreshing, null);
    }

    private static void StartRefresh()
    {
        if (Interlocked.CompareExchange(ref refreshInProgress, 1, 0) != 0) return;
        try
        {
            var refresh = new RefreshWork(Interlocked.Read(ref invalidationVersion));
            HealthRefreshScheduler.Queue(
                cancellationToken => Refresh(refresh, cancellationToken),
                () => TimeoutRefresh(refresh),
                () => Interlocked.Exchange(ref refreshInProgress, 0),
                TimeSpan.FromSeconds(ProbeTimeoutSeconds));
            return;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and
                                   not StackOverflowException and
                                   not ThreadAbortException)
        {
            // A health request remains fail-fast and degraded if background work cannot be scheduled.
        }

        Interlocked.Exchange(ref refreshInProgress, 0);
    }

    private static void Refresh(RefreshWork refresh, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var snapshot = ServiceRuntime.LoadSnapshot();
            cancellationToken.ThrowIfCancellationRequested();
            var evaluation = EvaluateHealth(snapshot, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            CompleteRefresh(refresh, new HealthSnapshot(
                evaluation.Healthy,
                snapshot.FipsEnabled,
                snapshot.ConfigurationVersion,
                refresh.InvalidationVersion,
                Stopwatch.GetTimestamp(),
                evaluation.Detail));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // ASP.NET is shutting down; do not publish a result from an abandoned probe.
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and
                                   not StackOverflowException and
                                   not ThreadAbortException)
        {
            CompleteRefresh(refresh, CreateDegradedSnapshot(
                refresh.InvalidationVersion,
                Stopwatch.GetTimestamp(),
                "The service health check failed unexpectedly."));
        }
    }

    private static void TimeoutRefresh(RefreshWork refresh)
    {
        lock (refresh.PublicationGate)
        {
            if (refresh.Completion != 0) return;
            Volatile.Write(ref cachedHealth, CreateDegradedSnapshot(
                refresh.InvalidationVersion,
                Stopwatch.GetTimestamp(),
                "The service health check timed out after 15 seconds."));
            refresh.Completion = 2;
        }
    }

    private static void CompleteRefresh(RefreshWork refresh, HealthSnapshot health)
    {
        lock (refresh.PublicationGate)
        {
            if (refresh.Completion == 1) return;
            Volatile.Write(ref cachedHealth, health);
            refresh.Completion = 1;
        }
    }

    private static HealthSnapshot CreateDegradedSnapshot(
        long observedInvalidation,
        long timestamp,
        string detail) =>
        new(
            false,
            PlatformSecurityPolicy.IsFipsEnabled,
            ServiceRuntime.ConfigurationVersion,
            observedInvalidation,
            timestamp,
            detail);

    private static HealthEvaluation EvaluateHealth(ServiceRuntimeSnapshot snapshot, CancellationToken cancellationToken)
    {
        try
        {
            // Validate configuration, FIPS policy, key access, and writable durable state.
            var configuration = snapshot.Configuration;
            var policyFailure = HealthPolicy.GetConfigurationPolicyFailure(configuration, snapshot.FipsEnabled);
            if (policyFailure != null) return new HealthEvaluation(false, policyFailure);

            var utcNow = DateTime.UtcNow;
            cancellationToken.ThrowIfCancellationRequested();
            var certificateValidationTimeUtc = HealthPolicy.GetRuntimeCertificateValidationTimeUtc(
                configuration,
                utcNow);
            cancellationToken.ThrowIfCancellationRequested();
            if (!ServiceRuntime.Certificates.ValidateSelection(
                    configuration,
                    certificateValidationTimeUtc,
                    out var certificateFailure))
            {
                return new HealthEvaluation(
                    false,
                    certificateFailure ?? "The timestamp signing certificate cannot be used.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            ServiceRuntime.Audit.ProbeWritable(configuration.LogRolloverInterval);
            cancellationToken.ThrowIfCancellationRequested();
            return new HealthEvaluation(true, null);
        }
        catch (Exception ex) when (ex is ConfigurationErrorsException or CertificateSelectionException or
                                   System.Security.Cryptography.CryptographicException or UnauthorizedAccessException or
                                   AuditLogException or IssuanceStateException or System.IO.IOException)
        {
            return new HealthEvaluation(false, ex.Message);
        }
    }

    private static bool IsFresh(long now, long timestamp)
    {
        var elapsed = now - timestamp;
        return elapsed >= 0 && elapsed < CacheDurationTicks;
    }

    private static bool IsWithinStaleGrace(long now, long timestamp)
    {
        var elapsed = now - timestamp;
        return elapsed >= 0 && elapsed < CacheDurationTicks + StaleGraceTicks;
    }

    internal static bool ShouldServeStale(bool cacheKeyMatches, long now, long timestamp) =>
        cacheKeyMatches && !IsFresh(now, timestamp) && IsWithinStaleGrace(now, timestamp);

    private sealed class HealthSnapshot(
        bool healthy,
        bool fipsEnabled,
        long configurationVersion,
        long invalidationVersion,
        long timestamp,
        string detail)
    {
        internal bool Healthy { get; } = healthy;
        internal bool FipsEnabled { get; } = fipsEnabled;
        internal long ConfigurationVersion { get; } = configurationVersion;
        internal long InvalidationVersion { get; } = invalidationVersion;
        internal long Timestamp { get; } = timestamp;
        internal string Detail { get; } = detail;
    }

    internal readonly struct HealthResult(
        bool healthy,
        bool fipsEnabled,
        bool hasSnapshot,
        bool stale,
        bool refreshing,
        string detail)
    {
        internal bool Healthy { get; } = healthy;
        internal bool FipsEnabled { get; } = fipsEnabled;
        internal bool HasSnapshot { get; } = hasSnapshot;
        internal bool Stale { get; } = stale;
        internal bool Refreshing { get; } = refreshing;
        internal string Detail { get; } = detail;
    }

    private readonly struct HealthEvaluation(bool healthy, string detail)
    {
        internal bool Healthy { get; } = healthy;
        internal string Detail { get; } = detail;
    }

    private sealed class RefreshWork(long invalidationVersion)
    {
        internal int Completion;
        internal long InvalidationVersion { get; } = invalidationVersion;
        internal object PublicationGate { get; } = new();
    }
}

internal static class HealthPolicy
{
    internal static DateTime GetRuntimeCertificateValidationTimeUtc(
        ServiceConfiguration configuration,
        DateTime utcNow)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var nextGenerationTimeUtc = ServiceRuntime.IssuanceState.ValidateAndGetNextGenerationTime(
            utcNow,
            TimeSpan.FromSeconds(configuration.ClockRollbackToleranceSeconds),
            configuration.Ordering);
        return GetCertificateValidationTimeUtc(
            utcNow,
            nextGenerationTimeUtc,
            TimeSpan.FromSeconds(HealthHandler.CacheDurationSeconds + HealthHandler.StaleGraceSeconds));
    }

    internal static DateTime GetCertificateValidationTimeUtc(
        DateTime utcNow,
        DateTime nextGenerationTimeUtc,
        TimeSpan cacheDuration)
    {
        if (cacheDuration < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(cacheDuration));

        utcNow = utcNow.ToUniversalTime();
        nextGenerationTimeUtc = nextGenerationTimeUtc.ToUniversalTime();
        var cacheHorizonUtc = CertificateRepository.GetSelectionValidationTimeUtc(utcNow, cacheDuration);
        return nextGenerationTimeUtc > cacheHorizonUtc ? nextGenerationTimeUtc : cacheHorizonUtc;
    }

    internal static bool IsConfigurationPolicyUsable(ServiceConfiguration configuration, bool fipsEnabled)
    {
        return GetConfigurationPolicyFailure(configuration, fipsEnabled) is null;
    }

    internal static string GetConfigurationPolicyFailure(ServiceConfiguration configuration, bool fipsEnabled)
    {
        if (configuration is null) return "Service settings are unavailable.";

        var errors = configuration.Validate();
        if (errors.Count != 0) return string.Join(" ", errors);

        var signingHash = HashAlgorithmCatalog.FindByName(configuration.SigningDigestAlgorithm);
        if (signingHash is null || !signingHash.CmsSigningSupported || (fipsEnabled && signingHash.IsLegacy))
            return "The configured timestamp signing hash is not allowed by the current Windows security policy.";

        // Every enabled endpoint must be usable under the effective policy. Do not
        // let one healthy protocol mask an enabled protocol that can never succeed.
        if (!configuration.Rfc3161Enabled && !configuration.AuthenticodeEnabled)
            return "All timestamp endpoints are disabled.";
        if (configuration.Rfc3161Enabled && !HasEffectiveRequestHash(configuration, fipsEnabled))
            return "RFC 3161 has no request hash algorithm allowed by the current Windows security policy.";
        if (configuration.AuthenticodeEnabled && fipsEnabled)
            return "Legacy Authenticode timestamping is unavailable while Windows FIPS mode is enabled.";
        return null;
    }

    internal static bool HasEffectiveRequestHash(ServiceConfiguration configuration, bool fipsEnabled) =>
        (configuration?.AllowedHashAlgorithms ?? [])
        .Select(HashAlgorithmCatalog.FindByName)
        .Any(algorithm => algorithm != null && (!fipsEnabled || !algorithm.IsLegacy));

}
