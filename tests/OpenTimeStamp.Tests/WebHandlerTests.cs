using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Web.Handlers;
using OpenTimeStamp.Web.Infrastructure;

namespace OpenTimeStamp.Tests;

internal static class WebHandlerTests
{
    public static void Register(ICollection<TestCase> tests)
    {
        tests.Add(new TestCase("Health policy rejects unusable enabled protocols", HealthPolicyRequiresEveryEnabledProtocol));
        tests.Add(new TestCase("Health certificate horizon covers cache and durable time", HealthCertificateValidationHorizon));
        tests.Add(new TestCase("Health cache serves a bounded stale result during refresh", HealthCacheUsesBoundedStaleWindow));
        tests.Add(new TestCase(
            "Health refresh scheduling preserves timeout and late completion",
            HealthRefreshSchedulingIsBounded));
        tests.Add(new TestCase("FIPS policy permits Authenticode disable but not enable", FipsAuthenticodeTransitionIsFailSafe));
        tests.Add(new TestCase("FIPS policy permits legacy hash removal but not addition", FipsLegacyHashTransitionIsFailSafe));
        tests.Add(new TestCase("Web runtime settings reject invalid configured limits", WebRuntimeSettingsRejectInvalidLimits));
        tests.Add(new TestCase(
            "Timestamp media types use strict first-party parsing",
            TimestampMediaTypesAreStrictlyParsed));
        tests.Add(new TestCase("Timestamp body intake does not consume processing capacity", TimestampAdmissionUsesIndependentTiers));
        tests.Add(new TestCase("Timestamp body intake is bounded per transport peer", TimestampAdmissionUsesPerPeerLimit));
        tests.Add(new TestCase("Timestamp processing is bounded per transport peer", TimestampProcessingUsesPerPeerLimit));
        tests.Add(new TestCase("Timestamp admission limits span worker processes", TimestampAdmissionUsesNamedSharedLimits));
        tests.Add(new TestCase("Timestamp body deadline aborts and observes pending read", TimestampBodyDeadlineAbortsPendingRead));
        tests.Add(new TestCase("Timestamp body deadline releases a non-cancelable read", TimestampBodyDeadlineBoundsAbortObservation));
        tests.Add(new TestCase(
            "Timestamp abandoned body read retains its pooled buffer until completion",
            TimestampAbandonedReadRetainsPooledBuffer));
        tests.Add(new TestCase("Timestamp body cancellation remains distinguishable from deadline", TimestampBodyCancellationIsPreserved));
        tests.Add(new TestCase("Timestamp declared body length avoids a final copy", TimestampDeclaredBodyIsExactAllocated));
        tests.Add(new TestCase("Timestamp chunked body clears and returns pooled growth", TimestampChunkedBodyReturnsPooledBuffers));
        tests.Add(new TestCase("Timestamp streamed body bound maps to HTTP 413", TimestampBodyBoundMapsToPayloadTooLarge));
        tests.Add(new TestCase("Administrative CSRF payload expires and binds identity", AdminCsrfPayloadBindsIdentity));
        tests.Add(new TestCase("Administrative host normalization accepts bracketed IPv6", AdminHostNormalizationHandlesIpv6));
        tests.Add(new TestCase("Service landing page documents public and local endpoints", HomeLandingPageDocumentsEndpoints));
        tests.Add(new TestCase("Audit logger rejects a torn JSONL tail", AuditLoggerRejectsTornTail));
        tests.Add(new TestCase("Recent request dashboard activity is bounded, ordered, and expired", RecentRequestActivityIsBounded));
        tests.Add(new TestCase("Recent request dashboard activity is concurrency safe", RecentRequestActivityIsConcurrencySafe));
        tests.Add(new TestCase("Administrative activity rendering is explicit and escaped", AdminActivityRenderingIsExplicitAndEscaped));
        tests.Add(new TestCase("Administrative certificate card shows SHA-256 identity", AdminCertificateCardShowsSha256Identity));
        tests.Add(new TestCase(
            "Configuration auditing covers every persisted member",
            ConfigurationAuditCoversPersistedMembers));
    }

    private static void HomeLandingPageDocumentsEndpoints()
    {
        var localHtml = HomeHandler.Render("/OpenTimeStamp", "https://tsa.example.test", true);
        AssertEx.Contains("Timestamp Endpoints", localHtml);
        AssertEx.Contains("RFC 3161", localHtml);
        AssertEx.Contains("Legacy Authenticode", localHtml);
        AssertEx.Contains("Service Health", localHtml);
        AssertEx.Contains("Local Administration", localHtml);
        AssertEx.Contains("/OpenTimeStamp/timestamp/rfc3161", localHtml);
        AssertEx.Contains("/OpenTimeStamp/timestamp/authenticode", localHtml);
        AssertEx.Contains("/OpenTimeStamp/health", localHtml);
        AssertEx.Contains("/OpenTimeStamp/admin", localHtml);
        AssertEx.Contains(
            "signtool timestamp /tr https://tsa.example.test/OpenTimeStamp/timestamp/rfc3161 " +
            "/td SHA256 signed-file.exe",
            localHtml);
        AssertEx.Contains("Common Client Commands", localHtml);
        AssertEx.Contains("PowerShell — Sign and Timestamp a Script", localHtml);
        AssertEx.Contains("Set-AuthenticodeSignature", localHtml);
        AssertEx.Contains("Cert:\\CurrentUser\\My\\&lt;code-signing-thumbprint&gt;", localHtml);
        AssertEx.Contains("-FilePath &#39;.\\script.ps1&#39;", localHtml);
        AssertEx.Contains("-HashAlgorithm SHA256", localHtml);
        AssertEx.Contains("-IncludeChain All", localHtml);
        AssertEx.Contains(
            "-TimestampServer &#39;http://&lt;server&gt;/OpenTimeStamp/timestamp/authenticode&#39;",
            localHtml);
        AssertEx.Contains("requires the legacy endpoint over HTTP", localHtml);
        AssertEx.False(localHtml.IndexOf("Invoke-WebRequest", StringComparison.Ordinal) >= 0,
            "The landing page retained an extra PowerShell RFC 3161 example.");
        AssertEx.False(localHtml.IndexOf("Invoke-RestMethod", StringComparison.Ordinal) >= 0,
            "The landing page retained an extra PowerShell health example.");

        var remoteHtml = HomeHandler.Render("/OpenTimeStamp", "https://tsa.example.test", false);
        AssertEx.False(remoteHtml.IndexOf("Local Administration", StringComparison.Ordinal) >= 0,
            "The public landing page disclosed the local administrative endpoint.");
        AssertEx.False(remoteHtml.IndexOf("/OpenTimeStamp/admin", StringComparison.Ordinal) >= 0,
            "The public landing page emitted a link to the local administrative endpoint.");

        var escapedHtml = HomeHandler.Render("/<app>", "https://example.test", true);
        AssertEx.False(escapedHtml.IndexOf("<app>", StringComparison.Ordinal) >= 0,
            "The service landing page emitted a path without HTML encoding.");
    }

    private static void FipsAuthenticodeTransitionIsFailSafe()
    {
        AssertEx.True(AdminHandler.ResolveAuthenticodeEnabled(false, false, true));
        AssertEx.False(AdminHandler.ResolveAuthenticodeEnabled(false, true, false));
        AssertEx.True(AdminHandler.ResolveAuthenticodeEnabled(true, true, true));
        AssertEx.False(AdminHandler.ResolveAuthenticodeEnabled(true, true, false),
            "FIPS must not trap an already-enabled legacy endpoint in the enabled state.");
        AssertEx.False(AdminHandler.ResolveAuthenticodeEnabled(true, false, true),
            "A forged form value must not enable Authenticode while FIPS is active.");
    }

    private static void RecentRequestActivityIsBounded()
    {
        long observedTimestamp = 0;
        var tracker = new RecentRequestTracker(
            2,
            TimeSpan.FromHours(1),
            () => observedTimestamp);
        var start = new DateTime(2026, 7, 18, 12, 0, 0, DateTimeKind.Utc);
        for (var index = 0; index < 3; index++)
        {
            tracker.Record(new AuditRecord
            {
                TimestampUtc = start.AddMinutes(index),
                Protocol = "rfc3161",
                Result = index == 2 ? "granted" : "rejected",
                CorrelationId = "request-" + index,
                Username = "DOMAIN\\user",
                UserSid = "S-1-5-21-1000",
                AuthenticationType = "Negotiate",
                RemoteAddress = "192.0.2." + index,
                DurationMilliseconds = index
            });
        }

        var recent = tracker.Snapshot(2);
        AssertEx.Equal(2, recent.Count);
        AssertEx.Equal("request-2", recent[0].CorrelationId);
        AssertEx.Equal("S-1-5-21-1000", recent[0].UserSid);
        AssertEx.Equal("192.0.2.2", recent[0].RemoteAddress);
        AssertEx.Equal("request-1", recent[1].CorrelationId);
        observedTimestamp = Stopwatch.Frequency * 3600L;
        AssertEx.Equal(0, tracker.Snapshot(2).Count);
        observedTimestamp = 0;
        AssertEx.Equal(0, tracker.Snapshot(2).Count,
            "Expired request data must be removed from memory, not merely hidden by one snapshot.");
    }

    private static void RecentRequestActivityIsConcurrencySafe()
    {
        var tracker = new RecentRequestTracker(100, TimeSpan.FromHours(1), () => 0);
        Parallel.For(0, 500, index => tracker.Record(new AuditRecord
        {
            TimestampUtc = DateTime.UtcNow,
            Protocol = "rfc3161",
            Result = "granted",
            CorrelationId = "concurrent-" + index,
            RemoteAddress = "192.0.2.1"
        }));

        var recent = tracker.Snapshot(100);
        AssertEx.Equal(100, recent.Count);
        AssertEx.Equal(100, new HashSet<string>(recent.Select(record => record.CorrelationId)).Count,
            "Concurrent recording corrupted or duplicated retained request entries.");
    }

    private static void AdminActivityRenderingIsExplicitAndEscaped()
    {
        var requests = new[]
        {
            new RecentRequestActivity(
                new DateTime(2026, 7, 18, 12, 0, 0, DateTimeKind.Utc),
                "rfc3161<script>",
                "granted&recorded",
                "request-<1>",
                "DOMAIN\\<admin>",
                "S-1-5-21-1000",
                "Negotiate\"test",
                "192.0.2.1<peer>",
                12)
        };
        StringBuilder builder = new();
        AdminHandler.AppendRecentActivity(builder, requests);
        var html = builder.ToString();

        AssertEx.Contains("up to 100 timestamp results", html);
        AssertEx.Contains("Requests rejected before audit logging", html);
        AssertEx.Contains("Recent Activity by User", html);
        AssertEx.Contains("Recent Timestamp Results", html);
        AssertEx.Contains("Showing 1 of 1 results in recent history", html);
        AssertEx.False(html.IndexOf("Recorded Outcomes", StringComparison.OrdinalIgnoreCase) >= 0,
            "The administrative activity view used the retired Recorded Outcomes terminology.");
        AssertEx.Contains("Recent Result Count", html);
        AssertEx.False(html.IndexOf("retained tail", StringComparison.OrdinalIgnoreCase) >= 0,
            "The administrative activity view used internal buffer terminology.");
        AssertEx.Contains("Last Request (Local Time)", html);
        AssertEx.Contains("Time (Local)", html);
        AssertEx.Contains("Authentication Type", html);
        AssertEx.Contains("Last Client Address", html);
        AssertEx.Contains("Client Address", html);
        AssertEx.Contains("Processing Time", html);
        AssertEx.Contains(AdminHandler.FormatAdminTime(requests[0].TimestampUtc), html);
        AssertEx.Contains("DOMAIN\\&lt;admin&gt;", html);
        AssertEx.Contains("192.0.2.1&lt;peer&gt;", html);
        AssertEx.Contains("request-&lt;1&gt;", html);
        AssertEx.False(html.IndexOf("<script>", StringComparison.OrdinalIgnoreCase) >= 0,
            "Administrative activity values were emitted without HTML encoding.");

        var manyRequests = Enumerable.Range(0, 55)
            .Select(index => new RecentRequestActivity(
                new DateTime(2026, 7, 18, 12, 0, 0, DateTimeKind.Utc).AddSeconds(-index),
                "rfc3161",
                "granted",
                "request-" + index,
                "DOMAIN\\user",
                "S-1-5-21-1000",
                "Negotiate",
                "192.0.2.1",
                index))
            .ToList();
        builder.Clear();
        AdminHandler.AppendRecentActivity(builder, manyRequests);
        html = builder.ToString();
        AssertEx.Contains("Showing 50 of 55 results in recent history", html);
        AssertEx.Contains("RFC 3161", html);
        AssertEx.Contains("Successful", html);
        AssertEx.Contains("<code>request-49</code>", html);
        AssertEx.False(html.IndexOf("<code>request-50</code>", StringComparison.Ordinal) >= 0,
            "Administrative activity rendering exceeded its stated request-row limit.");

        builder.Clear();
        AdminHandler.AppendRecentActivity(builder, Array.Empty<RecentRequestActivity>());
        AssertEx.Contains("No timestamp requests have been recorded since the service started", builder.ToString());

        AssertEx.Equal("SHA-256", AdminHandler.FormatHashName("sha256"));
        AssertEx.Equal("RFC 3161", AdminHandler.FormatProtocol("rfc3161"));
        AssertEx.Equal("Successful", AdminHandler.FormatResult("granted"));
        AssertEx.Equal("Error", AdminHandler.FormatResult("error"));
        AssertEx.Equal("sha256:0123456789ab", AdminHandler.FormatConfigurationId("sha256:0123456789abcdef"));
        AssertEx.Equal("Unavailable", AdminHandler.FormatConfigurationId(null));

        var sameNameDifferentSids = new[]
        {
            new RecentRequestActivity(
                new DateTime(2026, 7, 18, 12, 0, 0, DateTimeKind.Utc),
                "rfc3161",
                "granted",
                "sid-request-1",
                "DOMAIN\\same-name",
                "S-1-5-21-1001",
                "Negotiate",
                "192.0.2.1",
                1),
            new RecentRequestActivity(
                new DateTime(2026, 7, 18, 11, 59, 0, DateTimeKind.Utc),
                "rfc3161",
                "granted",
                "sid-request-2",
                "DOMAIN\\same-name",
                "S-1-5-21-1002",
                "Negotiate",
                "192.0.2.2",
                1)
        };
        builder.Clear();
        AdminHandler.AppendRecentActivity(builder, sameNameDifferentSids);
        html = builder.ToString();
        var activitySectionEnd = html.IndexOf(
            "<div class=\"section\"><h2>Recent Timestamp Results",
            StringComparison.Ordinal);
        var userSection = html.Substring(0, activitySectionEnd);
        AssertEx.Contains("192.0.2.1", userSection);
        AssertEx.Contains("192.0.2.2", userSection,
            "Distinct Windows SIDs with the same display name were merged into one recent user.");
    }

    private static void AdminCertificateCardShowsSha256Identity()
    {
        const string sha256 = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        var expirationUtc = new DateTime(2030, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        AssertEx.Equal(sha256, AdminHandler.FormatCertificateSha256Thumbprint(Encoding.ASCII.GetBytes("abc")));

        StringBuilder builder = new();
        AdminHandler.AppendCertificateCard(builder, expirationUtc, sha256);
        var html = builder.ToString();
        AssertEx.Contains("Certificate", html);
        AssertEx.Contains("Expires " + AdminHandler.FormatAdminTime(expirationUtc), html);
        AssertEx.Contains("SHA-256 Thumbprint", html);
        AssertEx.Contains(sha256, html);
        AssertEx.False(html.IndexOf("Timestamp Results", StringComparison.OrdinalIgnoreCase) >= 0,
            "The certificate summary card retained the replaced activity title.");

        builder.Clear();
        AdminHandler.AppendCertificateCard(builder, null, null);
        AssertEx.Contains("Unavailable", builder.ToString());
        AssertEx.Contains("No usable timestamp signing certificate", builder.ToString());
    }

    private static void ConfigurationAuditCoversPersistedMembers()
    {
        var baseline = new ServiceConfiguration();
        var properties = typeof(ServiceConfiguration).GetProperties()
            .Where(property => property.IsDefined(typeof(DataMemberAttribute), false));
        foreach (var property in properties)
        {
            var changed = baseline.Clone();
            object replacement;
            if (property.PropertyType == typeof(bool))
                replacement = !(bool)property.GetValue(changed);
            else if (property.PropertyType == typeof(int))
                replacement = (int)property.GetValue(changed) + 1;
            else if (property.PropertyType == typeof(string))
                replacement = ((string)property.GetValue(changed) ?? string.Empty) + "-changed";
            else if (property.PropertyType == typeof(List<string>))
                replacement = new List<string> { "changed" };
            else
                throw new InvalidOperationException(
                    "Unhandled configuration property type " + property.PropertyType.Name + ".");

            property.SetValue(changed, replacement);
            var detail = AdminHandler.DescribeConfigurationChange(baseline, changed);
            AssertEx.True(
                detail.EndsWith("; changed=" + property.Name, StringComparison.Ordinal),
                property.Name + " is missing from the configuration audit descriptor.");
        }
    }

    private static void FipsLegacyHashTransitionIsFailSafe()
    {
        AssertEx.Equal(
            "MD5,SHA1,SHA256",
            string.Join(",", AdminHandler.ResolveAllowedHashAlgorithms(
                false,
                Array.Empty<string>(),
                new[] { "MD5", "SHA-1", "SHA256" })));

        AssertEx.Equal(
            "SHA256",
            string.Join(",", AdminHandler.ResolveAllowedHashAlgorithms(
                true,
                Array.Empty<string>(),
                new[] { "MD5", "SHA1", "SHA256" })),
            "A forged form value must not add a legacy request hash while FIPS is active.");

        AssertEx.Equal(
            "MD5,SHA256",
            string.Join(",", AdminHandler.ResolveAllowedHashAlgorithms(
                true,
                new[] { "MD5", "SHA1", "SHA256" },
                new[] { "MD5", "SHA256" })),
            "An originally configured legacy hash may remain selected while another is removed.");

        AssertEx.Equal(
            0,
            AdminHandler.ResolveAllowedHashAlgorithms(
                true,
                new[] { "MD5" },
                Array.Empty<string>()).Count,
            "FIPS must not trap an originally configured legacy request hash in the enabled state.");
    }

    private static void HealthPolicyRequiresEveryEnabledProtocol()
    {
        var configuration = CreateRfcConfiguration();
        configuration.AllowedHashAlgorithms = ["MD5", "SHA1"];
        AssertEx.True(HealthPolicy.IsConfigurationPolicyUsable(configuration, false));
        AssertEx.False(HealthPolicy.HasEffectiveRequestHash(configuration, true));
        AssertEx.False(HealthPolicy.IsConfigurationPolicyUsable(configuration, true),
            "RFC 3161 cannot be healthy when FIPS rejects every configured request hash.");
        AssertEx.Contains(
            "request hash algorithm",
            HealthPolicy.GetConfigurationPolicyFailure(configuration, true));

        configuration.AllowedHashAlgorithms = ["SHA256"];
        AssertEx.True(HealthPolicy.HasEffectiveRequestHash(configuration, true));
        AssertEx.True(HealthPolicy.IsConfigurationPolicyUsable(configuration, true));

        configuration.AuthenticodeEnabled = true;
        AssertEx.True(HealthPolicy.IsConfigurationPolicyUsable(configuration, false));
        AssertEx.False(HealthPolicy.IsConfigurationPolicyUsable(configuration, true),
            "A healthy RFC endpoint must not mask enabled Authenticode under FIPS.");
        AssertEx.Contains(
            "Authenticode timestamping",
            HealthPolicy.GetConfigurationPolicyFailure(configuration, true));

        configuration.Rfc3161Enabled = false;
        AssertEx.True(HealthPolicy.IsConfigurationPolicyUsable(configuration, false));
        AssertEx.False(HealthPolicy.IsConfigurationPolicyUsable(configuration, true));

        configuration.AuthenticodeEnabled = false;
        AssertEx.False(HealthPolicy.IsConfigurationPolicyUsable(configuration, false),
            "Health requires at least one enabled timestamp protocol.");
        AssertEx.Contains(
            "All timestamp endpoints are disabled",
            HealthPolicy.GetConfigurationPolicyFailure(configuration, false));
    }

    private static void HealthCertificateValidationHorizon()
    {
        var utcNow = new DateTime(2026, 7, 16, 12, 0, 0, DateTimeKind.Utc);
        var cacheDuration = TimeSpan.FromSeconds(30);
        AssertEx.Equal(
            utcNow.AddSeconds(45),
            HealthPolicy.GetCertificateValidationTimeUtc(
                utcNow,
                utcNow.AddSeconds(1),
                cacheDuration),
            "Health validation must cover both the health cache and certificate-selection cache horizons.");

        var durableFuture = utcNow.AddMinutes(5);
        AssertEx.Equal(
            durableFuture,
            HealthPolicy.GetCertificateValidationTimeUtc(utcNow, durableFuture, cacheDuration),
            "A future durable issuance clock must take precedence over the shorter cache horizon.");

        var nearMaximumUtc = new DateTime(DateTime.MaxValue.Ticks - 1, DateTimeKind.Utc);
        var saturated = HealthPolicy.GetCertificateValidationTimeUtc(
            nearMaximumUtc,
            nearMaximumUtc,
            cacheDuration);
        AssertEx.Equal(DateTime.MaxValue.Ticks, saturated.Ticks);
        AssertEx.Equal(DateTimeKind.Utc, saturated.Kind);
    }

    private static void HealthCacheUsesBoundedStaleWindow()
    {
        var frequency = Stopwatch.Frequency;
        AssertEx.False(HealthHandler.ShouldServeStale(true, frequency * 29, 0));
        AssertEx.True(HealthHandler.ShouldServeStale(true, frequency * 30, 0),
            "An ordinary cache expiry should serve the last matching result while one refresh starts.");
        AssertEx.True(HealthHandler.ShouldServeStale(true, frequency * 44, 0));
        AssertEx.False(HealthHandler.ShouldServeStale(true, frequency * 45, 0),
            "A stuck probe must not make a healthy result stale indefinitely.");
        AssertEx.False(HealthHandler.ShouldServeStale(false, frequency * 30, 0),
            "A changed configuration or FIPS policy must fail degraded instead of serving stale health.");
    }

    private static void HealthRefreshSchedulingIsBounded()
    {
        using ManualResetEventSlim refreshEntered = new();
        using ManualResetEventSlim releaseRefresh = new();
        using ManualResetEventSlim timeoutPublished = new();
        TaskCompletionSource<bool> publishTimeout = new();
        var refreshCompleted = 0;
        var schedulerCompleted = 0;
        var scheduled = HealthRefreshScheduler.RunAsync(
            cancellationToken =>
            {
                refreshEntered.Set();
                releaseRefresh.Wait(cancellationToken);
                Interlocked.Exchange(ref refreshCompleted, 1);
            },
            timeoutPublished.Set,
            () => Interlocked.Exchange(ref schedulerCompleted, 1),
            TimeSpan.FromSeconds(15),
            (_, _) => publishTimeout.Task,
            CancellationToken.None);
        try
        {
            AssertEx.True(refreshEntered.Wait(TimeSpan.FromSeconds(5)), "The hosted health refresh did not start.");
            publishTimeout.SetResult(true);
            AssertEx.True(timeoutPublished.Wait(TimeSpan.FromSeconds(5)), "The health timeout was not published.");
            AssertEx.Equal(0, Volatile.Read(ref refreshCompleted),
                "A timed-out health refresh was reported complete before its probe returned.");
        }
        finally
        {
            releaseRefresh.Set();
        }

        scheduled.GetAwaiter().GetResult();
        AssertEx.Equal(1, Volatile.Read(ref refreshCompleted));
        AssertEx.Equal(1, Volatile.Read(ref schedulerCompleted));

        var unexpectedTimeouts = 0;
        HealthRefreshScheduler.RunAsync(
            _ => { },
            () => Interlocked.Increment(ref unexpectedTimeouts),
            () => { },
            TimeSpan.FromMinutes(1),
            Task.Delay,
            CancellationToken.None).GetAwaiter().GetResult();
        AssertEx.Equal(0, unexpectedTimeouts,
            "Completing a health refresh must cancel its pending timeout publication.");

        using CancellationTokenSource shutdown = new();
        shutdown.Cancel();
        var shutdownObserved = 0;
        var shutdownCompletions = 0;
        HealthRefreshScheduler.RunAsync(
            cancellationToken =>
            {
                if (cancellationToken.IsCancellationRequested)
                    Interlocked.Exchange(ref shutdownObserved, 1);
            },
            () => Interlocked.Increment(ref unexpectedTimeouts),
            () => Interlocked.Increment(ref shutdownCompletions),
            TimeSpan.FromMinutes(1),
            Task.Delay,
            shutdown.Token).GetAwaiter().GetResult();
        AssertEx.Equal(1, shutdownObserved,
            "A hosted health refresh must observe ASP.NET shutdown cancellation.");
        AssertEx.Equal(1, shutdownCompletions);
        AssertEx.Equal(0, unexpectedTimeouts,
            "Hosted shutdown cancellation must not publish a probe timeout.");
    }

    private static void WebRuntimeSettingsRejectInvalidLimits()
    {
        AssertEx.Equal(4, WebRuntimeSettings.ParseBoundedSetting("Test", null, 4, 1, 8));
        AssertEx.Equal(8, WebRuntimeSettings.ParseBoundedSetting("Test", "8", 4, 1, 8));
        AssertEx.Throws<ConfigurationErrorsException>(() =>
            WebRuntimeSettings.ParseBoundedSetting("Test", "0", 4, 1, 8));
        AssertEx.Throws<ConfigurationErrorsException>(() =>
            WebRuntimeSettings.ParseBoundedSetting("Test", "9", 4, 1, 8));
        AssertEx.Throws<ConfigurationErrorsException>(() =>
            WebRuntimeSettings.ParseBoundedSetting("Test", "not-a-number", 4, 1, 8));
    }

    private static void TimestampMediaTypesAreStrictlyParsed()
    {
        const string expected = "application/timestamp-query";
        AssertEx.True(HttpSupport.HasExactMediaTypeValue("Application/Timestamp-Query", expected));
        AssertEx.True(HttpSupport.HasExactMediaTypeValue(
            "application/timestamp-query; charset=\"utf-8\"",
            expected));
        AssertEx.False(HttpSupport.HasExactMediaTypeValue("application/timestamp-reply", expected));
        AssertEx.False(HttpSupport.HasExactMediaTypeValue("application/timestamp-query; charset", expected));
        AssertEx.False(HttpSupport.HasExactMediaTypeValue(
            "application/timestamp-query; charset=\"unterminated",
            expected));
    }

    private static void TimestampAdmissionUsesIndependentTiers()
    {
        using var admission = new TimestampAdmissionController(8, 2, 8);
        List<IDisposable> bodyLeases = [];
        IDisposable firstProcessing = null;
        IDisposable secondProcessing = null;
        IDisposable replacementBody = null;
        try
        {
            for (var index = 0; index < 8; index++)
            {
                var lease = admission.TryEnterBodyIntake();
                AssertEx.NotNull(lease);
                bodyLeases.Add(lease);
            }

            AssertEx.True(admission.TryEnterBodyIntake() is null);

            // Saturated slow-body intake must leave all signing/audit slots free.
            firstProcessing = admission.TryEnterProcessing();
            secondProcessing = admission.TryEnterProcessing();
            AssertEx.NotNull(firstProcessing);
            AssertEx.NotNull(secondProcessing);
            AssertEx.True(admission.TryEnterProcessing() is null);

            bodyLeases[0].Dispose();
            bodyLeases[0].Dispose();
            replacementBody = admission.TryEnterBodyIntake();
            AssertEx.NotNull(replacementBody, "A completed body must independently return its intake slot.");
            AssertEx.True(admission.TryEnterBodyIntake() is null,
                "Disposing an admission lease twice must not over-release its semaphore.");
        }
        finally
        {
            replacementBody?.Dispose();
            firstProcessing?.Dispose();
            secondProcessing?.Dispose();
            foreach (var lease in bodyLeases) lease.Dispose();
        }
    }

    private static void TimestampAdmissionUsesPerPeerLimit()
    {
        using var admission = new TimestampAdmissionController(6, 1, 2);
        var firstA = admission.TryEnterBodyIntake("192.0.2.10");
        var secondA = admission.TryEnterBodyIntake("192.0.2.10");
        var firstB = admission.TryEnterBodyIntake("192.0.2.11");
        IDisposable replacementA = null;
        try
        {
            AssertEx.NotNull(firstA);
            AssertEx.NotNull(secondA);
            AssertEx.NotNull(firstB);
            AssertEx.True(admission.TryEnterBodyIntake("192.0.2.10") is null,
                "One slow transport peer must not consume the global intake pool.");
            AssertEx.Equal(2, admission.ActiveBodyClientCount);

            firstA.Dispose();
            firstA.Dispose();
            AssertEx.Equal(2, admission.ActiveBodyClientCount,
                "An idempotent release must retain the still-active peer entries.");
            replacementA = admission.TryEnterBodyIntake("192.0.2.10");
            AssertEx.NotNull(replacementA);
        }
        finally
        {
            replacementA?.Dispose();
            firstA?.Dispose();
            secondA?.Dispose();
            firstB?.Dispose();
        }

        AssertEx.Equal(0, admission.ActiveBodyClientCount,
            "The final lease release must remove each peer key instead of growing state forever.");
        using (var reacquired = admission.TryEnterBodyIntake("192.0.2.10"))
        {
            AssertEx.NotNull(reacquired);
        }
        AssertEx.Equal(0, admission.ActiveBodyClientCount);
    }

    private static void TimestampProcessingUsesPerPeerLimit()
    {
        using var admission = new TimestampAdmissionController(6, 4, 6, 2);
        var firstA = admission.TryEnterProcessing("192.0.2.10");
        var secondA = admission.TryEnterProcessing("192.0.2.10");
        var firstB = admission.TryEnterProcessing("192.0.2.11");
        IDisposable replacementA = null;
        try
        {
            AssertEx.NotNull(firstA);
            AssertEx.NotNull(secondA);
            AssertEx.NotNull(firstB);
            AssertEx.True(admission.TryEnterProcessing("192.0.2.10") is null);
            AssertEx.Equal(2, admission.ActiveProcessingClientCount);
            firstA.Dispose();
            replacementA = admission.TryEnterProcessing("192.0.2.10");
            AssertEx.NotNull(replacementA);
        }
        finally
        {
            replacementA?.Dispose();
            firstA?.Dispose();
            secondA?.Dispose();
            firstB?.Dispose();
        }

        AssertEx.Equal(0, admission.ActiveProcessingClientCount);
    }

    private static void TimestampAdmissionUsesNamedSharedLimits()
    {
        var scope = "Local\\OpenTimeStamp-Tests-" + Guid.NewGuid().ToString("N");
        using var workerA = new TimestampAdmissionController(2, 2, 1, 1, scope);
        using var workerB = new TimestampAdmissionController(2, 2, 1, 1, scope);
        var bodyA = workerA.TryEnterBodyIntake("192.0.2.10");
        IDisposable bodyB = null;
        var processingA = workerA.TryEnterProcessing("192.0.2.10");
        IDisposable processingB = null;
        try
        {
            AssertEx.NotNull(bodyA);
            AssertEx.True(workerB.TryEnterBodyIntake("192.0.2.10") is null,
                "The per-peer body limit must span controllers that simulate separate workers.");
            bodyB = workerB.TryEnterBodyIntake("192.0.2.11");
            AssertEx.NotNull(bodyB);
            AssertEx.True(workerA.TryEnterBodyIntake("192.0.2.12") is null,
                "The global body limit must span controllers that simulate separate workers.");
            AssertEx.NotNull(processingA);
            AssertEx.True(workerB.TryEnterProcessing("192.0.2.10") is null,
                "The per-peer processing limit must span controllers that simulate separate workers.");
            processingB = workerB.TryEnterProcessing("192.0.2.11");
            AssertEx.NotNull(processingB);
            AssertEx.True(workerA.TryEnterProcessing("192.0.2.12") is null,
                "The global processing limit must span controllers that simulate separate workers.");
        }
        finally
        {
            bodyA?.Dispose();
            bodyB?.Dispose();
            processingA?.Dispose();
            processingB?.Dispose();
        }
    }

    private static void TimestampBodyDeadlineAbortsPendingRead()
    {
        var stream = new AbortablePendingStream();
        var exception = AssertEx.Throws<RequestBodyException>(() =>
            HttpSupport.ReadBoundedStreamAsync(
                    stream,
                    -1,
                    1024,
                    TimeSpan.FromMilliseconds(100),
                    stream.Abort,
                    CancellationToken.None)
                .GetAwaiter()
                .GetResult());

        AssertEx.True(stream.AbortCalled, "A deadline must actively terminate the native pending read.");
        AssertEx.Equal(408, exception.StatusCode);
        AssertEx.True(exception.ConnectionAborted,
            "The handler must not attempt to write a response after aborting the transport connection.");
    }

    private static void TimestampBodyDeadlineBoundsAbortObservation()
    {
        var stream = new DeferredReadStream();
        using var observed = new ManualResetEventSlim();
        var stopwatch = Stopwatch.StartNew();
        var exception = AssertEx.Throws<RequestBodyException>(() =>
            HttpSupport.ReadBoundedStreamAsync(
                    stream,
                    -1,
                    1024,
                    TimeSpan.FromMilliseconds(50),
                    stream.Abort,
                    CancellationToken.None,
                    observed.Set)
                .GetAwaiter()
                .GetResult());

        AssertEx.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1),
            "A stream that ignores abort must not retain its admission lease indefinitely.");
        AssertEx.True(stream.AbortCalled);
        AssertEx.Equal(408, exception.StatusCode);

        stream.FaultAfterReturn();
        AssertEx.True(observed.Wait(TimeSpan.FromSeconds(1)),
            "The detached observer must consume a native-read fault that arrives after the 408 path returns.");
    }

    private static void TimestampAbandonedReadRetainsPooledBuffer()
    {
        var stream = new DeferredReadStream();
        using var returned = new ManualResetEventSlim();
        using var observed = new ManualResetEventSlim();
        var pool = new TrackingArrayPool(returned.Set);
        var exception = AssertEx.Throws<RequestBodyException>(() =>
            HttpSupport.ReadBoundedStreamAsync(
                    stream,
                    -1,
                    1024,
                    TimeSpan.FromMilliseconds(50),
                    stream.Abort,
                    CancellationToken.None,
                    observed.Set,
                    pool)
                .GetAwaiter()
                .GetResult());

        try
        {
            AssertEx.Equal(408, exception.StatusCode);
            AssertEx.True(stream.AbortCalled);
            AssertEx.Equal(0, pool.ReturnCount,
                "An incomplete native read still owns its destination and must not return it to the pool.");
        }
        finally
        {
            stream.CompleteAfterReturn([1, 2, 3]);
            AssertEx.True(returned.Wait(TimeSpan.FromSeconds(1)),
                "A detached read must return its buffer after its late successful completion.");
            AssertEx.True(observed.Wait(TimeSpan.FromSeconds(1)));
        }

        AssertEx.Equal(1, pool.ReturnCount, "The abandoned read returned its buffer more than once.");
        AssertEx.True(stream.PendingBuffer.All(value => value == 0),
            "The late read's bytes were not cleared before its buffer returned to the pool.");
    }

    private static void TimestampBodyCancellationIsPreserved()
    {
        var stream = new DeferredReadStream();
        using var returned = new ManualResetEventSlim();
        var pool = new TrackingArrayPool(returned.Set);
        using var cancellation = new CancellationTokenSource();
        using var observed = new ManualResetEventSlim();
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(50));
        AssertEx.Throws<OperationCanceledException>(() =>
            HttpSupport.ReadBoundedStreamAsync(
                    stream,
                    -1,
                    1024,
                    TimeSpan.FromSeconds(5),
                    stream.Abort,
                    cancellation.Token,
                    observed.Set,
                    pool)
                .GetAwaiter()
                .GetResult());
        AssertEx.True(stream.AbortCalled);
        stream.FaultAfterReturn();
        AssertEx.True(observed.Wait(TimeSpan.FromSeconds(1)));
        AssertEx.True(returned.Wait(TimeSpan.FromSeconds(1)));
        AssertEx.Equal(1, pool.ReturnCount);
        AssertEx.True(pool.AllReturnsRequestedClear);
    }

    private static void TimestampDeclaredBodyIsExactAllocated()
    {
        var stream = new RecordingReadStream([1, 2, 3, 4, 5]);
        var pool = new TrackingArrayPool();
        var result = HttpSupport.ReadBoundedStreamAsync(
                stream,
                5,
                16,
                TimeSpan.FromSeconds(1),
                null,
                CancellationToken.None,
                null,
                pool)
            .GetAwaiter()
            .GetResult();

        AssertEx.True(ReferenceEquals(stream.FirstReadBuffer, result),
            "A truthful Content-Length body should return its directly filled exact-size allocation.");
        AssertEx.SequenceEqual([1, 2, 3, 4, 5], result);
        AssertEx.Equal(0, pool.RentCount, "Known-length bodies must not borrow pooled storage.");
    }

    private static void TimestampChunkedBodyReturnsPooledBuffers()
    {
        var expected = new byte[9000];
        for (var index = 0; index < expected.Length; index++) expected[index] = (byte)index;
        var stream = new RecordingReadStream(expected);
        var pool = new TrackingArrayPool();
        var result = HttpSupport.ReadBoundedStreamAsync(
                stream,
                -1,
                10000,
                TimeSpan.FromSeconds(1),
                null,
                CancellationToken.None,
                null,
                pool)
            .GetAwaiter()
            .GetResult();

        AssertEx.SequenceEqual(expected, result);
        AssertEx.Equal(2, pool.RentCount);
        AssertEx.Equal(2, pool.ReturnCount);
        AssertEx.True(pool.AllReturnsRequestedClear,
            "Every pooled chunked-body buffer must request clearing on return.");
    }

    private static void TimestampBodyBoundMapsToPayloadTooLarge()
    {
        using var stream = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });
        var pool = new TrackingArrayPool();
        var aborted = false;
        var exception = AssertEx.Throws<RequestBodyException>(() =>
            HttpSupport.ReadBoundedStreamAsync(
                    stream,
                    -1,
                    4,
                    TimeSpan.FromSeconds(1),
                    () => aborted = true,
                    CancellationToken.None,
                    null,
                    pool)
                .GetAwaiter()
                .GetResult());

        AssertEx.Equal(413, exception.StatusCode);
        AssertEx.False(exception.ConnectionAborted);
        AssertEx.False(aborted, "An ordinary size rejection does not require tearing down a completed read.");
        AssertEx.Equal(1, pool.ReturnCount);
        AssertEx.True(pool.AllReturnsRequestedClear);
    }

    private static void AdminCsrfPayloadBindsIdentity()
    {
        var now = new DateTime(2026, 7, 18, 12, 0, 0, DateTimeKind.Utc);
        var identity = new RequestIdentity
        {
            Name = "EXAMPLE\\Administrator",
            Sid = "S-1-5-21-1-2-3-500",
            AuthenticationType = "Negotiate",
            IsAuthenticated = true
        };
        var payload = CsrfTokenManager.CreatePayload(identity, now);
        AssertEx.True(CsrfTokenManager.ValidatePayload(payload, identity, now.AddMinutes(59)));
        AssertEx.False(CsrfTokenManager.ValidatePayload(payload, identity, now.AddMinutes(61)));

        var otherIdentity = new RequestIdentity
        {
            Name = identity.Name,
            Sid = "S-1-5-21-1-2-3-501",
            AuthenticationType = identity.AuthenticationType,
            IsAuthenticated = true
        };
        AssertEx.False(CsrfTokenManager.ValidatePayload(payload, otherIdentity, now));
        AssertEx.False(CsrfTokenManager.ValidatePayload(
            CsrfTokenManager.CreatePayload(identity, now.AddMinutes(6)),
            identity,
            now));
    }

    private static void AdminHostNormalizationHandlesIpv6()
    {
        AssertEx.Equal("::1", HttpSupport.NormalizeHost("[::1]"));
        AssertEx.Equal("::1", HttpSupport.NormalizeHost(" ::1 "));
        AssertEx.Equal("localhost", HttpSupport.NormalizeHost(" localhost "));
    }

    private static void AuditLoggerRejectsTornTail()
    {
        using var directory = new TemporaryDirectory();
        var logDirectory = directory.File("Logs");
        Directory.CreateDirectory(logDirectory);
        var path = Path.Combine(logDirectory, "timestamp-" + DateTime.UtcNow.ToString("yyyyMMdd") + ".jsonl");
        const string torn = "{\"timestampUtc\":\"interrupted";
        File.WriteAllText(path, torn, new UTF8Encoding(false));
        var logger = new AuditLogger(logDirectory);

        AssertEx.Throws<AuditLogException>(() => logger.ProbeWritable());
        AssertEx.Throws<AuditLogException>(() => logger.Write(new AuditRecord
        {
            TimestampUtc = DateTime.UtcNow,
            EventType = "test",
            Result = "granted"
        }, 30, true));
        AssertEx.Equal(torn, File.ReadAllText(path),
            "A new event must never be concatenated onto an incomplete JSON object.");
    }

    private static ServiceConfiguration CreateRfcConfiguration()
    {
        var configuration = TestFixtures.CreateConfiguration();
        configuration.Rfc3161Enabled = true;
        configuration.CertificateThumbprint = "AA";
        return configuration;
    }

    private sealed class AbortablePendingStream : Stream
    {
        private readonly TaskCompletionSource<int> pendingRead = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal bool AbortCalled { get; private set; }

        internal void Abort()
        {
            AbortCalled = true;
            pendingRead.TrySetException(new IOException("The test stream was aborted."));
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken) => pendingRead.Task;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class DeferredReadStream : Stream
    {
        private readonly TaskCompletionSource<int> pendingRead = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int pendingOffset;

        internal bool AbortCalled { get; private set; }

        internal byte[] PendingBuffer { get; private set; }

        internal void Abort() => AbortCalled = true;

        internal void FaultAfterReturn() =>
            pendingRead.TrySetException(new IOException("The delayed native read failed."));

        internal void CompleteAfterReturn(byte[] value)
        {
            Buffer.BlockCopy(value, 0, PendingBuffer, pendingOffset, value.Length);
            pendingRead.TrySetResult(value.Length);
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            PendingBuffer = buffer;
            pendingOffset = offset;
            return pendingRead.Task;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class RecordingReadStream(byte[] source) : Stream
    {
        private int offset;

        internal byte[] FirstReadBuffer { get; private set; }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int bufferOffset,
            int count,
            CancellationToken cancellationToken)
        {
            FirstReadBuffer ??= buffer;
            var read = Math.Min(count, source.Length - offset);
            if (read != 0) Buffer.BlockCopy(source, offset, buffer, bufferOffset, read);
            offset += read;
            return Task.FromResult(read);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => source.Length;
        public override long Position
        {
            get => offset;
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int bufferOffset, int count) => throw new NotSupportedException();
        public override long Seek(long seekOffset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int bufferOffset, int count) => throw new NotSupportedException();
    }

    private sealed class TrackingArrayPool(Action returned = null) : ArrayPool<byte>
    {
        internal int RentCount { get; private set; }
        internal int ReturnCount { get; private set; }
        internal bool AllReturnsRequestedClear { get; private set; } = true;

        public override byte[] Rent(int minimumLength)
        {
            RentCount++;
            return new byte[minimumLength];
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            ReturnCount++;
            AllReturnsRequestedClear &= clearArray;
            if (clearArray) Array.Clear(array, 0, array.Length);
            returned?.Invoke();
        }
    }
}
