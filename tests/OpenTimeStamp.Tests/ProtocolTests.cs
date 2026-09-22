using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Issuance;
using OpenTimeStamp.Protocols;

namespace OpenTimeStamp.Tests;

internal static class ProtocolTests
{
    private const string SigningCertificateOid = "1.2.840.113549.1.9.16.2.12";
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string SigningTimeOid = "1.2.840.113549.1.9.5";
    private const string Pkcs7SignedDataOid = "1.2.840.113549.1.7.2";
    private const string TstInfoContentTypeOid = "1.2.840.113549.1.9.16.1.4";

    public static void Register(ICollection<TestCase> tests)
    {
        // Exercise wire rejections, token semantics, CMS attributes, and legacy countersigning.
        tests.Add(new TestCase("RFC3161 processor rejection responses", Rfc3161Rejections));
        tests.Add(new TestCase("RFC3161 rejects generation outside certificate validity", Rfc3161CertificateValidityAtGenerationTime));
        tests.Add(new TestCase(
            "Certificate validation uses supplied signing time and associated private key",
            CertificateValidationAtSigningTime));
        tests.Add(new TestCase("Certificate trust validation is production-default and explicitly bypassable", CertificateTrustPolicy));
        tests.Add(new TestCase("Automatic certificate ordering prefers the latest expiration", AutomaticCertificateOrdering));
        tests.Add(new TestCase(
            "Certificate refresh stale reuse is bounded by the validated horizon",
            CertificateRefreshStaleReuse));
        tests.Add(new TestCase(
            "Certificate refresh single-flight waits for a cold selection",
            CertificateRefreshSingleFlight));
        tests.Add(new TestCase(
            "Certificate refresh wait honors cancellation and invalidation",
            CertificateRefreshWaitInterruption));
        tests.Add(new TestCase("Platform FIPS registry interpretation fails closed", FipsRegistryInterpretation));
        tests.Add(new TestCase("Certificate profile and cancellation precede durable allocation", PreallocationGuards));
        tests.Add(new TestCase("Protocols resample the clock for durable allocation", ProtocolAllocationResamplesClock));
        tests.Add(new TestCase("RFC3161 common request hashes honor Windows FIPS policy", Rfc3161CommonHashAlgorithms));
        tests.Add(new TestCase("RFC3161 happy path preserves policy, nonce, and imprint", Rfc3161HappyPath));
        tests.Add(new TestCase("RFC3161 certReq controls certificate inclusion", Rfc3161CertificateInclusion));
        tests.Add(new TestCase("RFC3161 CMS signature and ESS attribute", Rfc3161CmsSignatureAndEss));
        tests.Add(new TestCase("RFC3161 CMS signing digests and legacy ESS attribute", Rfc3161SigningDigestAlgorithms));
        tests.Add(new TestCase("Authenticode response is a verified CMS countersignature", AuthenticodeResponse));
    }

    private static void AutomaticCertificateOrdering()
    {
        var latest = new DateTime(2030, 1, 1);
        List<CertificateDescriptor> certificates =
        [
            new() { IsEligible = false, NotAfter = latest.AddYears(5), StoreLocation = StoreLocation.LocalMachine, Thumbprint = "00" },
            new() { IsEligible = true, NotAfter = latest, StoreLocation = StoreLocation.CurrentUser, Thumbprint = "01" },
            new() { IsEligible = true, NotAfter = latest, StoreLocation = StoreLocation.LocalMachine, Thumbprint = "02" },
            new() { IsEligible = true, NotAfter = latest, StoreLocation = StoreLocation.LocalMachine, Thumbprint = "01" },
            new() { IsEligible = true, NotAfter = latest.AddDays(-1), StoreLocation = StoreLocation.LocalMachine, Thumbprint = "03" }
        ];

        var ordered = CertificateRepository.OrderCertificates(certificates);
        AssertEx.Equal("01|02|01|03|00", string.Join("|", ordered.Select(item => item.Thumbprint)));

        var manual = new ServiceConfiguration();
        manual.CertificateSelectionMode = ServiceConfiguration.ManualCertificateSelection;
        var automatic = manual.Clone();
        automatic.CertificateSelectionMode = ServiceConfiguration.AutomaticCertificateSelection;
        AssertEx.NotEqual(
            CertificateRepository.BuildSelectionCacheKey(manual),
            CertificateRepository.BuildSelectionCacheKey(automatic));

        using var repository = new CertificateRepository();
        AssertEx.Throws<ArgumentNullException>(() => repository.ValidateSelection(null, latest, out _));
    }

    private static void CertificateRefreshStaleReuse()
    {
        const string cacheKey = "selection";
        var validationStartedUtc = new DateTime(2026, 7, 16, 12, 0, 0, DateTimeKind.Utc);
        var cacheExpiresUtc = validationStartedUtc.AddSeconds(30);
        var validationHorizonUtc = CertificateRepository.GetSelectionValidationTimeUtc(
            validationStartedUtc,
            TimeSpan.Zero);
        AssertEx.Equal(validationStartedUtc.AddSeconds(45), validationHorizonUtc,
            "The validation horizon must cover the cache, chain URL timeout, and scheduling margin.");

        AssertEx.False(CertificateRepository.CanServeCachedSelectionDuringRefresh(
            true,
            cacheKey,
            cacheKey,
            cacheExpiresUtc.AddTicks(-1),
            cacheExpiresUtc,
            validationHorizonUtc), "Fresh selections use the normal cache path.");
        AssertEx.True(CertificateRepository.CanServeCachedSelectionDuringRefresh(
            true,
            cacheKey,
            cacheKey,
            cacheExpiresUtc,
            cacheExpiresUtc,
            validationHorizonUtc));
        AssertEx.True(CertificateRepository.CanServeCachedSelectionDuringRefresh(
            true,
            cacheKey,
            cacheKey,
            validationHorizonUtc.AddTicks(-1),
            cacheExpiresUtc,
            validationHorizonUtc));
        AssertEx.False(CertificateRepository.CanServeCachedSelectionDuringRefresh(
            true,
            cacheKey,
            cacheKey,
            validationHorizonUtc,
            cacheExpiresUtc,
            validationHorizonUtc), "A cached selection must never be served at or beyond its validated horizon.");
        AssertEx.False(CertificateRepository.CanServeCachedSelectionDuringRefresh(
            false,
            cacheKey,
            cacheKey,
            cacheExpiresUtc,
            cacheExpiresUtc,
            validationHorizonUtc));
        AssertEx.False(CertificateRepository.CanServeCachedSelectionDuringRefresh(
            true,
            "changed-selection",
            cacheKey,
            cacheExpiresUtc,
            cacheExpiresUtc,
            validationHorizonUtc));
    }

    private static void CertificateRefreshSingleFlight()
    {
        using var fixture = new TimestampCertificateFixture();
        using var repository = new CertificateRepository();
        using var refreshStarted = new ManualResetEventSlim();
        using var releaseRefresh = new ManualResetEventSlim();
        var configuration = TestFixtures.CreateConfiguration();
        var loadCount = 0;
        X509Certificate2 firstCertificate = null;
        X509Certificate2 secondCertificate = null;
        Exception firstFailure = null;
        Exception secondFailure = null;
        Func<ServiceConfiguration, DateTime, DateTime, X509Certificate2> loader = (_, _, _) =>
        {
            if (Interlocked.Increment(ref loadCount) != 1)
                throw new InvalidOperationException("Concurrent callers started more than one certificate load.");
            refreshStarted.Set();
            if (!releaseRefresh.Wait(TimeSpan.FromSeconds(5)))
                throw new TimeoutException("The certificate refresh test was not released.");
            return new X509Certificate2(fixture.Certificate);
        };
        var first = new Thread(() =>
        {
            try
            {
                firstCertificate = repository.GetSelectedCertificate(configuration, loader);
            }
            catch (Exception ex)
            {
                firstFailure = ex;
            }
        }) { IsBackground = true };
        var second = new Thread(() =>
        {
            try
            {
                secondCertificate = repository.GetSelectedCertificate(configuration, loader);
            }
            catch (Exception ex)
            {
                secondFailure = ex;
            }
        }) { IsBackground = true };

        try
        {
            first.Start();
            AssertEx.True(refreshStarted.Wait(TimeSpan.FromSeconds(5)), "The first certificate refresh did not start.");
            second.Start();
            AssertThreadWaiting(second, "A cold concurrent certificate request did not wait for the active refresh.");

            releaseRefresh.Set();
            AssertEx.True(first.Join(TimeSpan.FromSeconds(5)), "The first certificate request did not finish.");
            AssertEx.True(second.Join(TimeSpan.FromSeconds(5)), "The waiting certificate request did not finish.");
            AssertEx.True(firstFailure is null, "The first certificate request failed: " + firstFailure);
            AssertEx.True(secondFailure is null, "The waiting certificate request failed: " + secondFailure);
            AssertEx.Equal(1, loadCount, "Concurrent certificate requests did not share one refresh.");
            AssertEx.Equal(firstCertificate.Thumbprint, secondCertificate.Thumbprint);
        }
        finally
        {
            releaseRefresh.Set();
            if (first.IsAlive) first.Join(TimeSpan.FromSeconds(5));
            if (second.IsAlive) second.Join(TimeSpan.FromSeconds(5));
            firstCertificate?.Dispose();
            secondCertificate?.Dispose();
        }
    }

    private static void CertificateRefreshWaitInterruption()
    {
        using var fixture = new TimestampCertificateFixture();
        var configuration = TestFixtures.CreateConfiguration();
        using (var repository = new CertificateRepository())
        using (var refreshStarted = new ManualResetEventSlim())
        using (var releaseRefresh = new ManualResetEventSlim())
        using (var waiterCancellation = new CancellationTokenSource())
        {
            var loadCount = 0;
            Exception leaderFailure = null;
            Exception waiterFailure = null;
            X509Certificate2 leaderCertificate = null;
            Func<ServiceConfiguration, DateTime, DateTime, X509Certificate2> loader = (_, _, _) =>
            {
                Interlocked.Increment(ref loadCount);
                refreshStarted.Set();
                if (!releaseRefresh.Wait(TimeSpan.FromSeconds(5)))
                    throw new TimeoutException("The cancellation refresh test was not released.");
                return new X509Certificate2(fixture.Certificate);
            };
            var leader = new Thread(() =>
            {
                try
                {
                    leaderCertificate = repository.GetSelectedCertificate(configuration, loader);
                }
                catch (Exception ex)
                {
                    leaderFailure = ex;
                }
            }) { IsBackground = true };
            var waiter = new Thread(() =>
            {
                try
                {
                    using var certificate = repository.GetSelectedCertificate(
                        configuration,
                        loader,
                        waiterCancellation.Token);
                }
                catch (Exception ex)
                {
                    waiterFailure = ex;
                }
            }) { IsBackground = true };

            try
            {
                leader.Start();
                AssertEx.True(refreshStarted.Wait(TimeSpan.FromSeconds(5)));
                waiter.Start();
                AssertThreadWaiting(waiter, "The cancellable certificate request did not wait for the active refresh.");
                waiterCancellation.Cancel();
                AssertEx.True(
                    waiter.Join(TimeSpan.FromSeconds(5)),
                    "Cancellation did not wake the certificate waiter.");
                AssertEx.True(waiterFailure is OperationCanceledException,
                    "The canceled certificate waiter returned an unexpected result: " + waiterFailure);

                releaseRefresh.Set();
                AssertEx.True(leader.Join(TimeSpan.FromSeconds(5)));
                AssertEx.True(
                    leaderFailure is null,
                    "Canceling a waiter disrupted the refresh leader: " + leaderFailure);
                AssertEx.NotNull(leaderCertificate);
                AssertEx.Equal(1, loadCount);
            }
            finally
            {
                releaseRefresh.Set();
                if (leader.IsAlive) leader.Join(TimeSpan.FromSeconds(5));
                if (waiter.IsAlive) waiter.Join(TimeSpan.FromSeconds(5));
                leaderCertificate?.Dispose();
            }
        }

        using (var repository = new CertificateRepository())
        using (var refreshStarted = new ManualResetEventSlim())
        using (var releaseRefresh = new ManualResetEventSlim())
        {
            var loadCount = 0;
            Exception leaderFailure = null;
            Exception waiterFailure = null;
            Func<ServiceConfiguration, DateTime, DateTime, X509Certificate2> loader = (_, _, _) =>
            {
                Interlocked.Increment(ref loadCount);
                refreshStarted.Set();
                if (!releaseRefresh.Wait(TimeSpan.FromSeconds(5)))
                    throw new TimeoutException("The invalidation refresh test was not released.");
                return new X509Certificate2(fixture.Certificate);
            };
            var leader = new Thread(() =>
            {
                try
                {
                    using var certificate = repository.GetSelectedCertificate(configuration, loader);
                }
                catch (Exception ex)
                {
                    leaderFailure = ex;
                }
            }) { IsBackground = true };
            var waiter = new Thread(() =>
            {
                try
                {
                    using var certificate = repository.GetSelectedCertificate(configuration, loader);
                }
                catch (Exception ex)
                {
                    waiterFailure = ex;
                }
            }) { IsBackground = true };

            try
            {
                leader.Start();
                AssertEx.True(refreshStarted.Wait(TimeSpan.FromSeconds(5)));
                waiter.Start();
                AssertThreadWaiting(
                    waiter,
                    "The invalidation certificate request did not wait for the active refresh.");
                repository.InvalidateSelectionCache();
                AssertEx.True(
                    waiter.Join(TimeSpan.FromSeconds(5)),
                    "Invalidation did not wake the certificate waiter.");
                AssertEx.True(waiterFailure is CertificateSelectionException);
                AssertEx.Contains("settings changed", waiterFailure.Message);

                releaseRefresh.Set();
                AssertEx.True(leader.Join(TimeSpan.FromSeconds(5)));
                AssertEx.True(leaderFailure is CertificateSelectionException);
                AssertEx.Contains("settings changed", leaderFailure.Message);
                AssertEx.Equal(1, loadCount, "Invalidation started a stale-snapshot certificate refresh.");
                using var recovered = repository.GetSelectedCertificate(
                    configuration,
                    (_, _, _) =>
                    {
                        Interlocked.Increment(ref loadCount);
                        return new X509Certificate2(fixture.Certificate);
                    });
                AssertEx.Equal(
                    2,
                    loadCount,
                    "A new-generation certificate refresh did not recover after invalidation.");
            }
            finally
            {
                releaseRefresh.Set();
                if (leader.IsAlive) leader.Join(TimeSpan.FromSeconds(5));
                if (waiter.IsAlive) waiter.Join(TimeSpan.FromSeconds(5));
            }
        }
    }

    private static void AssertThreadWaiting(Thread thread, string message)
    {
        AssertEx.True(SpinWait.SpinUntil(
            () => !thread.IsAlive || (thread.ThreadState & ThreadState.WaitSleepJoin) != 0,
            TimeSpan.FromSeconds(5)), message);
        AssertEx.True(thread.IsAlive && (thread.ThreadState & ThreadState.WaitSleepJoin) != 0, message);
    }

    private static void Rfc3161CommonHashAlgorithms()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var configuration = TestFixtures.CreateConfiguration();
            configuration.AllowedHashAlgorithms = HashAlgorithmCatalog.All.Select(item => item.Name).ToList();
            var processor = new Rfc3161TimestampProcessor();
            var stateStore = TestFixtures.CreateInitializedStateStore(directory.File("all-hashes.bin"));
            var now = new DateTime(2026, 7, 16, 13, 0, 0, DateTimeKind.Utc);
            foreach (var algorithm in HashAlgorithmCatalog.All)
            {
                var result = processor.Process(
                    TestFixtures.BuildRfc3161Request(algorithm.Oid, new byte[algorithm.DigestLength]),
                    configuration,
                    certificate.Certificate,
                    stateStore,
                    now);
                if (PlatformSecurityPolicy.IsRequestHashAllowed(algorithm))
                {
                    AssertEx.True(result.Granted, algorithm.Name + ": " + result.Detail);
                    AssertEx.Equal(algorithm.Oid, result.HashAlgorithmOid);
                }
                else
                {
                    AssertRejected(result, Rfc3161FailureInfo.BadAlgorithm);
                }
            }
        }
    }

    private static void Rfc3161Rejections()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var configuration = TestFixtures.CreateConfiguration();
            var processor = new Rfc3161TimestampProcessor();
            var store = TestFixtures.CreateInitializedStateStore(directory.File("issuance.bin"));
            var now = new DateTime(2026, 7, 16, 12, 30, 0, DateTimeKind.Utc);

            var unknownHashRequest = TestFixtures.BuildRfc3161Request("1.2.3.4.5", new byte[32]);
            AssertEx.False(processor.TryPreflight(
                Rfc3161Request.Parse(unknownHashRequest),
                configuration,
                out var preflightRejection));
            AssertRejected(preflightRejection, Rfc3161FailureInfo.BadAlgorithm);

            var unknownHash = processor.Process(
                unknownHashRequest,
                configuration,
                certificate.Certificate,
                store,
                now);
            AssertRejected(unknownHash, Rfc3161FailureInfo.BadAlgorithm);

            var wrongDigestSize = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[31]),
                configuration,
                certificate.Certificate,
                store,
                now);
            AssertRejected(wrongDigestSize, Rfc3161FailureInfo.BadAlgorithm);

            configuration.AllowedHashAlgorithms = new List<string> { "SHA384" };
            var disabledHash = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]),
                configuration,
                certificate.Certificate,
                store,
                now);
            AssertRejected(disabledHash, Rfc3161FailureInfo.BadAlgorithm);

            configuration.AllowedHashAlgorithms = new List<string> { "SHA256" };
            var policy = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], "1.2.3.999"),
                configuration,
                certificate.Certificate,
                store,
                now);
            AssertRejected(policy, Rfc3161FailureInfo.UnacceptedPolicy);

            var extensions = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], includeExtensions: true),
                configuration,
                certificate.Certificate,
                store,
                now);
            AssertRejected(extensions, Rfc3161FailureInfo.UnacceptedExtension);

            var malformed = processor.Process(new byte[] { 0x30, 0x80 }, configuration, certificate.Certificate, store, now);
            AssertRejected(malformed, Rfc3161FailureInfo.BadDataFormat);

            var noCertificate = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]),
                configuration,
                null,
                store,
                now);
            AssertRejected(noCertificate, Rfc3161FailureInfo.SystemFailure);
        }
    }

    private static void Rfc3161CertificateValidityAtGenerationTime()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var configuration = TestFixtures.CreateConfiguration();
            var processor = new Rfc3161TimestampProcessor();
            var request = TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]);

            var beforeValidity = processor.Process(
                request,
                configuration,
                certificate.Certificate,
                TestFixtures.CreateInitializedStateStore(directory.File("before-validity.bin")),
                certificate.Certificate.NotBefore.ToUniversalTime().AddSeconds(-1));
            AssertRejected(beforeValidity, Rfc3161FailureInfo.SystemFailure);
            AssertEx.Contains("next timestamp signing time", beforeValidity.Detail);

            var afterValidity = processor.Process(
                request,
                configuration,
                certificate.Certificate,
                TestFixtures.CreateInitializedStateStore(directory.File("after-validity.bin")),
                certificate.Certificate.NotAfter.ToUniversalTime().AddSeconds(1));
            AssertRejected(afterValidity, Rfc3161FailureInfo.SystemFailure);
            AssertEx.Contains("next timestamp signing time", afterValidity.Detail);
        }
    }

    private static void CertificateValidationAtSigningTime()
    {
        using (var certificate = new TimestampCertificateFixture())
        {
            var insideValidity = new DateTime(2026, 7, 16, 12, 0, 0, DateTimeKind.Utc);
            AssertEx.True(CertificateRepository.ValidateCertificate(
                certificate.Certificate,
                "SHA256",
                insideValidity,
                out var reason));
            AssertEx.Equal<string>(null, reason);

            AssertEx.False(CertificateRepository.ValidateCertificate(
                certificate.Certificate,
                "SHA256",
                certificate.Certificate.NotBefore.ToUniversalTime().AddTicks(-1),
                out reason));
            AssertEx.Contains("next timestamp signing time", reason);

            AssertEx.False(CertificateRepository.ValidateCertificate(
                certificate.Certificate,
                "SHA256",
                certificate.Certificate.NotAfter.ToUniversalTime().AddTicks(1),
                out reason));
            AssertEx.Contains("next timestamp signing time", reason);

            using var publicOnly = X509CertificateLoader.LoadCertificate(
                certificate.Certificate.Export(X509ContentType.Cert));
            AssertEx.False(CertificateRepository.ValidateCertificate(
                publicOnly,
                "SHA256",
                insideValidity,
                out reason));
            AssertEx.Contains("private key", reason,
                "Health validation must prove access to the selected signing key.");
        }
    }

    private static void CertificateTrustPolicy()
    {
        using (var certificate = new TimestampCertificateFixture())
        {
            var validationTime = new DateTime(2026, 7, 16, 12, 0, 0, DateTimeKind.Utc);
            AssertEx.True(CertificateRepository.ValidateCertificateTrust(
                certificate.Certificate,
                validationTime,
                true,
                out var reason));
            AssertEx.Equal<string>(null, reason);

            AssertEx.False(CertificateRepository.ValidateCertificateTrust(
                certificate.Certificate,
                validationTime,
                false,
                out reason));
            AssertEx.Contains("chain", reason);
            AssertEx.False(CertificateRepository.ValidateCertificateTrust(null, validationTime, true, out reason));

            var configuration = TestFixtures.CreateConfiguration();
            var productionCacheKey = CertificateRepository.BuildSelectionCacheKey(configuration);
            configuration.AllowUntrustedDevelopmentCertificate = true;
            AssertEx.NotEqual(productionCacheKey, CertificateRepository.BuildSelectionCacheKey(configuration));
        }
    }

    private static void FipsRegistryInterpretation()
    {
        AssertEx.Equal(MLDsa.IsSupported, PlatformSecurityPolicy.IsMldsaSupported);
        AssertEx.False(PlatformSecurityPolicy.InterpretFipsRegistryValue(null));
        AssertEx.False(PlatformSecurityPolicy.InterpretFipsRegistryValue(0));
        AssertEx.True(PlatformSecurityPolicy.InterpretFipsRegistryValue(1));
        AssertEx.True(PlatformSecurityPolicy.InterpretFipsRegistryValue(-1));
        AssertEx.True(PlatformSecurityPolicy.InterpretFipsRegistryValue("0"));
        AssertEx.True(PlatformSecurityPolicy.InterpretFipsRegistryValue(0L));
    }

    private static void PreallocationGuards()
    {
        using (var directory = new TemporaryDirectory())
        using (var weakCertificate = new TimestampCertificateFixture(1024))
        {
            var path = directory.File("preallocation.bin");
            var stateStore = TestFixtures.CreateInitializedStateStore(path);
            var before = SnapshotFiles(directory.Path);
            var configuration = TestFixtures.CreateConfiguration();
            var request = TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]);
            var now = new DateTime(2026, 7, 16, 12, 0, 0, DateTimeKind.Utc);
            var processor = new Rfc3161TimestampProcessor();

            var weakKey = processor.Process(
                request,
                configuration,
                weakCertificate.Certificate,
                stateStore,
                now);
            AssertRejected(weakKey, Rfc3161FailureInfo.SystemFailure);
            AssertEx.Contains("2048", weakKey.Detail);
            AssertSnapshotUnchanged(before, directory.Path);

            using (var certificate = new TimestampCertificateFixture())
            {
                AssertEx.Throws<ArgumentNullException>(() => new AuthenticodeTimestampProcessor().Process(
                    TestFixtures.BuildAuthenticodeRequest([1, 2, 3]),
                    null,
                    certificate.Certificate,
                    stateStore,
                    now));

                AssertEx.Throws<OperationCanceledException>(() => processor.Process(
                    request,
                    configuration,
                    certificate.Certificate,
                    stateStore,
                    now,
                    new CancellationToken(true)));

                if (PlatformSecurityPolicy.IsLegacyAuthenticodeAllowed)
                {
                    var parsedSignature = AuthenticodeTimestampProcessor.ParseRequest(
                        TestFixtures.BuildAuthenticodeRequest([1, 2, 3]));
                    AssertEx.Throws<OperationCanceledException>(() =>
                        new AuthenticodeTimestampProcessor().ProcessParsedSignature(
                            parsedSignature,
                            configuration,
                            certificate.Certificate,
                            stateStore,
                            now,
                            new CancellationToken(true)));
                }
            }

            AssertSnapshotUnchanged(before, directory.Path);
        }
    }

    private static void ProtocolAllocationResamplesClock()
    {
        using var directory = new TemporaryDirectory();
        using var certificate = new TimestampCertificateFixture();
        var configuration = TestFixtures.CreateConfiguration();
        var now = new DateTime(2026, 7, 16, 12, 0, 0, DateTimeKind.Utc);
        var store = TestFixtures.CreateInitializedStateStore(directory.File("clock.bin"));
        store.Allocate(now.AddSeconds(3), TimeSpan.Zero, false);
        var sample = 0;
        Func<DateTime> clock = () => ++sample == 1 ? now : now.AddSeconds(4);
        var request = Rfc3161Request.Parse(TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]));
        var rfc3161 = new Rfc3161TimestampProcessor().Process(
            request, configuration, certificate.Certificate, store, clock, CancellationToken.None);
        AssertEx.True(rfc3161.Granted, rfc3161.Detail);
        AssertEx.Equal(now.AddSeconds(4), rfc3161.GenerationTimeUtc);
        if (!PlatformSecurityPolicy.IsLegacyAuthenticodeAllowed) return;

        sample = 0;
        var authenticode = new AuthenticodeTimestampProcessor().ProcessParsedSignature(
            [1, 2, 3], configuration, certificate.Certificate, store, clock, CancellationToken.None);
        AssertEx.Equal(now.AddSeconds(4), authenticode.GenerationTimeUtc);
    }

    private static void Rfc3161HappyPath()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var configuration = TestFixtures.CreateConfiguration();
            var stateStore = TestFixtures.CreateInitializedStateStore(directory.File("issuance.bin"));
            var now = new DateTime(2026, 7, 16, 13, 14, 15, 123, DateTimeKind.Utc);
            var digest = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
            var nonce = new byte[] { 0xde, 0xad, 0xbe, 0xef, 0x01 };
            var request = TestFixtures.BuildRfc3161Request(
                TestFixtures.Sha256Oid,
                digest,
                TestFixtures.AlternatePolicyOid,
                nonce,
                true);

            var parsedRequest = Rfc3161Request.Parse(request);
            AssertEx.True(new Rfc3161TimestampProcessor().TryPreflight(
                parsedRequest,
                configuration,
                out var preflightRejection));
            AssertEx.Equal<Rfc3161Result>(null, preflightRejection);
            var result = new Rfc3161TimestampProcessor().Process(
                parsedRequest,
                configuration,
                certificate.Certificate,
                stateStore,
                now);
            AssertEx.True(result.Granted, result.Detail);
            AssertEx.Equal<Rfc3161FailureInfo?>(null, result.FailureInfo);
            AssertEx.Equal(TestFixtures.AlternatePolicyOid, result.PolicyOid);
            AssertEx.Equal(TestFixtures.Sha256Oid, result.HashAlgorithmOid);
            AssertEx.SequenceEqual(digest, result.MessageImprint);
            AssertEx.Equal(now, result.GenerationTimeUtc);
            AssertEx.Equal(0, TestFixtures.ExtractRfc3161Status(result.EncodedResponse));

            var token = TestFixtures.ExtractGrantedRfc3161Token(result.EncodedResponse);
            var cms = TestFixtures.DecodeCms(token);
            AssertEx.Equal(Rfc3161TimestampProcessor.TstInfoContentTypeOid, cms.ContentInfo.ContentType.Value);
            // Correctly versioned non-id-data SignedData is exposed as the unwrapped TSTInfo value.
            var tstInfoOuter = new DerReader(cms.ContentInfo.Content);
            var tstInfo = tstInfoOuter.ReadSequence();
            tstInfoOuter.ThrowIfNotEmpty();
            AssertEx.Equal(1, tstInfo.ReadIntegerInt32());
            AssertEx.Equal(TestFixtures.AlternatePolicyOid, tstInfo.ReadObjectIdentifier());
            var imprint = tstInfo.ReadSequence();
            var algorithmIdentifier = new DerReader(imprint.ReadEncodedValue()).ReadSequence();
            AssertEx.Equal(TestFixtures.Sha256Oid, algorithmIdentifier.ReadObjectIdentifier());
            algorithmIdentifier.ReadNull();
            algorithmIdentifier.ThrowIfNotEmpty();
            AssertEx.SequenceEqual(digest, imprint.ReadOctetString());
            imprint.ThrowIfNotEmpty();
            AssertEx.SequenceEqual(result.SerialNumber, tstInfo.ReadPositiveInteger());
            var encodedTime = tstInfo.ReadEncodedValue();
            AssertEx.Equal((byte)0x18, encodedTime[0], "genTime must use GeneralizedTime.");
            AssertEx.SequenceEqual(nonce, tstInfo.ReadPositiveInteger());
            tstInfo.ThrowIfNotEmpty();
        }
    }

    private static void Rfc3161CertificateInclusion()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var configuration = TestFixtures.CreateConfiguration();
            var now = new DateTime(2026, 7, 16, 14, 0, 0, DateTimeKind.Utc);
            var processor = new Rfc3161TimestampProcessor();

            var requestedStore = TestFixtures.CreateInitializedStateStore(directory.File("with-cert.bin"));
            var withCertificate = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], certificateRequested: true),
                configuration,
                certificate.Certificate,
                requestedStore,
                now);
            AssertEx.True(withCertificate.Granted, withCertificate.Detail);
            var withCertificateCms = TestFixtures.DecodeCms(TestFixtures.ExtractGrantedRfc3161Token(withCertificate.EncodedResponse));
            AssertEx.True(withCertificateCms.Certificates.Cast<X509Certificate2>().Any(item =>
                string.Equals(item.Thumbprint, certificate.Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)));

            configuration.IncludeCertificateChain = true;
            var chainStore = TestFixtures.CreateInitializedStateStore(directory.File("with-chain.bin"));
            var withChain = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], certificateRequested: true),
                configuration,
                certificate.Certificate,
                chainStore,
                now);
            AssertEx.True(withChain.Granted, withChain.Detail);
            var withChainCms = TestFixtures.DecodeCms(TestFixtures.ExtractGrantedRfc3161Token(withChain.EncodedResponse));
            AssertEx.True(withChainCms.Certificates.Cast<X509Certificate2>().Any(item =>
                string.Equals(item.Thumbprint, certificate.Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)),
                "certReq must include the TSA signing certificate even when it is a self-signed test certificate.");

            var omittedStore = TestFixtures.CreateInitializedStateStore(directory.File("without-cert.bin"));
            configuration.IncludeCertificateChain = false;
            var withoutCertificate = processor.Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]),
                configuration,
                certificate.Certificate,
                omittedStore,
                now);
            AssertEx.True(withoutCertificate.Granted, withoutCertificate.Detail);
            var withoutCertificateCms = TestFixtures.DecodeCms(TestFixtures.ExtractGrantedRfc3161Token(withoutCertificate.EncodedResponse));
            AssertEx.Equal(0, withoutCertificateCms.Certificates.Count);
            withoutCertificateCms.CheckSignature(new X509Certificate2Collection(certificate.Certificate), true);
        }
    }

    private static void Rfc3161CmsSignatureAndEss()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var configuration = TestFixtures.CreateConfiguration();
            var stateStore = TestFixtures.CreateInitializedStateStore(directory.File("issuance.bin"));
            var now = new DateTime(2026, 7, 16, 15, 0, 0, DateTimeKind.Utc);
            var result = new Rfc3161TimestampProcessor().Process(
                TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], certificateRequested: true),
                configuration,
                certificate.Certificate,
                stateStore,
                now);
            AssertEx.True(result.Granted, result.Detail);
            var cms = TestFixtures.DecodeCms(TestFixtures.ExtractGrantedRfc3161Token(result.EncodedResponse));
            AssertEx.Equal(1, cms.SignerInfos.Count);
            cms.CheckSignature(true);
            var signer = cms.SignerInfos[0];
            AssertEx.Equal(TestFixtures.Sha256Oid, signer.DigestAlgorithm.Value);
            AssertEx.True(HasSignedAttribute(signer, SigningTimeOid), "CMS signer must carry signingTime.");

            var ess = signer.SignedAttributes.Cast<CryptographicAttributeObject>()
                .SingleOrDefault(attribute => attribute.Oid.Value == SigningCertificateV2Oid);
            AssertEx.NotNull(ess, "CMS signer must carry ESS signingCertificateV2.");
            AssertEx.Equal(1, ess.Values.Count);
            var actualCertificateHash = ReadEssCertificateHash(ess.Values[0], out var certificateHashAlgorithmOid);
            AssertEx.Equal<string>(null, certificateHashAlgorithmOid,
                "SHA256 ESSCertIDv2 must use the omitted default hash algorithm.");
            byte[] expectedCertificateHash;
            using (var sha256 = new SHA256Cng())
            {
                expectedCertificateHash = sha256.ComputeHash(certificate.Certificate.RawData);
            }

            AssertEx.SequenceEqual(expectedCertificateHash, actualCertificateHash);
        }
    }

    private static void Rfc3161SigningDigestAlgorithms()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var configuration = TestFixtures.CreateConfiguration();
            var processor = new Rfc3161TimestampProcessor();
            var now = new DateTime(2026, 7, 16, 15, 30, 0, DateTimeKind.Utc);
            foreach (var algorithm in HashAlgorithmCatalog.All.Where(item => item.CmsSigningSupported))
            {
                configuration.SigningDigestAlgorithm = algorithm.Name;
                var stateStore = TestFixtures.CreateInitializedStateStore(directory.File("sign-" + algorithm.Name + ".bin"));
                var result = processor.Process(
                    TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], certificateRequested: true),
                    configuration,
                    certificate.Certificate,
                    stateStore,
                    now);
                if (!PlatformSecurityPolicy.IsSigningHashAllowed(algorithm))
                {
                    AssertRejected(result, Rfc3161FailureInfo.SystemFailure);
                    continue;
                }

                AssertEx.True(result.Granted, algorithm.Name + ": " + result.Detail);
                var encodedToken = TestFixtures.ExtractGrantedRfc3161Token(result.EncodedResponse);
                AssertRfc3161CmsEnvelope(encodedToken, algorithm);
                var cms = TestFixtures.DecodeCms(encodedToken);
                cms.CheckSignature(true);
                AssertEx.Equal(algorithm.Oid, cms.SignerInfos[0].DigestAlgorithm.Value);
                var expectedEssOid = string.Equals(algorithm.Name, "SHA1", StringComparison.Ordinal)
                    ? SigningCertificateOid
                    : SigningCertificateV2Oid;
                var ess = cms.SignerInfos[0].SignedAttributes.Cast<CryptographicAttributeObject>()
                    .SingleOrDefault(attribute => attribute.Oid.Value == expectedEssOid);
                AssertEx.NotNull(ess,
                    algorithm.Name + " must carry the corresponding ESS signing-certificate attribute.");
                AssertEx.Equal(1, ess.Values.Count);
                using HashAlgorithm certificateHashAlgorithm = algorithm.Name switch
                {
                    "SHA1" => new SHA1Cng(),
                    "SHA256" => new SHA256Cng(),
                    "SHA384" => new SHA384Cng(),
                    "SHA512" => new SHA512Cng(),
                    _ => throw new InvalidOperationException("Unexpected CMS signing hash.")
                };
                var expectedCertificateHash = certificateHashAlgorithm.ComputeHash(certificate.Certificate.RawData);
                var actualCertificateHash = ReadEssCertificateHash(
                    ess.Values[0],
                    out var certificateHashAlgorithmOid);
                var expectedCertificateHashAlgorithmOid = algorithm.Name is "SHA1" or "SHA256"
                    ? null
                    : algorithm.Oid;

                AssertEx.Equal(expectedCertificateHashAlgorithmOid, certificateHashAlgorithmOid);
                AssertEx.SequenceEqual(expectedCertificateHash, actualCertificateHash);
            }
        }
    }

    private static void AuthenticodeResponse()
    {
        using (var directory = new TemporaryDirectory())
        using (var certificate = new TimestampCertificateFixture())
        {
            var signature = Enumerable.Range(0, 96).Select(value => (byte)(value * 3)).ToArray();
            var request = TestFixtures.BuildAuthenticodeRequest(signature);
            var parsedSignature = AuthenticodeTimestampProcessor.ParseRequest(request);
            var processor = new AuthenticodeTimestampProcessor();
            var configuration = TestFixtures.CreateConfiguration();
            var store = TestFixtures.CreateInitializedStateStore(directory.File("authenticode.bin"));
            var now = new DateTime(2026, 7, 16, 16, 0, 0, DateTimeKind.Utc);

            if (!PlatformSecurityPolicy.IsLegacyAuthenticodeAllowed)
            {
                var disabled = AssertEx.Throws<AuthenticodeProtocolException>(() =>
                    processor.ProcessParsedSignature(
                        parsedSignature,
                        configuration,
                        certificate.Certificate,
                        store,
                        now));
                AssertEx.Contains("FIPS", disabled.Message);
                return;
            }

            var result = processor.ProcessParsedSignature(
                parsedSignature,
                configuration,
                certificate.Certificate,
                store,
                now);
            AssertEx.SequenceEqual(signature, result.RequestedSignature);
            AssertEx.Equal(now, result.GenerationTimeUtc);
            AssertEx.NotNull(result.AuditSerialNumber);
            var cms = TestFixtures.DecodeCms(result.EncodedResponse);
            AssertEx.Equal(AuthenticodeTimestampProcessor.DataContentTypeOid, cms.ContentInfo.ContentType.Value);
            AssertEx.SequenceEqual(signature, cms.ContentInfo.Content);
            AssertEx.Equal(1, cms.SignerInfos.Count);
            AssertEx.True(cms.Certificates.Count > 0);
            cms.CheckSignature(true);
            AssertEx.True(HasSignedAttribute(cms.SignerInfos[0], SigningCertificateV2Oid));
        }
    }

    private static void AssertRejected(Rfc3161Result result, Rfc3161FailureInfo failure)
    {
        AssertEx.False(result.Granted);
        AssertEx.Equal<Rfc3161FailureInfo?>(failure, result.FailureInfo);
        AssertEx.Equal(2, TestFixtures.ExtractRfc3161Status(result.EncodedResponse));
        AssertEx.Equal((int)failure, TestFixtures.ExtractRfc3161FailureBit(result.EncodedResponse));
    }

    private static bool HasSignedAttribute(SignerInfo signer, string oid)
    {
        return signer.SignedAttributes.Cast<CryptographicAttributeObject>()
            .Any(attribute => string.Equals(attribute.Oid.Value, oid, StringComparison.Ordinal));
    }

    private static void AssertRfc3161CmsEnvelope(byte[] encodedCms, TimestampHashAlgorithm expectedDigest)
    {
        var outer = new DerReader(encodedCms);
        var contentInfo = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        AssertEx.Equal(Pkcs7SignedDataOid, contentInfo.ReadObjectIdentifier());
        var explicitContent = contentInfo.ReadConstructed(0xa0);
        contentInfo.ThrowIfNotEmpty();
        var signedData = explicitContent.ReadSequence();
        explicitContent.ThrowIfNotEmpty();
        AssertEx.Equal(3, signedData.ReadIntegerInt32(),
            "Non-id-data RFC 3161 content requires SignedData version 3.");

        var digestAlgorithms = signedData.ReadConstructed(0x31);
        ReadAlgorithmIdentifier(
            digestAlgorithms,
            out var outerDigestOid,
            out var outerDigestHasParameters);
        digestAlgorithms.ThrowIfNotEmpty();
        AssertEx.Equal(expectedDigest.Oid, outerDigestOid);
        if (IsSha2Digest(expectedDigest.Oid))
        {
            AssertEx.False(outerDigestHasParameters,
                "Generated SHA-2 digest AlgorithmIdentifier parameters must be absent.");
        }

        var encapsulatedContent = signedData.ReadSequence();
        AssertEx.Equal(TstInfoContentTypeOid, encapsulatedContent.ReadObjectIdentifier());
        while (encapsulatedContent.HasData) encapsulatedContent.ReadEncodedValue();
        while (signedData.HasData && (signedData.PeekTag() == 0xa0 || signedData.PeekTag() == 0xa1))
        {
            signedData.ReadEncodedValue();
        }

        var signerInfos = signedData.ReadConstructed(0x31);
        signedData.ThrowIfNotEmpty();
        var signerInfo = signerInfos.ReadSequence();
        signerInfos.ThrowIfNotEmpty();
        signerInfo.ReadIntegerInt32();
        signerInfo.ReadEncodedValue();
        ReadAlgorithmIdentifier(
            signerInfo,
            out var signerDigestOid,
            out var signerDigestHasParameters);
        AssertEx.Equal(expectedDigest.Oid, signerDigestOid);
        if (IsSha2Digest(expectedDigest.Oid))
        {
            AssertEx.False(signerDigestHasParameters,
                "Generated SHA-2 SignerInfo digest AlgorithmIdentifier parameters must be absent.");
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

    private static bool IsSha2Digest(string oid) =>
        string.Equals(oid, "2.16.840.1.101.3.4.2.4", StringComparison.Ordinal) ||
        string.Equals(oid, "2.16.840.1.101.3.4.2.1", StringComparison.Ordinal) ||
        string.Equals(oid, "2.16.840.1.101.3.4.2.2", StringComparison.Ordinal) ||
        string.Equals(oid, "2.16.840.1.101.3.4.2.3", StringComparison.Ordinal);

    private static byte[] ReadEssCertificateHash(
        AsnEncodedData encodedAttributeValue,
        out string hashAlgorithmOid)
    {
        var outer = new DerReader(encodedAttributeValue.RawData);
        var signingCertificate = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        var certificates = signingCertificate.ReadSequence();
        signingCertificate.ThrowIfNotEmpty();
        var essCertId = certificates.ReadSequence();
        certificates.ThrowIfNotEmpty();
        hashAlgorithmOid = null;
        if (essCertId.HasData && essCertId.PeekTag() == 0x30)
        {
            ReadAlgorithmIdentifier(essCertId, out hashAlgorithmOid, out var hasParameters);
            AssertEx.False(hasParameters, "ESS SHA-2 AlgorithmIdentifier parameters must be absent.");
        }

        var certificateHash = essCertId.ReadOctetString();
        essCertId.ThrowIfNotEmpty();
        return certificateHash;
    }

    private static Dictionary<string, byte[]> SnapshotFiles(string directory) =>
        Directory.GetFiles(directory).ToDictionary(
            Path.GetFileName,
            File.ReadAllBytes,
            StringComparer.OrdinalIgnoreCase);

    private static void AssertSnapshotUnchanged(
        IReadOnlyDictionary<string, byte[]> expected,
        string directory)
    {
        var actual = SnapshotFiles(directory);
        AssertEx.Equal(expected.Count, actual.Count);
        foreach (var file in expected)
        {
            AssertEx.True(actual.TryGetValue(file.Key, out var contents), file.Key + " disappeared unexpectedly.");
            AssertEx.SequenceEqual(file.Value, contents, file.Key + " changed before durable allocation.");
        }
    }
}
