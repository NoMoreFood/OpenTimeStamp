using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Issuance;

namespace OpenTimeStamp.Tests;

internal static class PersistenceAndConfigurationTests
{
    public static void Register(ICollection<TestCase> tests)
    {
        // Keep persistence, concurrency, and configuration coverage grouped by subsystem.
        tests.Add(new TestCase("Issuance first allocation accepts rollback tolerance", FirstAllocationWithTolerance));
        tests.Add(new TestCase("Issuance state is durable and serials are unique", DurableUniqueSerialAllocation));
        tests.Add(new TestCase("Issuance ordering and rollback protection", OrderingAndClockRollback));
        tests.Add(new TestCase("Issuance allocation is concurrency-safe", ConcurrentAllocation));
        tests.Add(new TestCase("Issuance filesystem lock coordinates external handles", IssuanceFilesystemLock));
        tests.Add(new TestCase("Issuance cancellation stops lock waits without allocation", IssuanceCancellation));
        tests.Add(new TestCase("Issuance fast path honors staged recovery state", StagedStateRecovery));
        tests.Add(new TestCase("Issuance missing and corrupt state recovers or fails closed", MissingAndCorruptStateRecovery));
        tests.Add(new TestCase("Issuance partial state rollback is rejected", PartialStateRollbackRejected));
        tests.Add(new TestCase("Issuance coherent snapshot rollback requires an external anchor", CoherentSnapshotRollbackBoundary));
        tests.Add(new TestCase("Issuance legacy state migrates without resetting", LegacyStateMigration));
        tests.Add(new TestCase("Issuance health validation requires write access", HealthValidationRequiresWriteAccess));
        tests.Add(new TestCase("Configuration defaults fail safe until provisioned", ConfigurationDefaultsFailSafe));
        tests.Add(new TestCase(
            "Configuration clone copies values and isolates lists",
            ConfigurationCloneIsIndependent));
        tests.Add(new TestCase("Configuration XML round-trip and normalization", ConfigurationRoundTrip));
        tests.Add(new TestCase("Configuration compare-and-swap rejects stale writers", ConfigurationCompareAndSwap));
        tests.Add(new TestCase("Configuration concurrent writers have one CAS winner", ConcurrentConfigurationCompareAndSwap));
        tests.Add(new TestCase("Configuration filesystem lock coordinates external handles", ConfigurationFilesystemLock));
        tests.Add(new TestCase("Configuration load detects same-metadata replacement", ConfigurationLoadDetectsSameMetadataReplacement));
        tests.Add(new TestCase("Configuration null root is rejected safely", NullConfigurationRootRejected));
        tests.Add(new TestCase("Audit health probe exercises the active append target", AuditProbeUsesActiveLog));
        tests.Add(new TestCase("Audit filesystem lock coordinates external handles", AuditFilesystemLock));
        tests.Add(new TestCase("Audit retention continues and retries at a bounded cadence", AuditRetentionRetryIsBounded));
        tests.Add(new TestCase("Audit rollover and pruning follow configuration", AuditRolloverAndPruning));
    }

    private static void FirstAllocationWithTolerance()
    {
        using (var directory = new TemporaryDirectory())
        {
            var now = new DateTime(2026, 7, 16, 17, 0, 0, DateTimeKind.Utc);
            var store = new IssuanceStateStore(directory.File("issuance.bin"));
            AssertEx.Throws<IssuanceStateException>(() =>
                store.Allocate(now, TimeSpan.FromSeconds(2), false),
                "Allocation must never implicitly create a missing state store.");
            store.Initialize();
            var allocation = store.Allocate(now, TimeSpan.FromSeconds(2), false);
            AssertEx.Equal(now, allocation.GenerationTimeUtc);
            AssertEx.Equal(16, allocation.SerialNumber.Length);
        }
    }

    private static void DurableUniqueSerialAllocation()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var now = new DateTime(2026, 7, 16, 18, 0, 0, DateTimeKind.Utc);
            var first = TestFixtures.CreateInitializedStateStore(path).Allocate(now, TimeSpan.Zero, false);
            AssertEx.True(File.Exists(path));
            AssertEx.True(File.Exists(path + ".lock"));
            var second = new IssuanceStateStore(path).Allocate(now, TimeSpan.Zero, false);
            AssertEx.NotEqual(TestFixtures.Hex(first.SerialNumber), TestFixtures.Hex(second.SerialNumber));
            AssertEx.SequenceEqual(TestFixtures.Incremented(first.SerialNumber), second.SerialNumber);
            AssertEx.Equal(first.GenerationTimeUtc, second.GenerationTimeUtc);

            var third = new IssuanceStateStore(path).Allocate(now.AddSeconds(1), TimeSpan.Zero, false);
            AssertEx.SequenceEqual(TestFixtures.Incremented(second.SerialNumber), third.SerialNumber);
            AssertEx.Equal(now.AddSeconds(1), third.GenerationTimeUtc);
            AssertEx.SequenceEqual(File.ReadAllBytes(path), File.ReadAllBytes(path + ".bak"),
                "The recovery copy must mirror the committed generation, not the previous issued serial.");
        }
    }

    private static void OrderingAndClockRollback()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var store = TestFixtures.CreateInitializedStateStore(path);
            var now = new DateTime(2026, 7, 16, 19, 0, 0, DateTimeKind.Utc);
            var first = store.Allocate(now, TimeSpan.Zero, true);
            var ordered = store.Allocate(now.AddMilliseconds(-500), TimeSpan.FromSeconds(1), true);
            AssertEx.Equal(first.GenerationTimeUtc.AddTicks(1), ordered.GenerationTimeUtc);
            AssertEx.SequenceEqual(TestFixtures.Incremented(first.SerialNumber), ordered.SerialNumber);

            AssertEx.Throws<ClockRollbackException>(() =>
                store.Allocate(now.AddSeconds(-5), TimeSpan.FromSeconds(1), true));
            store.Validate(ordered.GenerationTimeUtc.AddSeconds(-1), TimeSpan.FromSeconds(1));
            AssertEx.Throws<ClockRollbackException>(() =>
                store.Validate(ordered.GenerationTimeUtc.AddSeconds(-2), TimeSpan.FromSeconds(1)));

            var nextOrderedTime = store.ValidateAndGetNextGenerationTime(
                ordered.GenerationTimeUtc,
                TimeSpan.Zero,
                true);
            AssertEx.Equal(ordered.GenerationTimeUtc.AddTicks(1), nextOrderedTime,
                "Strict ordering must preview the same one-tick advance used by allocation.");
            AssertEx.Equal(
                ordered.GenerationTimeUtc,
                store.ValidateAndGetNextGenerationTime(ordered.GenerationTimeUtc, TimeSpan.Zero, false));

            var afterFailure = new IssuanceStateStore(path).Allocate(ordered.GenerationTimeUtc, TimeSpan.Zero, true);
            AssertEx.SequenceEqual(TestFixtures.Incremented(ordered.SerialNumber), afterFailure.SerialNumber,
                "A rejected rollback must not consume a serial number.");
            AssertEx.Equal(nextOrderedTime, afterFailure.GenerationTimeUtc,
                "Preview validation must not consume or otherwise change the next allocation.");
        }
    }

    private static void ConcurrentAllocation()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var now = new DateTime(2026, 7, 16, 20, 0, 0, DateTimeKind.Utc);
            TestFixtures.CreateInitializedStateStore(path).Allocate(now, TimeSpan.Zero, false);
            var serials = new ConcurrentBag<string>();
            Parallel.For(0, 32, index =>
            {
                var allocation = new IssuanceStateStore(path).Allocate(now.AddSeconds(1), TimeSpan.Zero, false);
                serials.Add(TestFixtures.Hex(allocation.SerialNumber));
            });
            AssertEx.Equal(32, serials.Count);
            AssertEx.Equal(32, serials.Distinct(StringComparer.Ordinal).Count());
        }
    }

    private static void IssuanceFilesystemLock()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var store = TestFixtures.CreateInitializedStateStore(path);
            AssertExclusiveHandleBlocks(
                path + ".lock",
                store.Validate,
                "An external handle must participate in the issuance filesystem lock.",
                "Issuance access did not resume after the filesystem lock was released.");
        }
    }

    private static void IssuanceCancellation()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance-cancellation.bin");
            var store = TestFixtures.CreateInitializedStateStore(path);
            var artifactPaths = new[] { path, path + ".bak", path + ".meta", path + ".meta.bak" };
            var before = artifactPaths.ToDictionary(item => item, File.ReadAllBytes, StringComparer.OrdinalIgnoreCase);
            var now = new DateTime(2026, 7, 16, 20, 0, 0, DateTimeKind.Utc);

            using (var cancellation = new CancellationTokenSource())
            using (var started = new ManualResetEventSlim())
            using (new FileStream(path + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                var waiting = Task.Run(() =>
                {
                    started.Set();
                    store.Allocate(now, TimeSpan.Zero, false, cancellation.Token);
                });
                AssertEx.True(started.Wait(2000), "The cancellable issuance contender did not start.");
                AssertEx.False(waiting.Wait(150), "Issuance unexpectedly bypassed the external lock.");
                cancellation.Cancel();
                AssertEx.True(SpinWait.SpinUntil(() => waiting.IsCompleted, 2000),
                    "Cancellation did not stop the issuance lock wait promptly.");
                AssertEx.Throws<OperationCanceledException>(() => waiting.GetAwaiter().GetResult());
            }

            AssertEx.Throws<OperationCanceledException>(() =>
                store.Allocate(now, TimeSpan.Zero, false, new CancellationToken(true)));
            foreach (var artifact in before)
            {
                AssertEx.SequenceEqual(
                    artifact.Value,
                    File.ReadAllBytes(artifact.Key),
                    System.IO.Path.GetFileName(artifact.Key) + " changed during canceled allocation.");
            }
        }
    }

    private static void StagedStateRecovery()
    {
        using (var directory = new TemporaryDirectory())
        {
            const int generationOffset = 20;
            const int serialOffset = 28;
            const int statePayloadLength = 52;
            const int markerIntegrityKeyOffset = 20;
            const int integrityKeyLength = 32;
            var path = directory.File("issuance-staged.bin");
            var store = TestFixtures.CreateInitializedStateStore(path);
            var staged = File.ReadAllBytes(path);
            var marker = File.ReadAllBytes(path + ".meta");
            var nextGeneration = BitConverter.ToUInt64(staged, generationOffset) + 1;
            Buffer.BlockCopy(BitConverter.GetBytes(nextGeneration), 0, staged, generationOffset, sizeof(ulong));
            var currentSerial = new byte[16];
            Buffer.BlockCopy(staged, serialOffset, currentSerial, 0, currentSerial.Length);
            var stagedSerial = TestFixtures.Incremented(currentSerial);
            Buffer.BlockCopy(stagedSerial, 0, staged, serialOffset, stagedSerial.Length);
            var integrityKey = new byte[integrityKeyLength];
            Buffer.BlockCopy(marker, markerIntegrityKeyOffset, integrityKey, 0, integrityKey.Length);
            using (var hmac = new HMACSHA256(integrityKey))
            {
                var integrity = hmac.ComputeHash(staged, 0, statePayloadLength);
                Buffer.BlockCopy(integrity, 0, staged, statePayloadLength, integrity.Length);
            }

            File.WriteAllBytes(path + ".new", staged);
            var allocation = store.Allocate(
                new DateTime(2026, 7, 16, 20, 15, 0, DateTimeKind.Utc),
                TimeSpan.Zero,
                false);
            AssertEx.SequenceEqual(TestFixtures.Incremented(stagedSerial), allocation.SerialNumber,
                "A valid staged generation must enter the full recovery candidate selection.");
        }
    }

    private static void MissingAndCorruptStateRecovery()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var now = new DateTime(2026, 7, 16, 20, 30, 0, DateTimeKind.Utc);
            var store = TestFixtures.CreateInitializedStateStore(path);
            AssertEx.True(File.Exists(path + ".meta.bak"));

            // The very first initialization commits a distinct same-generation marker mirror.
            // Repeated repair must refresh that mirror after replacing the active marker, so
            // later active-marker loss still does not lose the integrity key.
            store.Initialize();
            AssertEx.Equal("OTSB", Encoding.ASCII.GetString(File.ReadAllBytes(path + ".meta.bak"), 0, 4));
            File.Delete(path + ".meta");
            store.Initialize();
            AssertEx.True(File.Exists(path + ".meta"));
            AssertEx.True(File.Exists(path + ".meta.bak"));
            var first = store.Allocate(now, TimeSpan.Zero, true);
            AssertEx.True(File.Exists(path + ".bak"));
            AssertEx.True(File.Exists(path + ".meta"));

            // A missing active copy is recoverable because the backup mirrors the exact
            // committed generation rather than the previous (possibly issued) serial.
            File.Delete(path);
            var recovered = new IssuanceStateStore(path);
            recovered.Initialize();
            var second = recovered.Allocate(now, TimeSpan.Zero, true);
            AssertEx.SequenceEqual(TestFixtures.Incremented(first.SerialNumber), second.SerialNumber);
            AssertEx.Equal(first.GenerationTimeUtc.AddTicks(1), second.GenerationTimeUtc);

            // Independently corrupting the active record must recover from the authenticated
            // same-generation backup without rolling the serial or issuance time backward.
            var active = File.ReadAllBytes(path);
            active[28] ^= 0x01;
            File.WriteAllBytes(path, active);
            recovered.Initialize();
            var third = recovered.Allocate(second.GenerationTimeUtc, TimeSpan.Zero, true);
            AssertEx.SequenceEqual(TestFixtures.Incremented(second.SerialNumber), third.SerialNumber);
            AssertEx.Equal(second.GenerationTimeUtc.AddTicks(1), third.GenerationTimeUtc);

            // An independently missing active marker is recovered from its explicitly
            // committed same-generation mirror without changing serial or time state.
            File.Delete(path + ".meta");
            recovered.Initialize();
            var fourth = recovered.Allocate(third.GenerationTimeUtc, TimeSpan.Zero, true);
            AssertEx.SequenceEqual(TestFixtures.Incremented(third.SerialNumber), fourth.SerialNumber);
            AssertEx.Equal(third.GenerationTimeUtc.AddTicks(1), fourth.GenerationTimeUtc);

            // Once issuance has occurred, loss of every state copy must fail closed even
            // though the persistent initialization/high-water marker remains.
            File.Delete(path);
            File.Delete(path + ".bak");
            var missing = new IssuanceStateStore(path);
            AssertEx.Throws<IssuanceStateException>(() => missing.Initialize());
            AssertEx.Throws<IssuanceStateException>(() =>
                missing.Allocate(now.AddSeconds(1), TimeSpan.Zero, true));

            // A post-issuance marker mirror cannot reconstruct missing issued state. If both
            // state copies and the active marker disappear, recovery must still fail closed.
            var staleSeedPath = directory.File("stale-seed.bin");
            var staleSeedStore = TestFixtures.CreateInitializedStateStore(staleSeedPath);
            staleSeedStore.Allocate(now, TimeSpan.Zero, false);
            File.Delete(staleSeedPath);
            File.Delete(staleSeedPath + ".bak");
            File.Delete(staleSeedPath + ".meta");
            AssertEx.True(File.Exists(staleSeedPath + ".meta.bak"));
            var staleSeedRecovery = new IssuanceStateStore(staleSeedPath);
            AssertEx.Throws<IssuanceStateException>(() => staleSeedRecovery.Initialize());
            AssertEx.Throws<IssuanceStateException>(() => staleSeedRecovery.Validate());
            AssertEx.Throws<IssuanceStateException>(() =>
                staleSeedRecovery.Allocate(now.AddSeconds(1), TimeSpan.Zero, false));

            // A crash after flushing the first marker temporary but before its atomic move
            // is safe to resume: no published marker or backup means issuance was impossible.
            var stagedInitializationPath = directory.File("staged-initialization.bin");
            var stagedInitialization = TestFixtures.CreateInitializedStateStore(stagedInitializationPath);
            File.Delete(stagedInitializationPath);
            File.Delete(stagedInitializationPath + ".bak");
            File.Delete(stagedInitializationPath + ".meta.bak");
            File.Move(stagedInitializationPath + ".meta", stagedInitializationPath + ".meta.new");
            stagedInitialization.Initialize();
            stagedInitialization.Allocate(now, TimeSpan.Zero, false);

            // A torn sole first marker staging file contains no committed identity. With no
            // other state evidence it is safe to discard and restart initialization.
            var tornInitializationPath = directory.File("torn-initialization.bin");
            File.WriteAllBytes(tornInitializationPath + ".meta.new", new byte[] { 0x4f, 0x54, 0x53 });
            var tornInitialization = new IssuanceStateStore(tornInitializationPath);
            tornInitialization.Initialize();
            AssertEx.True(File.Exists(tornInitializationPath));
            AssertEx.True(File.Exists(tornInitializationPath + ".bak"));
            AssertEx.True(File.Exists(tornInitializationPath + ".meta"));
            AssertEx.True(File.Exists(tornInitializationPath + ".meta.bak"));
            tornInitialization.Allocate(now, TimeSpan.Zero, false);

            // Unknown state evidence cannot use the same recovery exception: it may represent
            // a committed OTS2 store whose only integrity key was lost.
            var unsafeTornPath = directory.File("unsafe-torn-initialization.bin");
            File.WriteAllBytes(unsafeTornPath, new byte[] { 0x4f, 0x54, 0x53, 0x32 });
            File.WriteAllBytes(unsafeTornPath + ".meta.new", new byte[] { 0x4f, 0x54, 0x53 });
            AssertEx.Throws<IssuanceStateException>(() => new IssuanceStateStore(unsafeTornPath).Initialize());
        }
    }

    private static void PartialStateRollbackRejected()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var now = new DateTime(2026, 7, 16, 20, 45, 0, DateTimeKind.Utc);
            var store = TestFixtures.CreateInitializedStateStore(path);
            store.Allocate(now, TimeSpan.Zero, false);
            var priorAuthenticatedState = File.ReadAllBytes(path);
            store.Allocate(now.AddSeconds(1), TimeSpan.Zero, false);

            // Replaying a structurally valid, correctly authenticated old state into both
            // copies is still rejected by the separately committed generation high-water.
            File.WriteAllBytes(path, priorAuthenticatedState);
            File.WriteAllBytes(path + ".bak", priorAuthenticatedState);
            AssertEx.Throws<IssuanceStateException>(() => store.Validate());

            // Losing the active marker still leaves the explicitly committed, same-generation
            // marker mirror, so replaying only the state files remains detectable.
            File.Delete(path + ".meta");
            AssertEx.Throws<IssuanceStateException>(() => store.Validate());

            // Independent byte tampering in every redundant state is detected as corruption.
            var tampered = (byte[])priorAuthenticatedState.Clone();
            tampered[28] ^= 0x80;
            File.WriteAllBytes(path, tampered);
            File.WriteAllBytes(path + ".bak", tampered);
            AssertEx.Throws<IssuanceStateException>(() => store.Validate());
        }
    }

    private static void CoherentSnapshotRollbackBoundary()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var now = new DateTime(2026, 7, 16, 20, 47, 0, DateTimeKind.Utc);
            var store = TestFixtures.CreateInitializedStateStore(path);
            store.Allocate(now, TimeSpan.Zero, false);
            var snapshotState = File.ReadAllBytes(path);
            var snapshotBackup = File.ReadAllBytes(path + ".bak");
            var snapshotMarker = File.ReadAllBytes(path + ".meta");
            var snapshotMarkerBackup = File.ReadAllBytes(path + ".meta.bak");
            var second = store.Allocate(now.AddSeconds(1), TimeSpan.Zero, false);

            // State authentication detects partial replay only. A coherent old copy includes
            // its matching key and high-water marker, so local files cannot distinguish it
            // from the point in time when it was current. Backup/restore procedures therefore
            // need an external monotonic or append-only generation anchor.
            File.WriteAllBytes(path, snapshotState);
            File.WriteAllBytes(path + ".bak", snapshotBackup);
            File.WriteAllBytes(path + ".meta", snapshotMarker);
            File.WriteAllBytes(path + ".meta.bak", snapshotMarkerBackup);
            store.Validate();
            var replayed = store.Allocate(now.AddSeconds(1), TimeSpan.Zero, false);
            AssertEx.SequenceEqual(second.SerialNumber, replayed.SerialNumber,
                "This documents the whole-snapshot rollback boundary; " +
                "do not claim local anti-rollback protection for it.");
        }
    }

    private static void LegacyStateMigration()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var issuedAt = new DateTime(2026, 7, 16, 20, 50, 0, DateTimeKind.Utc);
            var legacySerial = Enumerable.Range(1, 16).Select(value => (byte)value).ToArray();
            using (FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (BinaryWriter writer = new(stream, Encoding.UTF8, false))
            {
                writer.Write(Encoding.ASCII.GetBytes("OTS1"));
                writer.Write(legacySerial);
                writer.Write(issuedAt.Ticks);
            }

            // A crash may leave the first marker staging file truncated before the OTS1
            // active record is replaced. The intact legacy record proves migration can retry.
            File.WriteAllBytes(path + ".meta.new", new byte[] { 0x4f, 0x54, 0x53 });

            var store = new IssuanceStateStore(path);
            store.Initialize();
            AssertEx.True(File.Exists(path + ".meta"));
            AssertEx.True(File.Exists(path + ".meta.bak"));

            // The first completed migration also has an independently usable marker mirror.
            File.Delete(path + ".meta");
            store.Initialize();
            var allocation = store.Allocate(issuedAt, TimeSpan.Zero, true);
            AssertEx.SequenceEqual(TestFixtures.Incremented(legacySerial), allocation.SerialNumber);
            AssertEx.Equal(issuedAt.AddTicks(1), allocation.GenerationTimeUtc);
            AssertEx.Equal("OTS2", Encoding.ASCII.GetString(File.ReadAllBytes(path), 0, 4));
            AssertEx.True(File.Exists(path + ".meta"));
        }
    }

    private static void HealthValidationRequiresWriteAccess()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var store = TestFixtures.CreateInitializedStateStore(path);
            store.Allocate(DateTime.UtcNow, TimeSpan.Zero, false);
            store.Validate();

            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
            try
            {
                AssertEx.Throws<IssuanceStateException>(
                    () => store.Validate(),
                    "Health validation must reject a read-only issuance artifact.");
            }
            finally
            {
                File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
            }

            var currentUser = WindowsIdentity.GetCurrent().User;
            if (currentUser is null) throw new InvalidOperationException("The current Windows identity has no SID.");

            var originalSecurity = File.GetAccessControl(path);
            var originalAccess = originalSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            var parentPath = Path.GetDirectoryName(path);
            var originalParentSecurity = Directory.GetAccessControl(parentPath);
            var originalParentAccess = originalParentSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            var restrictedSecurity = File.GetAccessControl(path);
            restrictedSecurity.AddAccessRule(new FileSystemAccessRule(
                currentUser,
                FileSystemRights.Delete,
                AccessControlType.Deny));
            File.SetAccessControl(path, restrictedSecurity);
            var restrictedParentSecurity = Directory.GetAccessControl(parentPath);
            restrictedParentSecurity.AddAccessRule(new FileSystemAccessRule(
                currentUser,
                FileSystemRights.DeleteSubdirectoriesAndFiles,
                AccessControlType.Deny));
            Directory.SetAccessControl(parentPath, restrictedParentSecurity);
            try
            {
                // Read/write access alone is insufficient for the File.Replace commit path.
                AssertEx.Throws<IssuanceStateException>(
                    () => store.Validate(),
                    "Health validation must reject an issuance artifact whose ACL denies DELETE.");
            }
            finally
            {
                var restoredSecurity = File.GetAccessControl(path);
                restoredSecurity.SetSecurityDescriptorSddlForm(originalAccess, AccessControlSections.Access);
                File.SetAccessControl(path, restoredSecurity);
                var restoredParentSecurity = Directory.GetAccessControl(parentPath);
                restoredParentSecurity.SetSecurityDescriptorSddlForm(
                    originalParentAccess,
                    AccessControlSections.Access);
                Directory.SetAccessControl(parentPath, restoredParentSecurity);
            }
        }
    }

    private static void ConfigurationDefaultsFailSafe()
    {
        var configuration = new ServiceConfiguration();
        AssertEx.False(configuration.Rfc3161Enabled);
        AssertEx.False(configuration.AuthenticodeEnabled);
        AssertEx.Equal(0, configuration.AccuracySeconds);
        AssertEx.Equal(0, configuration.AccuracyMilliseconds);
        AssertEx.False(configuration.AllowUntrustedDevelopmentCertificate);
        AssertEx.Equal(ServiceConfiguration.AutomaticCertificateSelection, configuration.CertificateSelectionMode);
        AssertEx.Equal(ServiceConfiguration.DailyLogRollover, configuration.LogRolloverInterval);
        AssertEx.Equal(365, configuration.LogRetentionDays);
        AssertEx.True(configuration.PruneAuditLogs);
        AssertEx.Equal("BUILTIN\\Administrators", configuration.AdminAllowedWindowsGroups.Single());
        AssertEx.Equal(0, configuration.Validate().Count);

        var nonCanonicalOid = new ServiceConfiguration
        {
            DefaultPolicyOid = "1.02.3",
            AcceptedPolicyOids = ["1.02.3"]
        };
        AssertEx.True(nonCanonicalOid.Validate().Any(item =>
            item.IndexOf("policy OID", StringComparison.OrdinalIgnoreCase) >= 0 &&
            item.IndexOf("not valid", StringComparison.OrdinalIgnoreCase) >= 0));

        configuration.Rfc3161Enabled = true;
        configuration.CertificateSelectionMode = ServiceConfiguration.ManualCertificateSelection;
        var errors = configuration.Validate();
        AssertEx.True(errors.Any(item => item.IndexOf("policy OID", StringComparison.OrdinalIgnoreCase) >= 0));
        AssertEx.True(errors.Any(item => item.IndexOf("certificate", StringComparison.OrdinalIgnoreCase) >= 0));

        configuration.CertificateSelectionMode = ServiceConfiguration.AutomaticCertificateSelection;
        AssertEx.False(configuration.Validate().Any(item => item.IndexOf("certificate", StringComparison.OrdinalIgnoreCase) >= 0),
            "Automatic selection must not require a configured thumbprint.");

        configuration.DefaultPolicyOid = TestFixtures.DefaultPolicyOid;
        configuration.AcceptedPolicyOids = [TestFixtures.DefaultPolicyOid];
        configuration.CertificateThumbprint = "AA";
        configuration.AccuracySeconds = 1;
        AssertEx.True(configuration.Validate().Any(item =>
            item.IndexOf("backward clock adjustment", StringComparison.OrdinalIgnoreCase) >= 0));

        configuration.AccuracySeconds = 0;
        configuration.AdminAllowedWindowsGroups.Clear();
        AssertEx.True(configuration.Validate().Any(item =>
            item.IndexOf("Windows group or SID", StringComparison.OrdinalIgnoreCase) >= 0));
    }

    private static void ConfigurationCloneIsIndependent()
    {
        var source = new ServiceConfiguration
        {
            SchemaVersion = 7,
            Rfc3161Enabled = true,
            AuthenticodeEnabled = true,
            AuthenticationMode = "Windows",
            CertificateStoreLocation = "CurrentUser",
            CertificateStoreName = "My",
            CertificateThumbprint = "AABBCC",
            CertificateSelectionMode = ServiceConfiguration.AutomaticCertificateSelection,
            DefaultPolicyOid = TestFixtures.DefaultPolicyOid,
            AcceptedPolicyOids = [TestFixtures.DefaultPolicyOid, TestFixtures.AlternatePolicyOid],
            AllowedHashAlgorithms = ["SHA256", "SHA512"],
            SigningDigestAlgorithm = "SHA512",
            IncludeCertificateChain = false,
            AccuracySeconds = 12,
            AccuracyMilliseconds = 345,
            Ordering = true,
            MaxRequestBytes = 131072,
            LogRetentionDays = 365,
            LogRolloverInterval = ServiceConfiguration.HourlyLogRollover,
            PruneAuditLogs = false,
            AdminAllowedWindowsGroups = ["S-1-5-32-544", "S-1-5-32-545"],
            FailClosedOnAuditError = false,
            LogMessageImprints = false,
            ClockRollbackToleranceSeconds = 12,
            AllowUntrustedDevelopmentCertificate = true
        };
        var clone = source.Clone();

        foreach (var property in typeof(ServiceConfiguration).GetProperties().Where(item => item.CanRead))
        {
            var sourceValue = property.GetValue(source);
            var cloneValue = property.GetValue(clone);
            if (sourceValue is List<string> sourceList)
            {
                var cloneList = (List<string>)cloneValue;
                AssertEx.False(
                    ReferenceEquals(sourceList, cloneList),
                    property.Name + " was not cloned independently.");
                AssertEx.Equal(string.Join("|", sourceList), string.Join("|", cloneList),
                    property.Name + " changed during cloning.");
                cloneList.Add("clone-only");
                AssertEx.False(sourceList.Contains("clone-only"), property.Name + " still shares mutable state.");
            }
            else
            {
                AssertEx.Equal(sourceValue, cloneValue, property.Name + " changed during cloning.");
            }
        }

        var nullLists = new ServiceConfiguration
        {
            AcceptedPolicyOids = null,
            AllowedHashAlgorithms = null,
            AdminAllowedWindowsGroups = null
        }.Clone();
        AssertEx.Equal(0, nullLists.AcceptedPolicyOids.Count);
        AssertEx.Equal(0, nullLists.AllowedHashAlgorithms.Count);
        AssertEx.Equal(0, nullLists.AdminAllowedWindowsGroups.Count);
    }

    private static void ConfigurationRoundTrip()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("configuration.xml");
            var store = new ConfigurationStore(path);
            var configuration = TestFixtures.CreateConfiguration();
            configuration.Rfc3161Enabled = true;
            configuration.AuthenticodeEnabled = true;
            configuration.AuthenticationMode = " Windows ";
            configuration.CertificateStoreLocation = " CurrentUser ";
            configuration.CertificateStoreName = " My ";
            configuration.CertificateThumbprint = "aa bb\u200ecc";
            configuration.AllowedHashAlgorithms = ["sha-256", " SHA384 ", "SHA-256"];
            configuration.AcceptedPolicyOids =
            [
                " " + TestFixtures.DefaultPolicyOid + " ",
                    TestFixtures.AlternatePolicyOid,
                    TestFixtures.AlternatePolicyOid
            ];
            configuration.SigningDigestAlgorithm = "sha-512";
            configuration.IncludeCertificateChain = true;
            configuration.AccuracySeconds = 10;
            configuration.AccuracyMilliseconds = 250;
            configuration.Ordering = true;
            configuration.MaxRequestBytes = 131072;
            configuration.LogRetentionDays = 365;
            configuration.LogRolloverInterval = " Weekly ";
            configuration.PruneAuditLogs = false;
            configuration.AdminAllowedWindowsGroups = [" BUILTIN\\Administrators ", "BUILTIN\\Administrators"];
            configuration.FailClosedOnAuditError = false;
            configuration.LogMessageImprints = false;
            configuration.ClockRollbackToleranceSeconds = 10;
            configuration.AllowUntrustedDevelopmentCertificate = true;
            configuration.CertificateSelectionMode = " Automatic ";

            store.Save(configuration);
            AssertEx.True(File.Exists(path));
            AssertEx.True(File.Exists(path + ".lock"));
            var loaded = new ConfigurationStore(path).Load();
            AssertEx.Equal(1, loaded.SchemaVersion);
            AssertEx.True(loaded.Rfc3161Enabled);
            AssertEx.True(loaded.AuthenticodeEnabled);
            AssertEx.Equal("Windows", loaded.AuthenticationMode);
            AssertEx.Equal("CurrentUser", loaded.CertificateStoreLocation);
            AssertEx.Equal("My", loaded.CertificateStoreName);
            AssertEx.Equal("AABBCC", loaded.CertificateThumbprint);
            AssertEx.Equal(TestFixtures.DefaultPolicyOid, loaded.DefaultPolicyOid);
            AssertEx.Equal(2, loaded.AcceptedPolicyOids.Count);
            AssertEx.Equal(TestFixtures.AlternatePolicyOid, loaded.AcceptedPolicyOids[1]);
            AssertEx.Equal(2, loaded.AllowedHashAlgorithms.Count);
            AssertEx.Equal("SHA256", loaded.AllowedHashAlgorithms[0]);
            AssertEx.Equal("SHA384", loaded.AllowedHashAlgorithms[1]);
            AssertEx.Equal("SHA512", loaded.SigningDigestAlgorithm);
            AssertEx.True(loaded.IncludeCertificateChain);
            AssertEx.Equal(10, loaded.AccuracySeconds);
            AssertEx.Equal(250, loaded.AccuracyMilliseconds);
            AssertEx.True(loaded.Ordering);
            AssertEx.Equal(131072, loaded.MaxRequestBytes);
            AssertEx.Equal(365, loaded.LogRetentionDays);
            AssertEx.Equal(ServiceConfiguration.WeeklyLogRollover, loaded.LogRolloverInterval);
            AssertEx.False(loaded.PruneAuditLogs);
            AssertEx.Equal(1, loaded.AdminAllowedWindowsGroups.Count);
            AssertEx.False(loaded.FailClosedOnAuditError);
            AssertEx.False(loaded.LogMessageImprints);
            AssertEx.Equal(10, loaded.ClockRollbackToleranceSeconds);
            AssertEx.True(loaded.AllowUntrustedDevelopmentCertificate);
            AssertEx.Equal(ServiceConfiguration.AutomaticCertificateSelection, loaded.CertificateSelectionMode);

            loaded.AllowedHashAlgorithms.Add("SHA1");
            AssertEx.Equal(2, store.Load().AllowedHashAlgorithms.Count, "Load must return an isolated clone.");

            loaded.AllowedHashAlgorithms.Remove("SHA1");
            loaded.LogRetentionDays = 366;
            store.Save(loaded);
            AssertEx.True(File.Exists(path + ".bak"), "Updating a configuration should retain the prior version as a backup.");
            AssertEx.Equal(366, store.Load().LogRetentionDays);
        }
    }

    private static void ConfigurationCompareAndSwap()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("configuration.xml");
            var store = new ConfigurationStore(path);
            var first = store.Load(out var initialGeneration);
            first.LogRetentionDays = 91;

            var savedGeneration = store.Save(first, initialGeneration);
            AssertEx.NotEqual(initialGeneration, savedGeneration);
            AssertEx.Equal(savedGeneration, new ConfigurationStore(path).GetGeneration(),
                "A successful save must return the generation that is already active on disk.");

            var stale = first.Clone();
            stale.LogRetentionDays = 92;
            AssertEx.Throws<ConfigurationConflictException>(() => store.Save(stale, initialGeneration));
            AssertEx.Equal(91, new ConfigurationStore(path).Load().LogRetentionDays,
                "A stale administrative writer must not replace the committed configuration.");
        }
    }

    private static void ConcurrentConfigurationCompareAndSwap()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("configuration.xml");
            var seedStore = new ConfigurationStore(path);
            seedStore.Save(new ServiceConfiguration());
            var baseline = seedStore.Load(out var generation);

            var first = baseline.Clone();
            first.LogRetentionDays = 101;
            var second = baseline.Clone();
            second.LogRetentionDays = 102;
            ConcurrentBag<string> outcomes = new();

            Parallel.Invoke(
                () => SaveWithOutcome(new ConfigurationStore(path), first, generation, outcomes),
                () => SaveWithOutcome(new ConfigurationStore(path), second, generation, outcomes));

            AssertEx.Equal(1, outcomes.Count(item => item == "saved"));
            AssertEx.Equal(1, outcomes.Count(item => item == "conflict"));
            AssertEx.True(new[] { 101, 102 }.Contains(new ConfigurationStore(path).Load().LogRetentionDays));
            AssertEx.Equal(0, Directory.GetFiles(directory.Path, "*.new").Length,
                "Successful or conflicting writers must not leave shared staging files behind.");
        }
    }

    private static void SaveWithOutcome(
        ConfigurationStore store,
        ServiceConfiguration configuration,
        string generation,
        ConcurrentBag<string> outcomes)
    {
        try
        {
            store.Save(configuration, generation);
            outcomes.Add("saved");
        }
        catch (ConfigurationConflictException)
        {
            outcomes.Add("conflict");
        }
    }

    private static void ConfigurationFilesystemLock()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("configuration.xml");
            var store = new ConfigurationStore(path);
            store.Save(new ServiceConfiguration());
            Task<string> waiting;
            using var started = new ManualResetEventSlim();
            using (new FileStream(path + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                waiting = Task.Run(() =>
                {
                    started.Set();
                    return store.GetGeneration();
                });
                AssertEx.True(started.Wait(1000), "The configuration lock contender did not start.");
                AssertEx.False(waiting.Wait(100),
                    "A handle outside ConfigurationStore must participate in the same filesystem lock.");
            }

            AssertEx.True(
                waiting.Wait(2000),
                "Configuration access did not resume after the filesystem lock was released.");
            AssertEx.Equal(store.GetGeneration(), waiting.Result);
        }
    }

    private static void NullConfigurationRootRejected()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("configuration.xml");
            File.WriteAllText(
                path,
                "<OpenTimeStampConfiguration xmlns=\"urn:opentimestamp:configuration:v1\" " +
                "xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" i:nil=\"true\" />",
                Encoding.UTF8);

            var exception = AssertEx.Throws<ConfigurationErrorsException>(() => new ConfigurationStore(path).Load());
            AssertEx.Contains("empty or does not contain valid settings", exception.Message);
        }
    }

    private static void ConfigurationLoadDetectsSameMetadataReplacement()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("configuration.xml");
            var firstStore = new ConfigurationStore(path);
            var initial = new ServiceConfiguration { LogRetentionDays = 101 };
            firstStore.Save(initial);
            var firstSnapshot = firstStore.Load(out var firstGeneration);
            var originalLength = new FileInfo(path).Length;
            var originalWriteTime = File.GetLastWriteTimeUtc(path);

            var secondStore = new ConfigurationStore(path);
            var replacement = secondStore.Load(out var expectedGeneration);
            replacement.LogRetentionDays = 102;
            secondStore.Save(replacement, expectedGeneration);
            AssertEx.Equal(originalLength, new FileInfo(path).Length,
                "The regression requires a replacement with the same file length.");

            // Reproduce filesystems or copy tools that preserve timestamps across an
            // atomic same-size replacement. Metadata-only caches miss this change.
            File.SetLastWriteTimeUtc(path, originalWriteTime);
            AssertEx.Equal(originalWriteTime, File.GetLastWriteTimeUtc(path));

            var reloaded = firstStore.Load(out var replacementGeneration);
            AssertEx.Equal(101, firstSnapshot.LogRetentionDays);
            AssertEx.Equal(102, reloaded.LogRetentionDays);
            AssertEx.NotEqual(firstGeneration, replacementGeneration);
        }
    }

    private static void AuditProbeUsesActiveLog()
    {
        using (var directory = new TemporaryDirectory())
        {
            var logDirectory = directory.File("Logs");
            var logger = new AuditLogger(logDirectory);
            logger.ProbeWritable();
            var activeLog = Directory.GetFiles(logDirectory, "timestamp-*.jsonl").Single();
            AssertEx.True(File.Exists(Path.Combine(logDirectory, ".audit.lock")));
            AssertEx.Equal(0L, new FileInfo(activeLog).Length,
                "A health probe must not fabricate an audit record.");

            using (new FileStream(activeLog, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                AssertEx.Throws<AuditLogException>(() => logger.ProbeWritable(),
                    "The probe must fail when the real daily append target cannot be opened for writing.");
            }

            logger.ProbeWritable();
        }
    }

    private static void AuditFilesystemLock()
    {
        using (var directory = new TemporaryDirectory())
        {
            var logDirectory = directory.File("Logs");
            var logger = new AuditLogger(logDirectory);
            logger.ProbeWritable();
            AssertExclusiveHandleBlocks(
                Path.Combine(logDirectory, ".audit.lock"),
                logger.ProbeWritable,
                "An external handle must participate in the audit filesystem lock.",
                "Audit access did not resume after the filesystem lock was released.");
        }
    }

    private static void AssertExclusiveHandleBlocks(
        string lockPath,
        Action contender,
        string didNotBlockMessage,
        string didNotResumeMessage)
    {
        Task waiting = null;
        using var started = new ManualResetEventSlim();
        try
        {
            using (new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                waiting = Task.Run(() =>
                {
                    started.Set();
                    contender();
                });
                AssertEx.True(started.Wait(2000), "The filesystem lock contender did not start.");
                AssertEx.False(waiting.Wait(150), didNotBlockMessage);
            }

            AssertEx.True(SpinWait.SpinUntil(() => waiting.IsCompleted, 5000), didNotResumeMessage);
            waiting.GetAwaiter().GetResult();
        }
        finally
        {
            if (waiting is not null && !waiting.IsCompleted)
            {
                try
                {
                    waiting.Wait(6000);
                }
                catch (AggregateException)
                {
                    // The normal assertion path observes contender failures above. This
                    // bounded wait only prevents a failed assertion from leaking a task.
                }
            }
        }
    }

    private static void AuditRetentionRetryIsBounded()
    {
        using (var directory = new TemporaryDirectory())
        {
            var logDirectory = directory.File("Logs");
            Directory.CreateDirectory(logDirectory);
            var today = DateTime.UtcNow.Date;
            var blocked = Path.Combine(
                logDirectory,
                "timestamp-" + today.AddDays(-3).ToString("yyyyMMdd") + ".jsonl");
            var removable = Path.Combine(
                logDirectory,
                "timestamp-" + today.AddDays(-2).ToString("yyyyMMdd") + ".jsonl");
            File.WriteAllText(blocked, "{}" + Environment.NewLine, new UTF8Encoding(false));
            File.WriteAllText(removable, "{}" + Environment.NewLine, new UTF8Encoding(false));
            File.SetAttributes(blocked, File.GetAttributes(blocked) | FileAttributes.ReadOnly);
            var logger = new AuditLogger(logDirectory, TimeSpan.FromSeconds(2));
            var record = new AuditRecord
            {
                TimestampUtc = today.AddHours(12),
                EventType = "retention-test",
                Result = "granted"
            };

            try
            {
                logger.Write(record, 1, true);
                AssertEx.True(File.Exists(blocked));
                AssertEx.False(File.Exists(removable),
                    "One inaccessible expired log must not stop cleanup of other expired logs.");

                File.SetAttributes(blocked, File.GetAttributes(blocked) & ~FileAttributes.ReadOnly);
                logger.Write(record, 1, true);
                AssertEx.True(File.Exists(blocked),
                    "A failed retention pass must not be retried on every audit write.");

                Thread.Sleep(2100);
                logger.Write(record, 1, true);
                AssertEx.False(File.Exists(blocked),
                    "A failed retention pass must be retried after the bounded delay.");
            }
            finally
            {
                if (File.Exists(blocked))
                {
                    File.SetAttributes(blocked, File.GetAttributes(blocked) & ~FileAttributes.ReadOnly);
                }
            }
        }
    }

    private static void AuditRolloverAndPruning()
    {
        using (var directory = new TemporaryDirectory())
        {
            var logDirectory = directory.File("Logs");
            Directory.CreateDirectory(logDirectory);
            var now = new DateTime(2026, 7, 18, 14, 30, 0, DateTimeKind.Utc);
            var expiredDaily = Path.Combine(logDirectory, "timestamp-20260716.jsonl");
            var expiredHourly = Path.Combine(logDirectory, "timestamp-20260717-13.jsonl");
            var expiredWeekly = Path.Combine(logDirectory, "timestamp-week-20260629.jsonl");
            var expiresNextHour = Path.Combine(logDirectory, "timestamp-20260717-14.jsonl");
            File.WriteAllText(expiredDaily, "{}" + Environment.NewLine, new UTF8Encoding(false));
            File.WriteAllText(expiredHourly, "{}" + Environment.NewLine, new UTF8Encoding(false));
            File.WriteAllText(expiredWeekly, "{}" + Environment.NewLine, new UTF8Encoding(false));
            File.WriteAllText(expiresNextHour, "{}" + Environment.NewLine, new UTF8Encoding(false));
            var logger = new AuditLogger(logDirectory);
            var record = new AuditRecord
            {
                TimestampUtc = now,
                EventType = "rollover-test",
                Result = "granted"
            };

            logger.Write(record, ServiceConfiguration.HourlyLogRollover, false, 1, true);
            AssertEx.True(File.Exists(Path.Combine(logDirectory, "timestamp-20260718-14.jsonl")));
            AssertEx.True(File.Exists(expiredDaily));
            AssertEx.True(File.Exists(expiredHourly));

            record.TimestampUtc = now.AddMinutes(1);
            logger.Write(record, ServiceConfiguration.HourlyLogRollover, true, 1, true);
            AssertEx.False(File.Exists(expiredDaily));
            AssertEx.False(File.Exists(expiredHourly));
            AssertEx.False(File.Exists(expiredWeekly));
            AssertEx.True(File.Exists(expiresNextHour));

            var cleanupAfterPruningToggle = Path.Combine(logDirectory, "timestamp-20260715-11.jsonl");
            File.WriteAllText(cleanupAfterPruningToggle, "{}" + Environment.NewLine, new UTF8Encoding(false));
            record.TimestampUtc = now.AddMinutes(2);
            logger.Write(record, ServiceConfiguration.HourlyLogRollover, false, 1, true);
            AssertEx.True(File.Exists(cleanupAfterPruningToggle));
            logger.Write(record, ServiceConfiguration.HourlyLogRollover, true, 1, true);
            AssertEx.False(File.Exists(cleanupAfterPruningToggle),
                "Re-enabling pruning must trigger cleanup in the same UTC hour.");

            record.TimestampUtc = now.AddHours(1);
            logger.Write(record, ServiceConfiguration.HourlyLogRollover, true, 1, true);
            AssertEx.False(File.Exists(expiresNextHour),
                "Hourly rollover must allow cleanup when the next UTC hour begins.");

            var cleanupAfterRetentionChange = Path.Combine(logDirectory, "timestamp-20260715.jsonl");
            File.WriteAllText(cleanupAfterRetentionChange, "{}" + Environment.NewLine, new UTF8Encoding(false));
            record.TimestampUtc = now.AddHours(1).AddMinutes(2);
            logger.Write(record, ServiceConfiguration.HourlyLogRollover, true, 1, true);
            AssertEx.True(File.Exists(cleanupAfterRetentionChange),
                "Repeated writes in one UTC hour must not repeat successful cleanup.");
            logger.Write(record, ServiceConfiguration.HourlyLogRollover, true, 2, true);
            AssertEx.False(File.Exists(cleanupAfterRetentionChange),
                "Changing retention must trigger cleanup in the same UTC hour.");

            var cleanupAfterRolloverChange = Path.Combine(logDirectory, "timestamp-20260715-12.jsonl");
            File.WriteAllText(cleanupAfterRolloverChange, "{}" + Environment.NewLine, new UTF8Encoding(false));
            logger.Write(record, ServiceConfiguration.DailyLogRollover, true, 2, true);
            AssertEx.False(File.Exists(cleanupAfterRolloverChange),
                "Changing rollover must trigger cleanup in the same UTC hour.");

            logger.Write(record, ServiceConfiguration.WeeklyLogRollover, false, 2, true);
            AssertEx.True(File.Exists(Path.Combine(logDirectory, "timestamp-week-20260713.jsonl")),
                "Weekly rollover must use the Monday UTC week boundary.");
        }
    }
}
