using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Issuance;

namespace OpenTimeStamp.Tests;

[TestClass]
public sealed class PersistenceAndConfigurationTests
{
    [TestMethod(DisplayName = "Issuance first allocation accepts rollback tolerance")]
    public void FirstAllocationWithTolerance()
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

    [TestMethod(DisplayName = "Issuance serials are random and independent of stored state")]
    public void RandomSerialAllocation()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var now = new DateTime(2026, 7, 16, 18, 0, 0, DateTimeKind.Utc);
            var first = TestFixtures.CreateInitializedStateStore(path).Allocate(now, TimeSpan.Zero, false);
            AssertEx.True(File.Exists(path));
            AssertEx.True(File.Exists(path + ".lock"));
            var snapshot = File.ReadAllBytes(path);
            var second = new IssuanceStateStore(path).Allocate(now, TimeSpan.Zero, false);
            AssertEx.Equal(first.GenerationTimeUtc, second.GenerationTimeUtc);

            // The issuance time is durable across store instances.
            var third = new IssuanceStateStore(path).Allocate(now.AddSeconds(1), TimeSpan.Zero, false);
            AssertEx.Equal(now.AddSeconds(1), third.GenerationTimeUtc);
            AssertEx.Throws<ClockRollbackException>(() =>
                new IssuanceStateStore(path).Allocate(now, TimeSpan.Zero, false));

            // Restoring an older copy of the state, as a backup restore or a cloned data
            // directory would, must not make the service repeat a serial number.
            File.WriteAllBytes(path, snapshot);
            File.Delete(path + ".bak");
            var afterRestore = new IssuanceStateStore(path).Allocate(now, TimeSpan.Zero, false);

            var serials = new[] { first, second, third, afterRestore }.Select(item => item.SerialNumber).ToList();
            foreach (var serial in serials)
            {
                AssertEx.Equal(16, serial.Length);
                AssertEx.Equal(0, serial[0] & 0x80, "Serial numbers must be positive integers.");
                AssertEx.True(serial.Any(value => value != 0));
            }

            AssertEx.Equal(serials.Count, serials.Select(TestFixtures.Hex).Distinct(StringComparer.Ordinal).Count());
        }
    }

    [TestMethod(DisplayName = "Issuance ordering and rollback protection")]
    public void OrderingAndClockRollback()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var store = TestFixtures.CreateInitializedStateStore(path);
            var now = new DateTime(2026, 7, 16, 19, 0, 0, DateTimeKind.Utc);
            var first = store.Allocate(now, TimeSpan.Zero, true);
            var ordered = store.Allocate(now.AddMilliseconds(-500), TimeSpan.FromSeconds(1), true);
            AssertEx.Equal(first.GenerationTimeUtc.AddTicks(1), ordered.GenerationTimeUtc);

            AssertEx.Throws<ClockRollbackException>(() =>
                store.Allocate(now.AddSeconds(-5), TimeSpan.FromSeconds(1), true));
            store.Validate(ordered.GenerationTimeUtc.AddSeconds(-1), TimeSpan.FromSeconds(1));
            AssertEx.Throws<ClockRollbackException>(() =>
                store.Validate(ordered.GenerationTimeUtc.AddSeconds(-2), TimeSpan.FromSeconds(1)));

            var nextOrderedTime = store.ValidateAndGetNextGenerationTime(
                () => ordered.GenerationTimeUtc,
                TimeSpan.Zero,
                true);
            AssertEx.Equal(ordered.GenerationTimeUtc.AddTicks(1), nextOrderedTime,
                "Strict ordering must preview the same one-tick advance used by allocation.");
            AssertEx.Equal(
                ordered.GenerationTimeUtc,
                store.ValidateAndGetNextGenerationTime(() => ordered.GenerationTimeUtc, TimeSpan.Zero, false));

            var afterFailure = new IssuanceStateStore(path).Allocate(ordered.GenerationTimeUtc, TimeSpan.Zero, true);
            AssertEx.Equal(nextOrderedTime, afterFailure.GenerationTimeUtc,
                "A rejected rollback and a preview must not move the issuance clock.");
        }
    }

    [TestMethod(DisplayName = "Issuance allocation is concurrency-safe")]
    public void ConcurrentAllocation()
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

    [TestMethod(DisplayName = "Issuance and health sample the clock after the filesystem lock")]
    [DataRow(false)]
    [DataRow(true)]
    public void StateAccessSamplesClockAfterLock(bool healthCheck)
    {
        using var directory = new TemporaryDirectory();
        var path = directory.File("issuance-clock.bin");
        var store = TestFixtures.CreateInitializedStateStore(path);
        var now = new DateTime(2026, 7, 16, 20, 0, 0, DateTimeKind.Utc);
        store.Allocate(now.AddSeconds(3), TimeSpan.Zero, false);
        var currentTicks = now.Ticks;
        var clockSamples = 0;
        Func<DateTime> clock = () =>
        {
            Interlocked.Increment(ref clockSamples);
            return new DateTime(Interlocked.Read(ref currentTicks), DateTimeKind.Utc);
        };
        Func<DateTime> operation = healthCheck
            ? () => store.ValidateAndGetNextGenerationTime(clock, TimeSpan.FromSeconds(2), false)
            : () => store.Allocate(clock, TimeSpan.FromSeconds(2), false, CancellationToken.None).GenerationTimeUtc;
        using var started = new ManualResetEventSlim();
        Task<DateTime> waiting = null;
        try
        {
            using (new FileStream(path + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                waiting = Task.Run(() =>
                {
                    started.Set();
                    return operation();
                });
                AssertEx.True(started.Wait(2000), "The issuance contender did not start.");
                AssertEx.False(waiting.Wait(150), "Issuance unexpectedly bypassed the external lock.");
                AssertEx.Equal(0, Volatile.Read(ref clockSamples), "The clock was sampled before acquiring the lock.");
                Interlocked.Exchange(ref currentTicks, now.AddSeconds(4).Ticks);
            }

            AssertEx.True(SpinWait.SpinUntil(() => waiting.IsCompleted, 5000), "Issuance did not resume.");
            AssertEx.Equal(now.AddSeconds(4), waiting.GetAwaiter().GetResult());
            Interlocked.Exchange(ref currentTicks, now.Ticks);
            AssertEx.Throws<ClockRollbackException>(() => operation());
        }
        finally
        {
            if (waiting is not null && !waiting.IsCompleted)
            {
                try { waiting.Wait(6000); }
                catch (AggregateException) { }
            }
        }
    }

    [TestMethod(DisplayName = "Issuance filesystem lock coordinates external handles")]
    public void IssuanceFilesystemLock()
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

    [TestMethod(DisplayName = "Issuance cancellation stops lock waits without allocation")]
    public void IssuanceCancellation()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance-cancellation.bin");
            var store = TestFixtures.CreateInitializedStateStore(path);
            store.Allocate(new DateTime(2026, 7, 16, 19, 59, 0, DateTimeKind.Utc), TimeSpan.Zero, false);
            store.Allocate(new DateTime(2026, 7, 16, 19, 59, 30, DateTimeKind.Utc), TimeSpan.Zero, false);
            var artifactPaths = new[] { path, path + ".bak" };
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

    [TestMethod(DisplayName = "Issuance state recovers from its newest valid copy")]
    public void StateRecoversFromNewestValidCopy()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var earlier = new DateTime(2026, 7, 16, 20, 30, 0, DateTimeKind.Utc);
            var later = earlier.AddMinutes(5);
            var store = TestFixtures.CreateInitializedStateStore(path);
            store.Allocate(earlier, TimeSpan.Zero, false);
            var earlierRecord = File.ReadAllBytes(path);
            store.Allocate(later, TimeSpan.Zero, false);
            var laterRecord = File.ReadAllBytes(path);
            AssertEx.SequenceEqual(earlierRecord, File.ReadAllBytes(path + ".bak"),
                "The replaced record must become the backup.");

            // A crash after flushing the staged record but before publishing it leaves the newer
            // mark only in the staging file. It must win over the older published record.
            File.WriteAllBytes(path, earlierRecord);
            File.WriteAllBytes(path + ".new", laterRecord);
            AssertEx.Throws<ClockRollbackException>(() => store.Validate(later.AddSeconds(-1), TimeSpan.Zero));
            AssertEx.Equal(later.AddTicks(1), store.Allocate(later, TimeSpan.Zero, true).GenerationTimeUtc);

            // A truncated staging file and a corrupted published record are both ignored in
            // favor of the backup, which still holds the previous mark.
            var newest = later.AddTicks(1);
            store.Allocate(newest.AddSeconds(1), TimeSpan.Zero, false);
            var corrupted = File.ReadAllBytes(path);
            corrupted[6] ^= 0x01;
            File.WriteAllBytes(path, corrupted);
            File.WriteAllBytes(path + ".new", new byte[] { 0x4f, 0x54, 0x53 });
            AssertEx.Throws<ClockRollbackException>(() => store.Validate(newest.AddSeconds(-1), TimeSpan.Zero));
            AssertEx.Equal(newest.AddSeconds(2), store.Allocate(newest.AddSeconds(2), TimeSpan.Zero, false).GenerationTimeUtc);

            // The published record alone is sufficient.
            File.Delete(path + ".bak");
            File.Delete(path + ".new");
            store.Validate();

            // So is the backup alone.
            store.Allocate(newest.AddSeconds(3), TimeSpan.Zero, false);
            File.Delete(path);
            AssertEx.Equal(newest.AddSeconds(2).AddTicks(1),
                store.Allocate(newest.AddSeconds(2), TimeSpan.Zero, true).GenerationTimeUtc);
        }
    }

    [TestMethod(DisplayName = "Issuance missing or unrecognized state fails closed")]
    public void MissingOrUnrecognizedStateFailsClosed()
    {
        using (var directory = new TemporaryDirectory())
        {
            var now = new DateTime(2026, 7, 16, 20, 45, 0, DateTimeKind.Utc);

            // Issuance never creates state, so losing every copy stops issuance until an
            // operator explicitly reinitializes or restores it.
            var lostPath = directory.File("lost.bin");
            var lost = TestFixtures.CreateInitializedStateStore(lostPath);
            lost.Allocate(now, TimeSpan.Zero, false);
            lost.Allocate(now.AddSeconds(1), TimeSpan.Zero, false);
            File.Delete(lostPath);
            File.Delete(lostPath + ".bak");
            AssertEx.Throws<IssuanceStateException>(() => lost.Validate());
            AssertEx.Throws<IssuanceStateException>(() => lost.Allocate(now.AddSeconds(2), TimeSpan.Zero, false));
            lost.Initialize();
            lost.Allocate(now.AddSeconds(2), TimeSpan.Zero, false);

            // Repeated initialization never resets an existing clock.
            lost.Initialize();
            AssertEx.Throws<ClockRollbackException>(() => lost.Allocate(now, TimeSpan.Zero, false));

            // Files that are neither current nor a recognized earlier format block an automatic
            // reset: they may be damaged state that still needs to be restored.
            var unknownPath = directory.File("unknown.bin");
            File.WriteAllBytes(unknownPath, new byte[] { 0x4f, 0x54, 0x53, 0x39, 0x00 });
            var unknown = new IssuanceStateStore(unknownPath);
            AssertEx.Throws<IssuanceStateException>(() => unknown.Initialize());
            AssertEx.Throws<IssuanceStateException>(() => unknown.Allocate(now, TimeSpan.Zero, false));

            var tamperedPath = directory.File("tampered.bin");
            var tampered = TestFixtures.CreateInitializedStateStore(tamperedPath);
            tampered.Allocate(now, TimeSpan.Zero, false);
            tampered.Allocate(now.AddSeconds(1), TimeSpan.Zero, false);
            foreach (var copy in new[] { tamperedPath, tamperedPath + ".bak" })
            {
                var record = File.ReadAllBytes(copy);
                record[record.Length - 1] ^= 0x80;
                File.WriteAllBytes(copy, record);
            }

            AssertEx.Throws<IssuanceStateException>(() => tampered.Validate());
            AssertEx.Throws<IssuanceStateException>(() => tampered.Initialize());
        }
    }

    [TestMethod(DisplayName = "Issuance legacy OTS1 state migrates without resetting its clock")]
    public void LegacyOts1StateMigration()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = directory.File("issuance.bin");
            var issuedAt = new DateTime(2026, 7, 16, 20, 50, 0, DateTimeKind.Utc);
            using (FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (BinaryWriter writer = new(stream, Encoding.UTF8, false))
            {
                writer.Write(Encoding.ASCII.GetBytes("OTS1"));
                writer.Write(Enumerable.Range(1, 16).Select(value => (byte)value).ToArray());
                writer.Write(issuedAt.Ticks);
            }

            // A migration to the intermediate format may have been interrupted while staging.
            File.WriteAllBytes(path + ".meta.new", new byte[] { 0x4f, 0x54, 0x53 });

            var store = new IssuanceStateStore(path);
            AssertEx.Throws<IssuanceStateException>(
                () => store.Allocate(issuedAt, TimeSpan.Zero, true),
                "Issuance must not use or migrate earlier state implicitly.");
            store.Initialize();
            AssertEx.Equal("OTS3", Encoding.ASCII.GetString(File.ReadAllBytes(path), 0, 4));
            AssertEx.False(File.Exists(path + ".meta.new"));
            AssertEx.Throws<ClockRollbackException>(() => store.Validate(issuedAt.AddSeconds(-1), TimeSpan.Zero));
            AssertEx.Equal(issuedAt.AddTicks(1), store.Allocate(issuedAt, TimeSpan.Zero, true).GenerationTimeUtc);
        }
    }

    [TestMethod(DisplayName = "Issuance legacy OTS2 state migrates only when authentic")]
    public void LegacyOts2StateMigration()
    {
        using (var directory = new TemporaryDirectory())
        {
            var issuedAt = new DateTime(2026, 7, 16, 20, 55, 0, DateTimeKind.Utc);

            // A complete store: both state copies and both markers, as steady-state OTS2 left them.
            var path = directory.File("issuance.bin");
            WriteLegacyOts2Store(path, issuedAt, issuedAt);
            var store = new IssuanceStateStore(path);
            AssertEx.Throws<IssuanceStateException>(() => store.Allocate(issuedAt.AddSeconds(1), TimeSpan.Zero, false));
            store.Initialize();
            AssertEx.Equal("OTS3", Encoding.ASCII.GetString(File.ReadAllBytes(path), 0, 4));
            foreach (var suffix in new[] { ".bak", ".meta", ".meta.bak" })
            {
                AssertEx.False(File.Exists(path + suffix), suffix + " from the earlier format was left behind.");
            }

            AssertEx.Throws<ClockRollbackException>(() => store.Validate(issuedAt.AddSeconds(-1), TimeSpan.Zero));
            AssertEx.Equal(issuedAt.AddTicks(1), store.Allocate(issuedAt, TimeSpan.Zero, true).GenerationTimeUtc);

            // An interrupted commit left the newer generation only in the active copy.
            var aheadPath = directory.File("ahead.bin");
            WriteLegacyOts2Store(aheadPath, issuedAt.AddSeconds(30), issuedAt);
            var ahead = new IssuanceStateStore(aheadPath);
            ahead.Initialize();
            AssertEx.Throws<ClockRollbackException>(() => ahead.Validate(issuedAt.AddSeconds(29), TimeSpan.Zero));

            // A damaged active copy is ignored in favor of its authentic mirror.
            var damagedPath = directory.File("damaged.bin");
            WriteLegacyOts2Store(damagedPath, issuedAt, issuedAt);
            var damaged = File.ReadAllBytes(damagedPath);
            damaged[44] ^= 0x01;
            File.WriteAllBytes(damagedPath, damaged);
            new IssuanceStateStore(damagedPath).Initialize();
            AssertEx.Equal("OTS3", Encoding.ASCII.GetString(File.ReadAllBytes(damagedPath), 0, 4));

            // State that no surviving marker authenticates must not seed the new clock.
            var forgedPath = directory.File("forged.bin");
            WriteLegacyOts2Store(forgedPath, issuedAt, issuedAt);
            foreach (var copy in new[] { forgedPath, forgedPath + ".bak" })
            {
                var forged = File.ReadAllBytes(copy);
                forged[44] ^= 0x01;
                File.WriteAllBytes(copy, forged);
            }

            AssertEx.Throws<IssuanceStateException>(() => new IssuanceStateStore(forgedPath).Initialize());
            AssertEx.Equal("OTS2", Encoding.ASCII.GetString(File.ReadAllBytes(forgedPath), 0, 4),
                "A failed migration must leave the earlier state untouched.");

            var keylessPath = directory.File("keyless.bin");
            WriteLegacyOts2Store(keylessPath, issuedAt, issuedAt);
            File.Delete(keylessPath + ".meta");
            File.Delete(keylessPath + ".meta.bak");
            AssertEx.Throws<IssuanceStateException>(() => new IssuanceStateStore(keylessPath).Initialize());
        }
    }

    // Lays out the files an OTS2 store kept: an HMAC-authenticated state record with its mirror,
    // and the key-bearing marker with its distinct mirror header.
    private static void WriteLegacyOts2Store(string path, DateTime activeLastIssuedUtc, DateTime mirrorLastIssuedUtc)
    {
        var stateIdentifier = Enumerable.Range(1, 16).Select(value => (byte)value).ToArray();
        var integrityKey = Enumerable.Range(101, 32).Select(value => (byte)value).ToArray();
        var serial = Enumerable.Range(201, 16).Select(value => (byte)value).ToArray();

        byte[] State(DateTime lastIssuedUtc)
        {
            using MemoryStream stream = new();
            using (BinaryWriter writer = new(stream, Encoding.UTF8, true))
            {
                writer.Write(Encoding.ASCII.GetBytes("OTS2"));
                writer.Write(stateIdentifier);
                writer.Write(7UL);
                writer.Write(serial);
                writer.Write(lastIssuedUtc.Ticks);
            }

            var payload = stream.ToArray();
            using HMACSHA256 hmac = new(integrityKey);
            return payload.Concat(hmac.ComputeHash(payload)).ToArray();
        }

        byte[] Marker(string magic)
        {
            using MemoryStream stream = new();
            using (BinaryWriter writer = new(stream, Encoding.UTF8, true))
            {
                writer.Write(Encoding.ASCII.GetBytes(magic));
                writer.Write(stateIdentifier);
                writer.Write(integrityKey);
                writer.Write(7UL);
                writer.Write(serial);
            }

            var payload = stream.ToArray();
            using SHA256 sha256 = SHA256.Create();
            return payload.Concat(sha256.ComputeHash(payload)).ToArray();
        }

        File.WriteAllBytes(path, State(activeLastIssuedUtc));
        File.WriteAllBytes(path + ".bak", State(mirrorLastIssuedUtc));
        File.WriteAllBytes(path + ".meta", Marker("OTSM"));
        File.WriteAllBytes(path + ".meta.bak", Marker("OTSB"));
    }

    [TestMethod(DisplayName = "Issuance health validation requires write access")]
    public void HealthValidationRequiresWriteAccess()
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

    [TestMethod(DisplayName = "Configuration defaults fail safe until provisioned")]
    public void ConfigurationDefaultsFailSafe()
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

    [TestMethod(DisplayName = "Configuration clone copies values and isolates lists")]
    public void ConfigurationCloneIsIndependent()
    {
        var source = new ServiceConfiguration
        {
            SchemaVersion = 7,
            Rfc3161Enabled = true,
            AuthenticodeEnabled = true,
            AuthenticationMode = "Windows",
            CertificateStoreLocation = "CurrentUser",
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

    [TestMethod(DisplayName = "Configuration XML round-trip and normalization")]
    public void ConfigurationRoundTrip()
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
            configuration.WriteWindowsEventLog = true;
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
            AssertEx.True(loaded.WriteWindowsEventLog);
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

    [TestMethod(DisplayName = "Configuration compare-and-swap rejects stale writers")]
    public void ConfigurationCompareAndSwap()
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

    [TestMethod(DisplayName = "Configuration concurrent writers have one CAS winner")]
    public void ConcurrentConfigurationCompareAndSwap()
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

    [TestMethod(DisplayName = "Configuration filesystem lock coordinates external handles")]
    public void ConfigurationFilesystemLock()
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

    [TestMethod(DisplayName = "Configuration elements absent from the file keep their defaults")]
    public void ConfigurationMissingElementsKeepDefaults()
    {
        using var directory = new TemporaryDirectory();
        var path = directory.File("tsa.config");
        var store = new ConfigurationStore(path);
        store.Save(new ServiceConfiguration());
        var complete = File.ReadAllText(path);
        var defaults = new ServiceConfiguration();

        string Without(string xml, params string[] elements)
        {
            foreach (var element in elements)
            {
                var stripped = Regex.Replace(
                    xml, @"\s*<" + element + @"\b.*?</" + element + ">", string.Empty, RegexOptions.Singleline);
                AssertEx.NotEqual(xml, stripped, element + " was not present in the saved settings file.");
                xml = stripped;
            }

            return xml;
        }

        ServiceConfiguration LoadEdited(string xml)
        {
            File.WriteAllText(path, xml, new UTF8Encoding(false));
            return store.Load();
        }

        // The serializer never runs the constructor, so every absent element must still fall
        // back to the constructor default rather than to false, zero, or an empty list.
        var loaded = LoadEdited(Without(
            complete,
            nameof(ServiceConfiguration.FailClosedOnAuditError),
            nameof(ServiceConfiguration.PruneAuditLogs),
            nameof(ServiceConfiguration.LogMessageImprints),
            nameof(ServiceConfiguration.IncludeCertificateChain),
            nameof(ServiceConfiguration.MaxRequestBytes),
            nameof(ServiceConfiguration.LogRetentionDays),
            nameof(ServiceConfiguration.ClockRollbackToleranceSeconds),
            nameof(ServiceConfiguration.SigningDigestAlgorithm),
            nameof(ServiceConfiguration.AllowedHashAlgorithms),
            nameof(ServiceConfiguration.AdminAllowedWindowsGroups)));
        AssertEx.True(loaded.FailClosedOnAuditError, "An absent fail-closed setting must not load as fail-open.");
        AssertEx.True(loaded.PruneAuditLogs);
        AssertEx.True(loaded.LogMessageImprints);
        AssertEx.True(loaded.IncludeCertificateChain);
        AssertEx.Equal(defaults.MaxRequestBytes, loaded.MaxRequestBytes);
        AssertEx.Equal(defaults.LogRetentionDays, loaded.LogRetentionDays);
        AssertEx.Equal(defaults.ClockRollbackToleranceSeconds, loaded.ClockRollbackToleranceSeconds);
        AssertEx.Equal(defaults.SigningDigestAlgorithm, loaded.SigningDigestAlgorithm);
        AssertEx.True(defaults.AllowedHashAlgorithms.SequenceEqual(loaded.AllowedHashAlgorithms));
        AssertEx.True(defaults.AdminAllowedWindowsGroups.SequenceEqual(loaded.AdminAllowedWindowsGroups));

        // The serializer skips an element that appears after a later-ordered one, or a second
        // time. Such a file is refused, because the edit it contains would otherwise be ignored.
        var failClosed = "<FailClosedOnAuditError>true</FailClosedOnAuditError>";
        var imprints = "<LogMessageImprints>true</LogMessageImprints>";
        AssertEx.True(complete.Contains(failClosed) && complete.Contains(imprints));
        var reordered = complete.Replace(failClosed, "<swap/>").Replace(imprints, failClosed).Replace("<swap/>", imprints);
        var misordered = AssertEx.Throws<ConfigurationErrorsException>(() => LoadEdited(reordered));
        AssertEx.Contains("FailClosedOnAuditError", misordered.Message);
        AssertEx.Throws<ConfigurationErrorsException>(() => LoadEdited(complete.Replace(
            failClosed, failClosed + "<FailClosedOnAuditError>false</FailClosedOnAuditError>")));

        // An element this release does not know, such as one written by another release, is skipped.
        loaded = LoadEdited(complete.Replace(
            "<CertificateThumbprint", "<CertificateStoreName>My</CertificateStoreName><CertificateThumbprint"));
        AssertEx.True(loaded.FailClosedOnAuditError);
        AssertEx.Equal(defaults.MaxRequestBytes, loaded.MaxRequestBytes);

        // Explicit values still win over the defaults.
        loaded = LoadEdited(complete.Replace(failClosed, "<FailClosedOnAuditError>false</FailClosedOnAuditError>"));
        AssertEx.False(loaded.FailClosedOnAuditError);

        // A file written before selection modes existed pinned one thumbprint, which is Manual.
        loaded = LoadEdited(Without(complete, nameof(ServiceConfiguration.CertificateSelectionMode)));
        AssertEx.Equal(ServiceConfiguration.ManualCertificateSelection, loaded.CertificateSelectionMode);

        // A settings file must declare its own schema version.
        var unversioned = Without(complete, nameof(ServiceConfiguration.SchemaVersion));
        AssertEx.Throws<ConfigurationErrorsException>(() => LoadEdited(unversioned));
    }

    [TestMethod(DisplayName = "Configuration null root is rejected safely")]
    public void NullConfigurationRootRejected()
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

    [TestMethod(DisplayName = "Configuration load detects same-metadata replacement")]
    public void ConfigurationLoadDetectsSameMetadataReplacement()
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

    [TestMethod(DisplayName = "Audit health probe exercises the active append target")]
    public void AuditProbeUsesActiveLog()
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

    [TestMethod(DisplayName = "Audit filesystem lock coordinates external handles")]
    public void AuditFilesystemLock()
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

    [TestMethod(DisplayName = "Audit retention continues and retries at a bounded cadence")]
    public void AuditRetentionRetryIsBounded()
    {
        using (var directory = new TemporaryDirectory())
        {
            var logDirectory = directory.File("Logs");
            Directory.CreateDirectory(logDirectory);
            var today = DateTime.UtcNow.Date;
            var blocked = Path.Combine(
                logDirectory,
                "timestamp-" + today.AddDays(-3).ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".jsonl");
            var removable = Path.Combine(
                logDirectory,
                "timestamp-" + today.AddDays(-2).ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".jsonl");
            File.WriteAllText(blocked, "{}" + Environment.NewLine, new UTF8Encoding(false));
            File.WriteAllText(removable, "{}" + Environment.NewLine, new UTF8Encoding(false));
            File.SetAttributes(blocked, File.GetAttributes(blocked) | FileAttributes.ReadOnly);
            List<AuditRecord> observed = [];
            var logger = new AuditLogger(logDirectory, TimeSpan.FromSeconds(2), observed.Add);
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
                AssertEx.Contains("could not be deleted", logger.RetentionWarning);
                AssertEx.Equal(1, observed.Count(item => item.EventType == "audit-retention-failure"));

                File.SetAttributes(blocked, File.GetAttributes(blocked) & ~FileAttributes.ReadOnly);
                logger.Write(record, 1, true);
                AssertEx.True(File.Exists(blocked),
                    "A failed retention pass must not be retried on every audit write.");
                AssertEx.Equal(1, observed.Count(item => item.EventType == "audit-retention-failure"));

                Thread.Sleep(2100);
                logger.Write(record, 1, true);
                AssertEx.False(File.Exists(blocked),
                    "A failed retention pass must be retried after the bounded delay.");
                AssertEx.True(logger.RetentionWarning == null, "Successful cleanup must clear its warning.");
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

    [TestMethod(DisplayName = "Audit rollover and pruning follow configuration")]
    public void AuditRolloverAndPruning()
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

    [TestMethod(DisplayName = "Audit observers cannot change durable commit outcomes")]
    public void AuditObserversAreNonBlocking()
    {
        using var directory = new TemporaryDirectory();
        var logDirectory = directory.File("Logs");
        var record = new AuditRecord { EventType = "timestamp", Result = "granted", CorrelationId = "durable" };
        var logger = new AuditLogger(logDirectory, _ => throw new InvalidOperationException("Observer unavailable."));
        AssertEx.True(logger.Write(record, 365, true));
        var active = Directory.GetFiles(logDirectory, "timestamp-*.jsonl").Single();
        AssertEx.Contains("durable", File.ReadAllText(active));
        AssertEx.Equal(1, File.ReadAllLines(active).Length);

        // A failed append emits a diagnostic with the original correlation, never a granted mirror.
        List<AuditRecord> observed = [];
        logger = new AuditLogger(logDirectory, observed.Add);
        using (new FileStream(active, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            AssertEx.Throws<AuditLogException>(() => logger.Write(record, 365, true));
        }
        AssertEx.Equal(1, observed.Count);
        AssertEx.Equal("audit-write-failure", observed[0].EventType);
        AssertEx.Equal(record.CorrelationId, observed[0].CorrelationId);

        // Fail-open mode still returns the result to the client, so mirror that result as well as its audit failure.
        observed.Clear();
        using (new FileStream(active, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            AssertEx.False(logger.Write(record, 365, false));
        }
        AssertEx.Equal(2, observed.Count);
        AssertEx.Equal("audit-write-failure", observed[0].EventType);
        AssertEx.Equal("granted", observed[1].Result);
    }

    [TestMethod(DisplayName = "Diagnostic files and optional Event Viewer delivery fail independently")]
    public void DiagnosticDeliveryIsIndependent()
    {
        using var directory = new TemporaryDirectory();
        var diagnosticDirectory = directory.File("Diagnostics");
        var events = new List<(string Message, EventLogEntryType Severity, int Id)>();
        var eventLogUnavailable = false;
        var eventLogAttempts = 0;
        var diagnostics = new DiagnosticLogger(diagnosticDirectory, "test-instance", (message, severity, id) =>
        {
            eventLogAttempts++;
            if (eventLogUnavailable) throw new UnauthorizedAccessException("Event source write access denied.");
            events.Add((message, severity, id));
        });
        var configuration = new ServiceConfiguration();
        diagnostics.Configure(configuration);
        diagnostics.Record(new AuditRecord
        {
            EventType = "unhandled-error", Result = "error", CorrelationId = "unexpected", Detail = "diagnostic detail"
        });
        var diagnosticFile = Directory.GetFiles(diagnosticDirectory, "timestamp-*.jsonl").Single();
        AssertEx.Contains("unexpected", File.ReadAllText(diagnosticFile));
        AssertEx.Equal(0, eventLogAttempts);

        // Every durable result reaches the optional sink when enabled, with its identity and trace fields.
        configuration.WriteWindowsEventLog = true;
        diagnostics.Configure(configuration);
        var audit = new AuditLogger(directory.File("Logs"), diagnostics.Record);
        foreach (var result in new[] { "granted", "rejected", "error" })
        {
            AssertEx.True(audit.Write(new AuditRecord
            {
                EventType = "timestamp", Result = result, CorrelationId = result,
                Username = "EXAMPLE\\Reviewer", Detail = "quoted \"value\"\nnext line"
            }, 365, true));
        }
        AssertEx.Equal(3, events.Count);
        AssertEx.Equal(EventLogEntryType.Information, events[0].Severity);
        AssertEx.Equal(EventLogEntryType.Warning, events[1].Severity);
        AssertEx.Equal(EventLogEntryType.Error, events[2].Severity);
        AssertEx.Contains("test-instance", events[0].Message);
        AssertEx.Contains("EXAMPLE\\\\Reviewer", events[0].Message);

        // Event Log failure preserves issuance and leaves a disk diagnostic plus a visible warning.
        eventLogUnavailable = true;
        AssertEx.True(audit.Write(new AuditRecord { EventType = "timestamp", Result = "granted" }, 365, true));
        AssertEx.Contains("Event Viewer logging is unavailable", diagnostics.Warning);
        AssertEx.Contains("event-log-failure", File.ReadAllText(diagnosticFile));
        AssertEx.Equal(4, eventLogAttempts);
        AssertEx.True(audit.Write(new AuditRecord { EventType = "timestamp", Result = "granted" }, 365, true));
        AssertEx.Equal(4, eventLogAttempts, "A broken optional sink must not be retried on every timestamp.");

        configuration.WriteWindowsEventLog = false;
        diagnostics.Configure(configuration);
        AssertEx.True(diagnostics.Warning == null);
        eventLogUnavailable = false;
        configuration.WriteWindowsEventLog = true;
        diagnostics.Configure(configuration);
        AssertEx.True(audit.Write(new AuditRecord { EventType = "timestamp", Result = "granted" }, 365, true));
        AssertEx.Equal(5, eventLogAttempts);

        // Losing the diagnostic disk destination must not prevent a working Event Log from receiving the failure.
        using (new FileStream(diagnosticFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            diagnostics.Record(new AuditRecord
            {
                EventType = "unhandled-error", Result = "error", CorrelationId = "disk-unavailable"
            });
        }
        AssertEx.Contains("Operational diagnostics could not be written", diagnostics.Warning);
        AssertEx.Contains("disk-unavailable", events.Last().Message);
    }
}
