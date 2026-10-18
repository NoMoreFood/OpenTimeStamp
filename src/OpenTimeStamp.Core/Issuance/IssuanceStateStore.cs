using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Threading;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Infrastructure;

namespace OpenTimeStamp.Issuance;

public sealed class IssuanceAllocation
{
    internal IssuanceAllocation(byte[] serialNumber, DateTime generationTimeUtc)
    {
        SerialNumber = serialNumber;
        GenerationTimeUtc = generationTimeUtc;
    }

    public byte[] SerialNumber { get; }

    public DateTime GenerationTimeUtc { get; }
}

/// <summary>
/// Supplies the serial number and generation time for each timestamp.
/// </summary>
/// <remarks>
/// Serial numbers are 127 random bits from the system generator, so their uniqueness does not
/// depend on stored state and survives a restored, cloned, or lost data directory. The only durable
/// state is the latest generation time: a high-water mark that detects a clock stepped backward
/// and keeps generation times strictly increasing when ordering is enabled.
/// </remarks>
public sealed class IssuanceStateStore
{
    private const int SerialLength = 16;
    private const int PayloadLength = 4 + sizeof(long);
    private const int RecordLength = PayloadLength + 32;
    private static readonly byte[] Magic = "OTS3"u8.ToArray();
    private readonly string path;
    private readonly string backupPath;
    private readonly string temporaryPath;
    private readonly string lockPath;

    public IssuanceStateStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A timestamp state path is required.", nameof(path));
        }

        this.path = Path.GetFullPath(path);
        backupPath = this.path + ".bak";
        temporaryPath = this.path + ".new";
        lockPath = this.path + ".lock";
    }

    /// <summary>
    /// Explicitly creates the state for a new installation, or carries the issuance clock over
    /// from a state written by an earlier release. Repeated calls change nothing.
    /// </summary>
    /// <remarks>
    /// Only this method creates state. Issuance never does, so losing the state stops issuance
    /// instead of silently discarding the rollback and ordering history.
    /// </remarks>
    public void Initialize()
    {
        using var storeLock = AcquireLock(TimeSpan.FromSeconds(10), CancellationToken.None);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            if (!TryReadHighWaterMark(out _))
            {
                var migrated = LegacyIssuanceState.ReadLastIssuedUtc(path);
                if (migrated is null && CurrentPaths().Any(File.Exists))
                {
                    throw new IssuanceStateException(
                        "Timestamp state files exist but none is valid. Automatic reset was blocked; " +
                        "restore the state from backup.");
                }

                Persist(migrated ?? DateTime.MinValue);
            }

            // Also finishes the cleanup of a migration that was interrupted after its commit.
            LegacyIssuanceState.DeleteArtifacts(path);
        }
        catch (Exception ex) when (IsStorageException(ex))
        {
            throw new IssuanceStateException(
                "OpenTimeStamp could not initialize timestamp state. Verify the data directory permissions and " +
                "free space.", ex);
        }
    }

    public IssuanceAllocation Allocate(
        Func<DateTime> utcNowProvider,
        TimeSpan rollbackTolerance,
        bool ordering,
        CancellationToken cancellationToken)
    {
        if (utcNowProvider is null) throw new ArgumentNullException(nameof(utcNowProvider));
        ValidateRollbackTolerance(rollbackTolerance);

        using var storeLock = AcquireLock(TimeSpan.FromSeconds(10), cancellationToken);
        try
        {
            var lastIssuedUtc = ReadHighWaterMark();

            // Sample after locking so waiting requests cannot report a false clock rollback.
            var utcNow = utcNowProvider().ToUniversalTime();
            EnsureClockNotRolledBack(lastIssuedUtc, utcNow, rollbackTolerance);
            var generationTime = CalculateGenerationTime(lastIssuedUtc, utcNow, ordering);

            // This is the final cancellation boundary. Once the mark moves, the time is issued.
            cancellationToken.ThrowIfCancellationRequested();

            // Record the generation time durably before returning it to the caller.
            if (generationTime != lastIssuedUtc) Persist(generationTime);
            return new IssuanceAllocation(CreateSerialNumber(), generationTime);
        }
        catch (Exception ex) when (IsStorageException(ex))
        {
            throw new IssuanceStateException(
                "OpenTimeStamp could not save timestamp state. Verify the data directory permissions and " +
                "free space.", ex);
        }
    }

    /// <summary>
    /// Validates state integrity, rollback policy, and commit access without issuing anything,
    /// and returns the generation time the next allocation would use.
    /// </summary>
    public DateTime ValidateAndGetNextGenerationTime(
        Func<DateTime> utcNowProvider,
        TimeSpan rollbackTolerance,
        bool ordering)
    {
        if (utcNowProvider is null) throw new ArgumentNullException(nameof(utcNowProvider));
        ValidateRollbackTolerance(rollbackTolerance);

        using var storeLock = AcquireLock(TimeSpan.FromSeconds(5), CancellationToken.None);
        try
        {
            var lastIssuedUtc = ReadHighWaterMark();

            // Compare against the clock after locking, just as issuance does.
            var utcNow = utcNowProvider().ToUniversalTime();
            EnsureClockNotRolledBack(lastIssuedUtc, utcNow, rollbackTolerance);
            var nextGenerationTimeUtc = CalculateGenerationTime(lastIssuedUtc, utcNow, ordering);

            // File.Replace requires delete access as well as read/write access. Request
            // the same rights here so health validation catches a restrictive file ACL
            // before the next issuance commit reaches its atomic replacement step.
            foreach (var candidate in CurrentPaths())
            {
                if (!File.Exists(candidate)) continue;
                if ((File.GetAttributes(candidate) & FileAttributes.ReadOnly) != 0)
                {
                    throw new IssuanceStateException("A timestamp state file is read-only: " + candidate);
                }

                using (new FileStream(
                           candidate,
                           FileMode.Open,
                           FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete,
                           FileShare.Read,
                           4096,
                           FileOptions.None))
                {
                }
            }

            // Probe creation and durable flush without modifying issuance data.
            var directory = Path.GetDirectoryName(path);
            var probe = Path.Combine(directory, ".state-health-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using FileStream stream = new(
                    probe,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    4096,
                    FileOptions.WriteThrough | FileOptions.DeleteOnClose);
                stream.WriteByte(0x01);
                stream.Flush(true);
            }
            finally
            {
                if (File.Exists(probe)) File.Delete(probe);
            }

            return nextGenerationTimeUtc;
        }
        catch (Exception ex) when (IsStorageException(ex))
        {
            throw new IssuanceStateException(
                "Timestamp state cannot be read and written. Verify the data directory permissions.", ex);
        }
    }

    private DateTime ReadHighWaterMark() =>
        TryReadHighWaterMark(out var lastIssuedUtc)
            ? lastIssuedUtc
            : throw new IssuanceStateException(CurrentPaths().Any(File.Exists)
                ? "Timestamp state is not valid. Restore it from backup, or rerun the installer to migrate " +
                  "state written by an earlier release."
                : "Timestamp state has not been initialized.");

    // The mark only ever moves forward, so the newest valid copy is always the right one. A staged
    // file wins after a crash that preceded its publication. The backup holds the mark before the
    // latest issuance and is reached only when nothing newer survives; the rollback check then
    // starts from that earlier time.
    private bool TryReadHighWaterMark(out DateTime lastIssuedUtc)
    {
        long? newest = null;
        foreach (var candidate in CurrentPaths())
        {
            var ticks = ReadRecord(candidate);
            if (ticks is not null && (newest is null || ticks > newest)) newest = ticks;
        }

        lastIssuedUtc = new DateTime(newest ?? 0, DateTimeKind.Utc);
        return newest is not null;
    }

    private static long? ReadRecord(string candidate)
    {
        if (!File.Exists(candidate)) return null;

        var record = new byte[RecordLength];
        using (FileStream stream = new(candidate, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (stream.Length != RecordLength) return null;
            for (var offset = 0; offset < record.Length;)
            {
                var read = stream.Read(record, offset, record.Length - offset);
                if (read == 0) return null;
                offset += read;
            }
        }

        if (!record.AsSpan().StartsWith(Magic)) return null;
        var checksum = WindowsHash.ComputeSha256(record.AsSpan(0, PayloadLength).ToArray());
        if (!record.AsSpan(PayloadLength).SequenceEqual(checksum)) return null;

        var ticks = BitConverter.ToInt64(record, Magic.Length);
        return ticks < 0 || ticks > DateTime.MaxValue.Ticks ? null : ticks;
    }

    private void Persist(DateTime lastIssuedUtc)
    {
        var record = new byte[RecordLength];
        Buffer.BlockCopy(Magic, 0, record, 0, Magic.Length);
        Buffer.BlockCopy(BitConverter.GetBytes(lastIssuedUtc.Ticks), 0, record, Magic.Length, sizeof(long));
        var checksum = WindowsHash.ComputeSha256(record.AsSpan(0, PayloadLength).ToArray());
        Buffer.BlockCopy(checksum, 0, record, PayloadLength, checksum.Length);

        // Flush a complete sibling file, then publish it atomically. The record it replaces
        // becomes the backup.
        using (FileStream stream = new(
                   temporaryPath,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None,
                   4096,
                   FileOptions.WriteThrough))
        {
            stream.Write(record, 0, record.Length);
            stream.Flush(true);
        }

        if (File.Exists(path))
        {
            File.Replace(temporaryPath, path, backupPath, true);
        }
        else
        {
            File.Move(temporaryPath, path);
        }
    }

    private static byte[] CreateSerialNumber()
    {
        var serial = new byte[SerialLength];
        using RandomNumberGenerator random = RandomNumberGenerator.Create();
        random.GetBytes(serial);

        // RFC 3161 serial numbers are positive integers.
        serial[0] &= 0x7f;
        if (serial.All(value => value == 0)) serial[SerialLength - 1] = 1;
        return serial;
    }

    private IEnumerable<string> CurrentPaths()
    {
        yield return path;
        yield return temporaryPath;
        yield return backupPath;
    }

    private static void EnsureClockNotRolledBack(
        DateTime lastIssuedUtc,
        DateTime utcNow,
        TimeSpan rollbackTolerance)
    {
        if (lastIssuedUtc == DateTime.MinValue) return;
        var minimumTicks = rollbackTolerance.Ticks >= lastIssuedUtc.Ticks
            ? DateTime.MinValue.Ticks
            : lastIssuedUtc.Ticks - rollbackTolerance.Ticks;
        if (utcNow.Ticks >= minimumTicks) return;

        throw new ClockRollbackException(string.Format(
            CultureInfo.InvariantCulture,
            "The system clock moved backward beyond the configured tolerance. Last issuance: {0:o}; current time: {1:o}.",
            lastIssuedUtc,
            utcNow));
    }

    private static DateTime CalculateGenerationTime(DateTime lastIssuedUtc, DateTime utcNow, bool ordering)
    {
        var generationTimeUtc = utcNow < lastIssuedUtc ? lastIssuedUtc : utcNow;
        if (!ordering || generationTimeUtc > lastIssuedUtc) return generationTimeUtc;
        if (lastIssuedUtc == DateTime.MaxValue)
        {
            throw new IssuanceStateException("The timestamp ordering time range has been exhausted.");
        }

        return lastIssuedUtc.AddTicks(1);
    }

    private static void ValidateRollbackTolerance(TimeSpan rollbackTolerance)
    {
        if (rollbackTolerance < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(rollbackTolerance), "Rollback tolerance cannot be negative.");
        }
    }

    private static bool IsStorageException(Exception exception) =>
        exception.IsFileAccessFailure() || exception is CryptographicException;

    private FileStream AcquireLock(TimeSpan wait, CancellationToken cancellationToken)
    {
        try
        {
            return FileSystemLock.Acquire(
                lockPath,
                wait,
                contention => new IssuanceStateException(
                    "Another OpenTimeStamp process is updating timestamp state. Try again shortly.",
                    contention),
                cancellationToken);
        }
        catch (Exception ex) when (IsStorageException(ex))
        {
            throw new IssuanceStateException(
                "OpenTimeStamp could not lock timestamp state. Verify the data directory permissions.", ex);
        }
    }
}

public class IssuanceStateException(string message, Exception? innerException = null)
    : Exception(message, innerException);

public sealed class ClockRollbackException(string message) : IssuanceStateException(message);
