using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Infrastructure;

namespace OpenTimeStamp.Audit;

public sealed class AuditRecord
{
    public DateTime TimestampUtc { get; set; }
    public string EventType { get; set; }
    public string Result { get; set; }
    public string CorrelationId { get; set; }
    public string Protocol { get; set; }
    public string Username { get; set; }
    public string UserSid { get; set; }
    public string AuthenticationType { get; set; }
    public string RemoteAddress { get; set; }
    public string PolicyOid { get; set; }
    public string HashAlgorithmOid { get; set; }
    public string MessageImprintHex { get; set; }
    public string SerialHex { get; set; }
    public string CertificateThumbprint { get; set; }
    public long DurationMilliseconds { get; set; }
    public string Detail { get; set; }
}

public sealed class AuditLogger
{
    private static readonly TimeSpan DefaultCleanupRetryInterval = TimeSpan.FromMinutes(5);
    private readonly string directory;
    private readonly string lockPath;
    private readonly object cleanupGate = new();
    private readonly long cleanupRetryIntervalTicks;
    private DateTime lastCleanupPeriodUtc;
    private int lastCleanupRetentionDays;
    private string lastCleanupRolloverInterval;
    private long lastCleanupFailureTimestamp;
    private bool cleanupRetryPending;
    private bool cleanupSuppressed;

    public AuditLogger(string directory) : this(directory, DefaultCleanupRetryInterval)
    {
    }

    internal AuditLogger(string directory, TimeSpan cleanupRetryInterval)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("A log directory is required.", nameof(directory));
        }

        if (cleanupRetryInterval < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(cleanupRetryInterval));
        }

        this.directory = Path.GetFullPath(directory);
        lockPath = Path.Combine(this.directory, ".audit.lock");
        cleanupRetryIntervalTicks = ToStopwatchTicks(cleanupRetryInterval);
    }

    public bool Write(AuditRecord record, int retentionDays, bool failClosed) =>
        Write(record, ServiceConfiguration.DailyLogRollover, true, retentionDays, failClosed);

    public bool Write(
        AuditRecord record,
        string rolloverInterval,
        bool pruneLogs,
        int retentionDays,
        bool failClosed)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        if (record.TimestampUtc == default) record.TimestampUtc = DateTime.UtcNow;

        try
        {
            // Serialize before entering the cross-process lock to minimize contention.
            Directory.CreateDirectory(directory);
            var file = GetLogPath(record.TimestampUtc, rolloverInterval);
            var bytes = new UTF8Encoding(false).GetBytes(Serialize(record) + Environment.NewLine);

            // Reject an interrupted final record before appending another line. Without
            // this check a valid record would be concatenated to a torn JSON fragment
            // and issuance could appear successfully audited when the line is invalid.
            using (AcquireLock(TimeSpan.FromSeconds(5)))
            {
                using FileStream stream = OpenActiveLog(file);
                EnsureCompleteJsonLineTail(stream);
                stream.Seek(0, SeekOrigin.End);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }

            if (pruneLogs) Cleanup(record.TimestampUtc, rolloverInterval, retentionDays);
            else SuppressCleanup();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            if (failClosed)
                throw new AuditLogException(
                    "The audit log entry could not be committed to disk. Verify the log directory permissions and free space.",
                    ex);
            return false;
        }
    }

    public void ProbeWritable() => ProbeWritable(ServiceConfiguration.DailyLogRollover);

    public void ProbeWritable(string rolloverInterval)
    {
        string probe = null;
        try
        {
            Directory.CreateDirectory(directory);
            var file = GetLogPath(DateTime.UtcNow, rolloverInterval);
            probe = Path.Combine(directory, ".audit-health-" + Guid.NewGuid().ToString("N") + ".tmp");
            using (AcquireLock(TimeSpan.FromSeconds(5)))
            {
                // Exercise the real target and reject a torn tail, then force an
                // allocation and durable flush on the same volume without fabricating
                // an audit event. A zero-byte flush can succeed on a full filesystem.
                using (FileStream active = OpenActiveLog(file))
                {
                    EnsureCompleteJsonLineTail(active);
                }

                using FileStream allocation = new(
                    probe,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    4096,
                    FileOptions.WriteThrough | FileOptions.DeleteOnClose);
                allocation.WriteByte(0x01);
                allocation.Flush(true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new AuditLogException(
                "The active audit log cannot be opened for writing. Verify the log file permissions and free space.", ex);
        }
        finally
        {
            try
            {
                if (probe != null && File.Exists(probe)) File.Delete(probe);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                // DeleteOnClose normally removes the probe. A uniquely named health
                // artifact is harmless if final cleanup is temporarily blocked.
            }
        }
    }

    private static FileStream OpenActiveLog(string file) => new(
        file,
        FileMode.OpenOrCreate,
        FileAccess.ReadWrite,
        FileShare.Read,
        4096,
        FileOptions.WriteThrough);

    private static void EnsureCompleteJsonLineTail(FileStream stream)
    {
        if (stream.Length == 0) return;

        stream.Seek(-1, SeekOrigin.End);
        if (stream.ReadByte() != 0x0A)
        {
            throw new IOException(
                "The active audit log ends with an incomplete JSON line. Stop issuance and reconcile the audit trail before continuing.");
        }
    }

    private void Cleanup(DateTime nowUtc, string rolloverInterval, int retentionDays)
    {
        nowUtc = nowUtc.ToUniversalTime();
        var cleanupPeriodUtc = GetCleanupPeriodUtc(nowUtc, rolloverInterval);
        lock (cleanupGate)
        {
            var sameCleanupKey = lastCleanupPeriodUtc == cleanupPeriodUtc &&
                lastCleanupRetentionDays == retentionDays &&
                string.Equals(lastCleanupRolloverInterval, rolloverInterval, StringComparison.OrdinalIgnoreCase);
            if (sameCleanupKey && !cleanupRetryPending && !cleanupSuppressed) return;

            var attemptTimestamp = Stopwatch.GetTimestamp();
            var elapsedSinceFailure = attemptTimestamp - lastCleanupFailureTimestamp;
            if (sameCleanupKey && cleanupRetryPending && !cleanupSuppressed && elapsedSinceFailure >= 0 &&
                elapsedSinceFailure < cleanupRetryIntervalTicks)
            {
                return;
            }

            lastCleanupPeriodUtc = cleanupPeriodUtc;
            lastCleanupRetentionDays = retentionDays;
            lastCleanupRolloverInterval = rolloverInterval;
            cleanupSuppressed = false;

            // Run retention once per configured UTC rollover period and only after the
            // current record is durable. Retry failed passes at a bounded cadence, while
            // allowing one inaccessible file to leave independently removable files unaffected.
            var threshold = nowUtc.AddDays(-Math.Max(1, retentionDays));
            var cleanupComplete = true;
            try
            {
                foreach (var file in Directory.EnumerateFiles(
                             directory,
                             "timestamp-*.jsonl",
                             SearchOption.TopDirectoryOnly))
                {
                    if (TryGetLogPeriodEndUtc(file, out var periodEndUtc) && periodEndUtc <= threshold)
                    {
                        try
                        {
                            File.Delete(file);
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                                   System.Security.SecurityException)
                        {
                            cleanupComplete = false;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       System.Security.SecurityException)
            {
                cleanupComplete = false;
            }

            if (cleanupComplete)
            {
                cleanupRetryPending = false;
            }
            else
            {
                lastCleanupFailureTimestamp = attemptTimestamp;
                cleanupRetryPending = true;
            }
        }
    }

    private void SuppressCleanup()
    {
        lock (cleanupGate) cleanupSuppressed = true;
    }

    private string GetLogPath(DateTime timestampUtc, string rolloverInterval)
    {
        timestampUtc = timestampUtc.ToUniversalTime();
        var suffix = string.Equals(rolloverInterval, ServiceConfiguration.HourlyLogRollover, StringComparison.OrdinalIgnoreCase)
            ? timestampUtc.ToString("yyyyMMdd-HH", CultureInfo.InvariantCulture)
            : string.Equals(rolloverInterval, ServiceConfiguration.DailyLogRollover, StringComparison.OrdinalIgnoreCase)
                ? timestampUtc.ToString("yyyyMMdd", CultureInfo.InvariantCulture)
                : string.Equals(rolloverInterval, ServiceConfiguration.WeeklyLogRollover, StringComparison.OrdinalIgnoreCase)
                    ? "week-" + GetWeekStartUtc(timestampUtc).ToString("yyyyMMdd", CultureInfo.InvariantCulture)
                    : throw new ArgumentException(
                        "The audit log rotation schedule must be Daily, Hourly, or Weekly.", nameof(rolloverInterval));
        return Path.Combine(directory, "timestamp-" + suffix + ".jsonl");
    }

    private static DateTime GetCleanupPeriodUtc(DateTime nowUtc, string rolloverInterval)
    {
        if (string.Equals(rolloverInterval, ServiceConfiguration.DailyLogRollover, StringComparison.OrdinalIgnoreCase))
            return nowUtc.Date;
        if (string.Equals(rolloverInterval, ServiceConfiguration.HourlyLogRollover, StringComparison.OrdinalIgnoreCase))
            return new DateTime(nowUtc.Year, nowUtc.Month, nowUtc.Day, nowUtc.Hour, 0, 0, DateTimeKind.Utc);
        if (string.Equals(rolloverInterval, ServiceConfiguration.WeeklyLogRollover, StringComparison.OrdinalIgnoreCase))
            return GetWeekStartUtc(nowUtc);

        throw new ArgumentException(
            "The audit log rotation schedule must be Daily, Hourly, or Weekly.", nameof(rolloverInterval));
    }

    private static bool TryGetLogPeriodEndUtc(string path, out DateTime periodEndUtc)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        if (name.Length == 18 && TryParseLogPeriod(name.Substring(10), "yyyyMMdd", out var dailyStartUtc))
        {
            periodEndUtc = dailyStartUtc.AddDays(1);
            return true;
        }

        if (name.Length == 21 && TryParseLogPeriod(name.Substring(10), "yyyyMMdd-HH", out var hourlyStartUtc))
        {
            periodEndUtc = hourlyStartUtc.AddHours(1);
            return true;
        }

        if (name.Length == 23 && name.StartsWith("timestamp-week-", StringComparison.Ordinal) &&
            TryParseLogPeriod(name.Substring(15), "yyyyMMdd", out var weeklyStartUtc))
        {
            periodEndUtc = weeklyStartUtc.AddDays(7);
            return true;
        }

        periodEndUtc = default;
        return false;
    }

    private static DateTime GetWeekStartUtc(DateTime timestampUtc)
    {
        timestampUtc = timestampUtc.ToUniversalTime();
        var daysSinceMonday = ((int)timestampUtc.DayOfWeek + 6) % 7;
        return timestampUtc.Date.AddDays(-daysSinceMonday);
    }

    private static bool TryParseLogPeriod(string value, string format, out DateTime timestampUtc) =>
        DateTime.TryParseExact(
            value,
            format,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestampUtc);

    private FileStream AcquireLock(TimeSpan wait) =>
        FileSystemLock.Acquire(
            lockPath,
            wait,
            contention => new IOException("Timed out waiting for the audit log lock.", contention),
            CancellationToken.None);

    private static string Serialize(AuditRecord record)
    {
        // Keep field order stable so JSONL records remain easy to inspect and diff.
        List<string> fields =
        [
            Field("timestampUtc", record.TimestampUtc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)),
            Field("eventType", record.EventType),
            Field("result", record.Result),
            Field("correlationId", record.CorrelationId),
            Field("protocol", record.Protocol),
            Field("username", string.IsNullOrEmpty(record.Username) ? "anonymous" : record.Username),
            Field("userSid", record.UserSid),
            Field("authenticationType", record.AuthenticationType),
            Field("remoteAddress", record.RemoteAddress),
            Field("policyOid", record.PolicyOid),
            Field("hashAlgorithmOid", record.HashAlgorithmOid),
            Field("messageImprint", record.MessageImprintHex),
            Field("serial", record.SerialHex),
            Field("certificateThumbprint", record.CertificateThumbprint),
            "\"durationMilliseconds\":" + record.DurationMilliseconds.ToString(CultureInfo.InvariantCulture),
            Field("detail", record.Detail)
        ];
        return "{" + string.Join(",", fields) + "}";
    }

    private static string Field(string name, string value) =>
        "\"" + Escape(name) + "\":" + (value is null ? "null" : "\"" + Escape(value) + "\"");

    private static string Escape(string value)
    {
        StringBuilder builder = new();
        foreach (var character in value ?? string.Empty)
        {
            switch (character)
            {
                case '\\': builder.Append("\\\\"); break;
                case '"': builder.Append("\\\""); break;
                case '\b': builder.Append("\\b"); break;
                case '\f': builder.Append("\\f"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                default:
                    if (character < 0x20)
                    {
                        builder.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(character);
                    }

                    break;
            }
        }

        return builder.ToString();
    }

    private static long ToStopwatchTicks(TimeSpan interval)
    {
        var scaled = interval.TotalSeconds * Stopwatch.Frequency;
        return scaled >= long.MaxValue ? long.MaxValue : (long)Math.Ceiling(scaled);
    }
}

public sealed class AuditLogException : Exception
{
    public AuditLogException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
