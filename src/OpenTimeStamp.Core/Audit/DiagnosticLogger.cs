using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using Microsoft.Win32;
using OpenTimeStamp.Configuration;

namespace OpenTimeStamp.Audit;

public sealed class DiagnosticLogger
{
    public const string WindowsLogName = "OpenTimeStamp";
    public const string WindowsEventSource = "OpenTimeStamp";
    private static readonly long RetryIntervalTicks = Stopwatch.Frequency * 300;
    private readonly AuditLogger fileLogger;
    private readonly string instance;
    private readonly Action<string, EventLogEntryType, int> eventWriter;
    private readonly object gate = new();
    private readonly Dictionary<string, long> lastFailureReports = new(StringComparer.Ordinal);
    private ServiceConfiguration configuration = new();
    private long nextEventLogAttempt;
    private string fileWarning;
    private string eventLogWarning;

    public DiagnosticLogger(string directory, string instance)
        : this(directory, instance, WriteWindowsEvent)
    {
    }

    internal DiagnosticLogger(string directory, string instance, Action<string, EventLogEntryType, int> eventWriter)
    {
        fileLogger = new AuditLogger(directory);
        this.instance = instance;
        this.eventWriter = eventWriter ?? throw new ArgumentNullException(nameof(eventWriter));
    }

    public string Warning => Volatile.Read(ref fileWarning) ?? Volatile.Read(ref eventLogWarning) ??
        fileLogger.RetentionWarning;

    public void Configure(ServiceConfiguration settings)
    {
        if (settings is null) throw new ArgumentNullException(nameof(settings));

        // Reset optional delivery backoff when the administrator changes its enabled state.
        var copy = settings.Clone();
        lock (gate)
        {
            if (configuration.WriteWindowsEventLog != copy.WriteWindowsEventLog)
            {
                nextEventLogAttempt = 0;
                Volatile.Write(ref eventLogWarning, null);
            }
            Volatile.Write(ref configuration, copy);
        }
    }

    public void Record(AuditRecord record)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        try
        {
            // Bound repeated operational failures without dropping ordinary audit mirrors.
            if (record.TimestampUtc == default) record.TimestampUtc = DateTime.UtcNow;
            var isAudit = record.EventType is "timestamp" or "configuration-change";
            if (!isAudit && record.EventType is "audit-write-failure" or "audit-retention-failure")
            {
                var now = Stopwatch.GetTimestamp();
                lock (gate)
                {
                    if (lastFailureReports.TryGetValue(record.EventType, out var last) &&
                        now - last >= 0 && now - last < RetryIntervalTicks) return;
                    lastFailureReports[record.EventType] = now;
                }
            }

            var settings = Volatile.Read(ref configuration);
            if (!isAudit) WriteDiagnosticFile(record, settings);
            if (!settings.WriteWindowsEventLog) return;

            // Event Viewer is an optional copy, independent of the authoritative audit commit.
            lock (gate)
            {
                var now = Stopwatch.GetTimestamp();
                if (nextEventLogAttempt != 0 && now < nextEventLogAttempt) return;
                try
                {
                    var message = "OpenTimeStamp\nInstance: " + instance + "\n" + AuditLogger.Serialize(record);
                    if (message.Length > 30000) message = message.Substring(0, 30000) + "\n[truncated]";
                    var severity = record.Result is "failed" or "error" ? EventLogEntryType.Error :
                        record.Result is "rejected" or "warning" ? EventLogEntryType.Warning :
                        EventLogEntryType.Information;
                    var eventId = record.EventType switch
                    {
                        "timestamp" => 1000,
                        "configuration-change" => 2000,
                        "audit-write-failure" => 3001,
                        "audit-retention-failure" => 3002,
                        _ => 3000
                    };
                    eventWriter(message, severity, eventId);
                    nextEventLogAttempt = 0;
                    Volatile.Write(ref eventLogWarning, null);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException and
                                           not StackOverflowException and not ThreadAbortException)
                {
                    nextEventLogAttempt = now + RetryIntervalTicks;
                    Volatile.Write(ref eventLogWarning,
                        "Event Viewer logging is unavailable. Rerun the IIS installer to register the " +
                        "OpenTimeStamp log and verify the service account's write access. Delivery will retry.");
                    WriteDiagnosticFile(new AuditRecord
                    {
                        EventType = "event-log-failure",
                        Result = "warning",
                        CorrelationId = record.CorrelationId,
                        Detail = ex.ToString()
                    }, settings);
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and
                                   not StackOverflowException and not ThreadAbortException)
        {
            Volatile.Write(ref fileWarning, "Operational diagnostics could not be recorded. Check the data directory.");
        }
    }

    private void WriteDiagnosticFile(AuditRecord record, ServiceConfiguration settings)
    {
        var written = fileLogger.Write(record, ServiceConfiguration.DailyLogRollover,
            settings.PruneAuditLogs, settings.LogRetentionDays, false);
        Volatile.Write(ref fileWarning, written ? null :
            "Operational diagnostics could not be written. Check the diagnostic log permissions and free space.");
    }

    private static void WriteWindowsEvent(string message, EventLogEntryType severity, int eventId)
    {
        // Source registration belongs to elevated setup, never the IIS worker identity.
        using var source = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\EventLog\" + WindowsLogName + "\\" + WindowsEventSource);
        if (source == null)
            throw new InvalidOperationException("The OpenTimeStamp Windows Event Log source is not registered.");

        using EventLog log = new(WindowsLogName, ".", WindowsEventSource);
        log.WriteEntry(message, severity, eventId);
    }
}
