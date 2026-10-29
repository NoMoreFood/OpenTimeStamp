using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using OpenTimeStamp.Cryptography;

namespace OpenTimeStamp.Issuance;

// Reads the sequential-serial state that earlier releases wrote, so an upgrade keeps its issuance
// clock. Nothing here writes those formats. Remove this file once no deployment upgrades from them.
internal static class LegacyIssuanceState
{
    // OTS1: magic, serial, ticks.
    private const int Ots1Length = 4 + 16 + sizeof(long);

    // OTS2: magic, state identifier, generation, serial, ticks, then an HMAC-SHA-256 of all of those.
    private const int Ots2PayloadLength = 4 + 16 + sizeof(ulong) + 16 + sizeof(long);
    private const int Ots2Length = Ots2PayloadLength + 32;

    // Marker: magic, state identifier, HMAC key, generation, initial serial, then a SHA-256.
    private const int MarkerKeyOffset = 4 + 16;
    private const int MarkerKeyLength = 32;
    private const int MarkerPayloadLength = MarkerKeyOffset + MarkerKeyLength + sizeof(ulong) + 16;
    private const int MarkerLength = MarkerPayloadLength + 32;

    private static readonly string[] StateSuffixes = [string.Empty, ".new", ".migrate", ".migrate.new"];
    private static readonly string[] MarkerSuffixes = [".meta", ".meta.bak", ".meta.new"];

    /// <summary>
    /// Returns the most recent issuance time a legacy store recorded, or null when the path holds
    /// no legacy state at all. Throws when legacy state is present but none of it can be verified.
    /// </summary>
    internal static DateTime? ReadLastIssuedUtc(string path)
    {
        var keys = MarkerSuffixes.Select(suffix => ReadMarkerKey(path + suffix)).OfType<byte[]>().ToList();
        var present = StateSuffixes.Concat(MarkerSuffixes).Concat([".bak", ".bak.new"])
            .Any(suffix => File.Exists(path + suffix));
        long? newest = null;
        var publishedValid = false;
        foreach (var suffix in StateSuffixes)
        {
            var record = ReadBounded(path + suffix, Ots2Length);
            if (record is null) continue;

            long? ticks = null;
            if (record.AsSpan().StartsWith("OTS2"u8))
            {
                present = true;
                if (record.Length == Ots2Length && keys.Any(key => IsAuthentic(record, key)))
                {
                    ticks = BitConverter.ToInt64(record, Ots2PayloadLength - sizeof(long));
                }
            }
            else if (suffix.Length == 0 && record.AsSpan().StartsWith("OTS1"u8))
            {
                present = true;
                if (record.Length == Ots1Length) ticks = BitConverter.ToInt64(record, Ots1Length - sizeof(long));
            }

            // The published or staged record may carry a newer mark than an old mirror.
            if (ticks is >= 0 && ticks <= DateTime.MaxValue.Ticks)
            {
                if (suffix.Length == 0) publishedValid = true;
                if (newest is null || ticks > newest) newest = ticks;
            }
        }

        if (publishedValid && newest is not null) return new DateTime(newest.Value, DateTimeKind.Utc);
        if (!present) return null;

        throw new IssuanceStateException(
            "Timestamp state written by an earlier release could not be verified for migration. " +
            "Restore the complete state set from backup.");
    }

    /// <summary>Removes files that only the earlier formats used, once the current state is committed.</summary>
    internal static void DeleteArtifacts(string path)
    {
        foreach (var suffix in MarkerSuffixes.Concat([".bak.new", ".migrate", ".migrate.new"]))
        {
            TryDelete(path + suffix);
        }

        // The first commit after a migration leaves the replaced legacy record as the backup.
        try
        {
            var backup = ReadBounded(path + ".bak", Ots2Length);
            if (backup is not null && backup.AsSpan().StartsWith("OTS2"u8)) TryDelete(path + ".bak");
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static byte[]? ReadMarkerKey(string candidate)
    {
        var marker = ReadBounded(candidate, MarkerLength);
        if (marker is null || marker.Length != MarkerLength ||
            !(marker.AsSpan().StartsWith("OTSM"u8) || marker.AsSpan().StartsWith("OTSB"u8)))
        {
            return null;
        }

        var checksum = WindowsHash.ComputeSha256(marker.AsSpan(0, MarkerPayloadLength).ToArray());
        return marker.AsSpan(MarkerPayloadLength).SequenceEqual(checksum)
            ? marker.AsSpan(MarkerKeyOffset, MarkerKeyLength).ToArray()
            : null;
    }

    private static bool IsAuthentic(byte[] record, byte[] key)
    {
        using HMACSHA256 hmac = new(key);
        return WindowsHash.FixedTimeEquals(
            hmac.ComputeHash(record, 0, Ots2PayloadLength),
            record.AsSpan(Ots2PayloadLength).ToArray());
    }

    // Returns null for a missing file and an empty array for one too large to be a legacy record.
    private static byte[]? ReadBounded(string candidate, int maximumLength)
    {
        if (!File.Exists(candidate)) return null;

        using FileStream stream = new(candidate, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > maximumLength) return [];

        var content = new byte[(int)stream.Length];
        for (var offset = 0; offset < content.Length;)
        {
            var read = stream.Read(content, offset, content.Length - offset);
            if (read == 0) return [];
            offset += read;
        }

        return content;
    }

    private static void TryDelete(string candidate)
    {
        try
        {
            if (File.Exists(candidate)) File.Delete(candidate);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
