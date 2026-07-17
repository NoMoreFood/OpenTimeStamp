using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
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

public sealed class IssuanceStateStore
{
    private const int SerialLength = 16;
    private const int StateIdentifierLength = 16;
    private const int IntegrityKeyLength = 32;
    private const int IntegrityLength = 32;
    private const int LegacyRecordLength = 4 + SerialLength + sizeof(long);
    private const int StatePayloadLength = 4 + StateIdentifierLength + sizeof(ulong) + SerialLength + sizeof(long);
    private const int StateRecordLength = StatePayloadLength + IntegrityLength;
    private const int MarkerPayloadLength = 4 + StateIdentifierLength + IntegrityKeyLength + sizeof(ulong) + SerialLength;
    private const int MarkerRecordLength = MarkerPayloadLength + IntegrityLength;
    private static readonly byte[] LegacyMagic = Encoding.ASCII.GetBytes("OTS1");
    private static readonly byte[] StateMagic = Encoding.ASCII.GetBytes("OTS2");
    private static readonly byte[] MarkerMagic = Encoding.ASCII.GetBytes("OTSM");
    private static readonly byte[] MirroredMarkerMagic = Encoding.ASCII.GetBytes("OTSB");
    private readonly string path;
    private readonly string backupPath;
    private readonly string temporaryPath;
    private readonly string backupTemporaryPath;
    private readonly string markerPath;
    private readonly string markerBackupPath;
    private readonly string markerTemporaryPath;
    private readonly string migrationPath;
    private readonly string migrationTemporaryPath;
    private readonly string lockPath;

    public IssuanceStateStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A timestamp state path is required.", nameof(path));
        }

        this.path = System.IO.Path.GetFullPath(path);
        backupPath = this.path + ".bak";
        temporaryPath = this.path + ".new";
        backupTemporaryPath = backupPath + ".new";
        markerPath = this.path + ".meta";
        markerBackupPath = markerPath + ".bak";
        markerTemporaryPath = markerPath + ".new";
        migrationPath = this.path + ".migrate";
        migrationTemporaryPath = migrationPath + ".new";
        lockPath = this.path + ".lock";
    }

    /// <summary>
    /// Explicitly creates a new state store or migrates a valid legacy OTS1 state.
    /// Repeated calls validate and repair redundant copies without reseeding the serial space.
    /// </summary>
    public void Initialize()
    {
        ExecuteLocked(TimeSpan.FromSeconds(10), () =>
        {
            try
            {
                InitializeLocked();
            }
            catch (IssuanceStateException)
            {
                throw;
            }
            catch (Exception ex) when (IsStorageException(ex))
            {
                throw new IssuanceStateException(
                    "OpenTimeStamp could not initialize timestamp state. Verify the data directory permissions and free space.", ex);
            }
        });
    }

    public IssuanceAllocation Allocate(DateTime utcNow, TimeSpan rollbackTolerance, bool ordering) =>
        Allocate(utcNow, rollbackTolerance, ordering, CancellationToken.None);

    public IssuanceAllocation Allocate(
        DateTime utcNow,
        TimeSpan rollbackTolerance,
        bool ordering,
        CancellationToken cancellationToken)
    {
        utcNow = utcNow.ToUniversalTime();
        ValidateRollbackTolerance(rollbackTolerance);

        return ExecuteLocked(TimeSpan.FromSeconds(10), cancellationToken, () =>
        {
            try
            {
                MarkerSelection markerSelection;
                DurableState loaded;
                if (!TryReadFullyMirroredState(out markerSelection, out loaded))
                {
                    markerSelection = ReadBestMarker();
                    if (markerSelection is null)
                    {
                        throw new IssuanceStateException(
                            "Timestamp state has not been initialized.");
                    }

                    loaded = LoadDurableState(markerSelection);
                }

                var marker = markerSelection.Marker;
                var state = loaded.State;

                // Complete an interrupted commit before beginning another generation. This
                // keeps the high-water marker at most one generation behind durable state.
                if (loaded.RequiresRepair)
                {
                    RepairState(state, marker);
                }

                EnsureClockNotRolledBack(state.LastIssuedUtc, utcNow, rollbackTolerance);
                var generationTime = CalculateGenerationTime(state.LastIssuedUtc, utcNow, ordering);

                if (state.Generation == ulong.MaxValue)
                {
                    throw new IssuanceStateException("Timestamp state has exhausted its sequence-number range.");
                }

                // This is the final cancellation boundary. Once the serial changes, finish
                // every durable publication even if the caller disconnects.
                cancellationToken.ThrowIfCancellationRequested();

                // Persist the next serial, timestamp, redundant copy, and high-water marker
                // before returning either issued value to the caller.
                Increment(state.SerialNumber);
                state.Generation++;
                state.LastIssuedUtc = generationTime;
                PersistStateCopies(state, marker);
                marker.Generation = state.Generation;
                PersistMarker(marker);
                return new IssuanceAllocation((byte[])state.SerialNumber.Clone(), generationTime);
            }
            catch (IssuanceStateException)
            {
                throw;
            }
            catch (Exception ex) when (IsStorageException(ex))
            {
                throw new IssuanceStateException(
                    "OpenTimeStamp could not save timestamp state. Verify the data directory permissions and free space.", ex);
            }
        });
    }

    public void Validate() => ValidateCore(null, TimeSpan.Zero, false);

    /// <summary>
    /// Validates state integrity and write access, and checks the durable issuance clock
    /// against the supplied current UTC time without allocating a serial number.
    /// </summary>
    public void Validate(DateTime utcNow, TimeSpan rollbackTolerance)
    {
        ValidateRollbackTolerance(rollbackTolerance);
        ValidateCore(utcNow.ToUniversalTime(), rollbackTolerance, false);
    }

    /// <summary>
    /// Validates state integrity, rollback policy, and commit access without consuming a
    /// serial number, and returns the generation time the next allocation would use.
    /// </summary>
    public DateTime ValidateAndGetNextGenerationTime(
        DateTime utcNow,
        TimeSpan rollbackTolerance,
        bool ordering)
    {
        ValidateRollbackTolerance(rollbackTolerance);
        return ValidateCore(utcNow.ToUniversalTime(), rollbackTolerance, ordering).Value;
    }

    private DateTime? ValidateCore(DateTime? utcNow, TimeSpan rollbackTolerance, bool ordering)
    {
        return ExecuteLocked(TimeSpan.FromSeconds(5), () =>
        {
            try
            {
                MarkerSelection markerSelection;
                DurableState loaded;
                if (!TryReadFullyMirroredState(out markerSelection, out loaded))
                {
                    markerSelection = ReadBestMarker();
                    if (markerSelection is null)
                    {
                        throw new IssuanceStateException("Timestamp state has not been initialized.");
                    }

                    loaded = LoadDurableState(markerSelection);
                }

                DateTime? nextGenerationTimeUtc = null;
                if (utcNow.HasValue)
                {
                    EnsureClockNotRolledBack(loaded.State.LastIssuedUtc, utcNow.Value, rollbackTolerance);
                    nextGenerationTimeUtc = CalculateGenerationTime(
                        loaded.State.LastIssuedUtc,
                        utcNow.Value,
                        ordering);
                }

                // File.Replace requires delete access as well as read/write access. Request
                // the same rights here so health validation catches a restrictive file ACL
                // before the next issuance commit reaches its atomic replacement step.
                foreach (var candidate in PersistentArtifactPaths())
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
                var directory = System.IO.Path.GetDirectoryName(path);
                Directory.CreateDirectory(directory);
                var probe = System.IO.Path.Combine(directory, ".state-health-" + Guid.NewGuid().ToString("N") + ".tmp");
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
            catch (IssuanceStateException)
            {
                throw;
            }
            catch (Exception ex) when (IsStorageException(ex))
            {
                throw new IssuanceStateException(
                    "Timestamp state cannot be read and written. Verify the data directory permissions.", ex);
            }
        });
    }

    private void InitializeLocked()
    {
        var directory = System.IO.Path.GetDirectoryName(path);
        Directory.CreateDirectory(directory);

        RecoverTornInitialMarkerIfSafe();
        var markerSelection = ReadBestMarker();
        if (markerSelection is null)
        {
            if (File.Exists(path))
            {
                MigrateLegacyState();
                return;
            }

            if (HasAnyStateEvidence())
            {
                throw new IssuanceStateException(
                    "Timestamp state files exist without a matching active state and integrity file. " +
                    "Automatic reset was blocked to prevent timestamp reuse.");
            }

            var initialSerial = CreateSerialSeed();
            var marker = CreateMarker(0, initialSerial);
            var state = new State
            {
                StateIdentifier = (byte[])marker.StateIdentifier.Clone(),
                Generation = 0,
                SerialNumber = (byte[])initialSerial.Clone(),
                LastIssuedUtc = DateTime.MinValue
            };

            // The generation-zero marker contains the initial serial, so a crash after this
            // durable write but before the state copies can be completed is recoverable.
            PersistMarker(marker);
            PersistStateCopies(state, marker);
            return;
        }

        var loaded = LoadDurableState(markerSelection);
        RepairState(loaded.State, markerSelection.Marker);
        TryDelete(migrationPath);
        TryDelete(migrationTemporaryPath);
    }

    private void RecoverTornInitialMarkerIfSafe()
    {
        // A sole malformed staging marker can only be discarded when the filesystem proves
        // that marker publication never committed: either this is an otherwise fresh store,
        // or the authoritative active record is still a complete legacy OTS1 record.
        if (File.Exists(markerPath) || File.Exists(markerBackupPath) || !File.Exists(markerTemporaryPath)) return;

        try
        {
            ReadMarker(markerTemporaryPath, out _);
            return;
        }
        catch (CorruptPersistentRecordException)
        {
        }

        var isFresh = !HasAnyStateEvidence();
        var hasValidLegacyActiveState = false;
        if (!isFresh && File.Exists(path))
        {
            try
            {
                ReadLegacyState(path);
                hasValidLegacyActiveState = true;
            }
            catch (IssuanceStateException)
            {
                // Unknown or unreadable state evidence must continue to fail closed.
            }
        }

        if (isFresh || hasValidLegacyActiveState)
        {
            File.Delete(markerTemporaryPath);
        }
    }

    private void MigrateLegacyState()
    {
        var legacy = ReadLegacyState(path);
        var marker = CreateMarker(1, legacy.SerialNumber);
        var state = new State
        {
            StateIdentifier = (byte[])marker.StateIdentifier.Clone(),
            Generation = 1,
            SerialNumber = (byte[])legacy.SerialNumber.Clone(),
            LastIssuedUtc = legacy.LastIssuedUtc
        };

        // Stage an authenticated OTS2 record before publishing its key-bearing marker.
        // If migration is interrupted, either the authoritative OTS1 active file remains,
        // or the marker can authenticate this staged copy and finish the migration.
        WriteAtomicFile(migrationPath, migrationTemporaryPath, SerializeState(state, marker), null);
        PersistMarker(marker);
        PersistStateCopies(state, marker);
        TryDelete(migrationPath);
        TryDelete(migrationTemporaryPath);
    }

    private DurableState LoadDurableState(MarkerSelection markerSelection)
    {
        List<StateCandidate> candidates = new();
        AddStateCandidate(candidates, path, markerSelection.Marker);
        AddStateCandidate(candidates, backupPath, markerSelection.Marker);
        AddStateCandidate(candidates, temporaryPath, markerSelection.Marker);
        AddStateCandidate(candidates, backupTemporaryPath, markerSelection.Marker);
        AddStateCandidate(candidates, migrationPath, markerSelection.Marker);
        AddStateCandidate(candidates, migrationTemporaryPath, markerSelection.Marker);

        State selected;
        if (candidates.Count == 0)
        {
            if (markerSelection.Marker.Generation != 0 || !markerSelection.CanReconstructInitialState)
            {
                throw new IssuanceStateException(
                    "All timestamp state copies are older than the last committed sequence.");
            }

            // A published active generation-zero marker, or its sole flushed staging file,
            // proves no serial has yet been returned. A generation-zero backup may precede
            // a lost issued generation-one state and must never reconstruct the serial seed.
            selected = new State
            {
                StateIdentifier = (byte[])markerSelection.Marker.StateIdentifier.Clone(),
                Generation = 0,
                SerialNumber = (byte[])markerSelection.Marker.InitialSerialNumber.Clone(),
                LastIssuedUtc = DateTime.MinValue
            };
        }
        else
        {
            var maximumGeneration = candidates.Max(item => item.State.Generation);
            selected = candidates.First(item => item.State.Generation == maximumGeneration).State;
            foreach (var candidate in candidates.Where(item => item.State.Generation == maximumGeneration))
            {
                if (!StatesEqual(selected, candidate.State))
                {
                    throw new IssuanceStateException(
                        "Timestamp state contains conflicting records with the same sequence number.");
                }
            }
        }

        var markerGeneration = markerSelection.Marker.Generation;
        if (selected.Generation < markerGeneration)
        {
            throw new IssuanceStateException(
                "Timestamp state was restored to an older sequence than the last committed value.");
        }

        if (selected.Generation > markerGeneration && selected.Generation - markerGeneration > 1)
        {
            throw new IssuanceStateException(
                "Timestamp state is too far ahead of its last committed sequence.");
        }

        if (selected.Generation == markerGeneration && !markerSelection.HasAuthoritativeMarker)
        {
            throw new IssuanceStateException(
                "A backup integrity file exists without matching timestamp state; current state cannot be verified.");
        }

        var activeMatches = candidates.Any(item =>
            string.Equals(item.Path, path, StringComparison.OrdinalIgnoreCase) && StatesEqual(item.State, selected));
        var backupMatches = candidates.Any(item =>
            string.Equals(item.Path, backupPath, StringComparison.OrdinalIgnoreCase) && StatesEqual(item.State, selected));
        var requiresRepair = selected.Generation != markerGeneration ||
                             !markerSelection.CurrentMatchesSelected ||
                             !markerSelection.MirroredBackupMatchesSelected ||
                             !activeMatches ||
                             !backupMatches;
        return new DurableState(selected, requiresRepair);
    }

    private bool TryReadFullyMirroredState(
        out MarkerSelection markerSelection,
        out DurableState durableState)
    {
        markerSelection = null;
        durableState = null;
        if (File.Exists(temporaryPath) || File.Exists(backupTemporaryPath) ||
            File.Exists(markerTemporaryPath) || File.Exists(migrationPath) ||
            File.Exists(migrationTemporaryPath) ||
            !File.Exists(markerPath) || !File.Exists(markerBackupPath) ||
            !File.Exists(path) || !File.Exists(backupPath))
        {
            return false;
        }

        try
        {
            var currentMarker = ReadMarker(markerPath, out var currentIsMirrored);
            var backupMarker = ReadMarker(markerBackupPath, out var backupIsMirrored);
            if (currentIsMirrored || !backupIsMirrored || !MarkersEqual(currentMarker, backupMarker)) return false;

            var currentState = ReadState(path, currentMarker);
            var backupState = ReadState(backupPath, currentMarker);
            if (!StatesEqual(currentState, backupState) || currentState.Generation != currentMarker.Generation)
            {
                return false;
            }

            markerSelection = new MarkerSelection(currentMarker, true, false, true, true);
            durableState = new DurableState(currentState, false);
            return true;
        }
        catch (CorruptPersistentRecordException)
        {
            return false;
        }
    }

    private void RepairState(State state, Marker marker)
    {
        PersistStateCopies(state, marker);
        marker.Generation = state.Generation;
        PersistMarker(marker);
    }

    private MarkerSelection ReadBestMarker()
    {
        List<MarkerCandidate> candidates = new();
        AddMarkerCandidate(candidates, markerPath);
        AddMarkerCandidate(candidates, markerBackupPath);
        AddMarkerCandidate(candidates, markerTemporaryPath);

        if (candidates.Count == 0)
        {
            if (HasAnyMarkerEvidence())
            {
                throw new IssuanceStateException("No valid timestamp-state integrity file remains.");
            }

            return null;
        }

        var identity = candidates[0].Marker;
        foreach (var candidate in candidates)
        {
            if (!FixedEquals(identity.StateIdentifier, candidate.Marker.StateIdentifier) ||
                !FixedEquals(identity.IntegrityKey, candidate.Marker.IntegrityKey) ||
                !FixedEquals(identity.InitialSerialNumber, candidate.Marker.InitialSerialNumber))
            {
                throw new IssuanceStateException("Conflicting timestamp-state integrity files were found.");
            }
        }

        var maximumGeneration = candidates.Max(item => item.Marker.Generation);
        var selected = candidates.First(item => item.Marker.Generation == maximumGeneration).Marker;
        var currentMatches = candidates.Any(item =>
            string.Equals(item.Path, markerPath, StringComparison.OrdinalIgnoreCase) &&
            !item.IsMirroredMarker &&
            MarkersEqual(item.Marker, selected));
        var temporaryMatches = candidates.Any(item =>
            string.Equals(item.Path, markerTemporaryPath, StringComparison.OrdinalIgnoreCase) &&
            !item.IsMirroredMarker &&
            MarkersEqual(item.Marker, selected));
        var mirroredBackupMatches = candidates.Any(item =>
            item.IsMirroredMarker &&
            (string.Equals(item.Path, markerBackupPath, StringComparison.OrdinalIgnoreCase) ||
             string.Equals(item.Path, markerTemporaryPath, StringComparison.OrdinalIgnoreCase)) &&
            MarkersEqual(item.Marker, selected));
        var canReconstructInitialState = currentMatches ||
                                          mirroredBackupMatches ||
                                          (temporaryMatches && !File.Exists(markerPath) &&
                                           !File.Exists(markerBackupPath) && !HasAnyStateEvidence());
        return new MarkerSelection(
            selected,
            currentMatches,
            temporaryMatches,
            mirroredBackupMatches,
            canReconstructInitialState);
    }

    private void AddMarkerCandidate(ICollection<MarkerCandidate> candidates, string candidatePath)
    {
        if (!File.Exists(candidatePath)) return;
        try
        {
            var marker = ReadMarker(candidatePath, out var isMirroredMarker);
            candidates.Add(new MarkerCandidate(candidatePath, marker, isMirroredMarker));
        }
        catch (CorruptPersistentRecordException)
        {
            // A valid redundant marker may recover an independently corrupted copy.
        }
    }

    private void AddStateCandidate(ICollection<StateCandidate> candidates, string candidatePath, Marker marker)
    {
        if (!File.Exists(candidatePath)) return;
        try
        {
            candidates.Add(new StateCandidate(candidatePath, ReadState(candidatePath, marker)));
        }
        catch (CorruptPersistentRecordException)
        {
            // A valid same-or-newer redundant state may recover an independently corrupted copy.
        }
    }

    private Marker ReadMarker(string candidatePath, out bool isMirroredMarker)
    {
        var encoded = ReadExactRecord(candidatePath, MarkerRecordLength, "integrity marker");
        isMirroredMarker = HasMagic(encoded, MirroredMarkerMagic);
        if (!isMirroredMarker && !HasMagic(encoded, MarkerMagic))
        {
            throw new CorruptPersistentRecordException("The timestamp-state integrity file has an invalid header.");
        }

        var payload = Slice(encoded, 0, MarkerPayloadLength);
        var storedIntegrity = Slice(encoded, MarkerPayloadLength, IntegrityLength);
        if (!FixedEquals(storedIntegrity, Cryptography.WindowsHash.ComputeSha256(payload)))
        {
            throw new CorruptPersistentRecordException("The timestamp-state integrity file failed its checksum validation.");
        }

        using MemoryStream stream = new(payload, false);
        using BinaryReader reader = new(stream, Encoding.UTF8, false);
        reader.ReadBytes(MarkerMagic.Length);
        var stateIdentifier = reader.ReadBytes(StateIdentifierLength);
        var integrityKey = reader.ReadBytes(IntegrityKeyLength);
        var generation = reader.ReadUInt64();
        var initialSerial = reader.ReadBytes(SerialLength);
        if (IsZero(stateIdentifier) || IsZero(integrityKey) || IsZero(initialSerial))
        {
            throw new CorruptPersistentRecordException("The timestamp-state integrity file contains an invalid zero value.");
        }

        return new Marker
        {
            StateIdentifier = stateIdentifier,
            IntegrityKey = integrityKey,
            Generation = generation,
            InitialSerialNumber = initialSerial
        };
    }

    private State ReadState(string candidatePath, Marker marker)
    {
        var encoded = ReadExactRecord(candidatePath, StateRecordLength, "state record");
        if (!HasMagic(encoded, StateMagic))
        {
            throw new CorruptPersistentRecordException("The timestamp state file has an invalid header.");
        }

        var payload = Slice(encoded, 0, StatePayloadLength);
        var storedIntegrity = Slice(encoded, StatePayloadLength, IntegrityLength);
        if (!FixedEquals(storedIntegrity, ComputeStateIntegrity(marker.IntegrityKey, payload)))
        {
            throw new CorruptPersistentRecordException("The timestamp state file failed its integrity check.");
        }

        using MemoryStream stream = new(payload, false);
        using BinaryReader reader = new(stream, Encoding.UTF8, false);
        reader.ReadBytes(StateMagic.Length);
        var stateIdentifier = reader.ReadBytes(StateIdentifierLength);
        var generation = reader.ReadUInt64();
        var serial = reader.ReadBytes(SerialLength);
        var ticks = reader.ReadInt64();
        if (!FixedEquals(stateIdentifier, marker.StateIdentifier) || IsZero(serial) ||
            ticks is < 0 || ticks > DateTime.MaxValue.Ticks)
        {
            throw new CorruptPersistentRecordException("The timestamp state file contains invalid values.");
        }

        if (generation == 0 &&
            (!FixedEquals(serial, marker.InitialSerialNumber) || ticks != 0))
        {
            throw new CorruptPersistentRecordException(
                "The initial timestamp state does not match its integrity file.");
        }

        return new State
        {
            StateIdentifier = stateIdentifier,
            Generation = generation,
            SerialNumber = serial,
            LastIssuedUtc = ticks == 0 ? DateTime.MinValue : new DateTime(ticks, DateTimeKind.Utc)
        };
    }

    private LegacyState ReadLegacyState(string candidatePath)
    {
        var encoded = ReadExactRecord(candidatePath, LegacyRecordLength, "legacy state record");
        if (!HasMagic(encoded, LegacyMagic))
        {
            throw new IssuanceStateException(
                "The existing timestamp state is not a supported OTS1 or OTS2 format.");
        }

        using MemoryStream stream = new(encoded, false);
        using BinaryReader reader = new(stream, Encoding.UTF8, false);
        reader.ReadBytes(LegacyMagic.Length);
        var serial = reader.ReadBytes(SerialLength);
        var ticks = reader.ReadInt64();
        if (IsZero(serial) || ticks is < 0 || ticks > DateTime.MaxValue.Ticks)
        {
            throw new IssuanceStateException("Legacy timestamp state is corrupt and cannot be migrated.");
        }

        return new LegacyState
        {
            SerialNumber = serial,
            LastIssuedUtc = ticks == 0 ? DateTime.MinValue : new DateTime(ticks, DateTimeKind.Utc)
        };
    }

    private void PersistStateCopies(State state, Marker marker)
    {
        var encoded = SerializeState(state, marker);

        // Flush a complete sibling file, atomically publish it, and then mirror the
        // identical committed generation to the recovery copy before returning.
        WriteAtomicFile(path, temporaryPath, encoded, backupPath);
        WriteAtomicFile(backupPath, backupTemporaryPath, encoded, null);
    }

    private void PersistMarker(Marker marker)
    {
        // First publish the normal high-water marker. Then create a distinct, same-generation
        // committed mirror. The separate header lets recovery distinguish this mirror from an
        // older OTSM replacement backup left by a crash between these two atomic operations.
        WriteAtomicFile(
            markerPath,
            markerTemporaryPath,
            SerializeMarker(marker, MarkerMagic),
            markerBackupPath);
        WriteAtomicFile(
            markerBackupPath,
            markerTemporaryPath,
            SerializeMarker(marker, MirroredMarkerMagic),
            null);
    }

    private static byte[] SerializeState(State state, Marker marker)
    {
        byte[] payload;
        using (MemoryStream stream = new(StatePayloadLength))
        {
            using BinaryWriter writer = new(stream, Encoding.UTF8, true);
            writer.Write(StateMagic);
            writer.Write(state.StateIdentifier);
            writer.Write(state.Generation);
            writer.Write(state.SerialNumber);
            writer.Write(state.LastIssuedUtc == DateTime.MinValue ? 0L : state.LastIssuedUtc.Ticks);
            writer.Flush();
            payload = stream.ToArray();
        }

        var result = new byte[StateRecordLength];
        Buffer.BlockCopy(payload, 0, result, 0, payload.Length);
        var integrity = ComputeStateIntegrity(marker.IntegrityKey, payload);
        Buffer.BlockCopy(integrity, 0, result, payload.Length, integrity.Length);
        return result;
    }

    private static byte[] SerializeMarker(Marker marker, byte[] magic)
    {
        byte[] payload;
        using (MemoryStream stream = new(MarkerPayloadLength))
        {
            using BinaryWriter writer = new(stream, Encoding.UTF8, true);
            writer.Write(magic);
            writer.Write(marker.StateIdentifier);
            writer.Write(marker.IntegrityKey);
            writer.Write(marker.Generation);
            writer.Write(marker.InitialSerialNumber);
            writer.Flush();
            payload = stream.ToArray();
        }

        var result = new byte[MarkerRecordLength];
        Buffer.BlockCopy(payload, 0, result, 0, payload.Length);
        var integrity = Cryptography.WindowsHash.ComputeSha256(payload);
        Buffer.BlockCopy(integrity, 0, result, payload.Length, integrity.Length);
        return result;
    }

    private static byte[] ComputeStateIntegrity(byte[] integrityKey, byte[] payload)
    {
        // Construct standard HMAC-SHA-256 with the service's Windows CNG SHA-256 primitive.
        // HMACSHA256 uses SHA256Managed on .NET Framework and is rejected when FIPS policy is enforced.
        const int blockLength = 64;
        var innerInput = new byte[blockLength + payload.Length];
        var outerInput = new byte[blockLength + IntegrityLength];
        for (var index = 0; index < blockLength; index++)
        {
            var keyByte = index < integrityKey.Length ? integrityKey[index] : (byte)0;
            innerInput[index] = (byte)(keyByte ^ 0x36);
            outerInput[index] = (byte)(keyByte ^ 0x5c);
        }

        Buffer.BlockCopy(payload, 0, innerInput, blockLength, payload.Length);
        var innerDigest = Cryptography.WindowsHash.ComputeSha256(innerInput);
        Buffer.BlockCopy(innerDigest, 0, outerInput, blockLength, innerDigest.Length);
        return Cryptography.WindowsHash.ComputeSha256(outerInput);
    }

    private static void WriteAtomicFile(
        string destination,
        string temporary,
        byte[] encoded,
        string replacementBackup)
    {
        using (FileStream stream = new(
                   temporary,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None,
                   4096,
                   FileOptions.WriteThrough))
        {
            stream.Write(encoded, 0, encoded.Length);
            stream.Flush(true);
        }

        if (File.Exists(destination))
        {
            File.Replace(temporary, destination, replacementBackup, true);
        }
        else
        {
            File.Move(temporary, destination);
        }
    }

    private static byte[] ReadExactRecord(string candidatePath, int expectedLength, string description)
    {
        try
        {
            using FileStream stream = new(candidatePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length != expectedLength)
            {
                throw new CorruptPersistentRecordException(
                    string.Format(CultureInfo.InvariantCulture, "The timestamp {0} has an invalid length.", description));
            }

            var result = new byte[expectedLength];
            var position = 0;
            while (position < result.Length)
            {
                var read = stream.Read(result, position, result.Length - position);
                if (read == 0)
                {
                    throw new CorruptPersistentRecordException(
                        string.Format(CultureInfo.InvariantCulture, "The timestamp {0} is truncated.", description));
                }

                position += read;
            }

            return result;
        }
        catch (CorruptPersistentRecordException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new IssuanceStateException(
                string.Format(CultureInfo.InvariantCulture, "The timestamp {0} could not be read.", description),
                ex);
        }
    }

    private static Marker CreateMarker(ulong generation, byte[] initialSerial)
    {
        var stateIdentifier = new byte[StateIdentifierLength];
        var integrityKey = new byte[IntegrityKeyLength];
        using RandomNumberGenerator random = RandomNumberGenerator.Create();
        random.GetBytes(stateIdentifier);
        random.GetBytes(integrityKey);
        if (IsZero(stateIdentifier)) stateIdentifier[stateIdentifier.Length - 1] = 1;
        if (IsZero(integrityKey)) integrityKey[integrityKey.Length - 1] = 1;
        return new Marker
        {
            StateIdentifier = stateIdentifier,
            IntegrityKey = integrityKey,
            Generation = generation,
            InitialSerialNumber = (byte[])initialSerial.Clone()
        };
    }

    private static byte[] CreateSerialSeed()
    {
        // Seed a positive 128-bit serial so independent installations start in unrelated spaces.
        var serial = new byte[SerialLength];
        using RandomNumberGenerator random = RandomNumberGenerator.Create();
        random.GetBytes(serial);
        serial[0] &= 0x7f;
        if (IsZero(serial)) serial[SerialLength - 1] = 1;
        return serial;
    }

    private bool HasAnyStateEvidence() =>
        PersistentStatePaths().Any(File.Exists);

    private bool HasAnyMarkerEvidence() =>
        MarkerPaths().Any(File.Exists);

    private IEnumerable<string> PersistentStatePaths()
    {
        yield return path;
        yield return backupPath;
        yield return temporaryPath;
        yield return backupTemporaryPath;
        yield return migrationPath;
        yield return migrationTemporaryPath;
    }

    private IEnumerable<string> MarkerPaths()
    {
        yield return markerPath;
        yield return markerBackupPath;
        yield return markerTemporaryPath;
    }

    private IEnumerable<string> PersistentArtifactPaths() =>
        PersistentStatePaths().Concat(MarkerPaths());

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

    private static void Increment(byte[] value)
    {
        for (var index = value.Length - 1; index >= 0; index--)
        {
            value[index]++;
            if (value[index] != 0) return;
        }

        throw new IssuanceStateException("The timestamp serial-number space has been exhausted.");
    }

    private static bool StatesEqual(State left, State right) =>
        left.Generation == right.Generation &&
        left.LastIssuedUtc.Ticks == right.LastIssuedUtc.Ticks &&
        FixedEquals(left.StateIdentifier, right.StateIdentifier) &&
        FixedEquals(left.SerialNumber, right.SerialNumber);

    private static bool MarkersEqual(Marker left, Marker right) =>
        left.Generation == right.Generation &&
        FixedEquals(left.StateIdentifier, right.StateIdentifier) &&
        FixedEquals(left.IntegrityKey, right.IntegrityKey) &&
        FixedEquals(left.InitialSerialNumber, right.InitialSerialNumber);

    private static bool HasMagic(byte[] value, byte[] magic)
    {
        if (value.Length < magic.Length) return false;
        var aggregate = 0;
        for (var index = 0; index < magic.Length; index++) aggregate |= value[index] ^ magic[index];
        return aggregate == 0;
    }

    private static byte[] Slice(byte[] value, int offset, int length)
    {
        var result = new byte[length];
        Buffer.BlockCopy(value, offset, result, 0, length);
        return result;
    }

    private static bool IsZero(byte[] value)
    {
        var aggregate = 0;
        foreach (var item in value) aggregate |= item;
        return aggregate == 0;
    }

    private static bool FixedEquals(byte[] left, byte[] right) =>
        Cryptography.WindowsHash.FixedTimeEquals(left, right);

    private static bool IsStorageException(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or CryptographicException;

    private static void TryDelete(string candidatePath)
    {
        try
        {
            if (File.Exists(candidatePath)) File.Delete(candidatePath);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private T ExecuteLocked<T>(TimeSpan wait, Func<T> action)
    {
        using var storeLock = AcquireLock(wait);
        return action();
    }

    private T ExecuteLocked<T>(TimeSpan wait, CancellationToken cancellationToken, Func<T> action)
    {
        using var storeLock = AcquireLock(wait, cancellationToken);
        return action();
    }

    private FileStream AcquireLock(TimeSpan wait) => AcquireLock(wait, CancellationToken.None);

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
        catch (IssuanceStateException)
        {
            throw;
        }
        catch (Exception ex) when (IsStorageException(ex))
        {
            throw new IssuanceStateException(
                "OpenTimeStamp could not lock timestamp state. Verify the data directory permissions.", ex);
        }
    }

    private void ExecuteLocked(TimeSpan wait, Action action)
    {
        ExecuteLocked<object>(wait, () =>
        {
            action();
            return null;
        });
    }

    private sealed class State
    {
        public byte[] StateIdentifier { get; set; }

        public ulong Generation { get; set; }

        public byte[] SerialNumber { get; set; }

        public DateTime LastIssuedUtc { get; set; }
    }

    private sealed class Marker
    {
        public byte[] StateIdentifier { get; set; }

        public byte[] IntegrityKey { get; set; }

        public ulong Generation { get; set; }

        public byte[] InitialSerialNumber { get; set; }
    }

    private sealed class LegacyState
    {
        public byte[] SerialNumber { get; set; }

        public DateTime LastIssuedUtc { get; set; }
    }

    private sealed class DurableState
    {
        public DurableState(State state, bool requiresRepair)
        {
            State = state;
            RequiresRepair = requiresRepair;
        }

        public State State { get; }

        public bool RequiresRepair { get; }
    }

    private sealed class StateCandidate
    {
        public StateCandidate(string path, State state)
        {
            Path = path;
            State = state;
        }

        public string Path { get; }

        public State State { get; }
    }

    private sealed class MarkerCandidate
    {
        public MarkerCandidate(string path, Marker marker, bool isMirroredMarker)
        {
            Path = path;
            Marker = marker;
            IsMirroredMarker = isMirroredMarker;
        }

        public string Path { get; }

        public Marker Marker { get; }

        public bool IsMirroredMarker { get; }
    }

    private sealed class MarkerSelection
    {
        public MarkerSelection(
            Marker marker,
            bool currentMatchesSelected,
            bool temporaryMatchesSelected,
            bool mirroredBackupMatchesSelected,
            bool canReconstructInitialState)
        {
            Marker = marker;
            CurrentMatchesSelected = currentMatchesSelected;
            TemporaryMatchesSelected = temporaryMatchesSelected;
            MirroredBackupMatchesSelected = mirroredBackupMatchesSelected;
            CanReconstructInitialState = canReconstructInitialState;
        }

        public Marker Marker { get; }

        public bool CurrentMatchesSelected { get; }

        public bool TemporaryMatchesSelected { get; }

        public bool MirroredBackupMatchesSelected { get; }

        public bool CanReconstructInitialState { get; }

        public bool HasAuthoritativeMarker =>
            CurrentMatchesSelected || TemporaryMatchesSelected || MirroredBackupMatchesSelected;
    }

    private sealed class CorruptPersistentRecordException : IssuanceStateException
    {
        public CorruptPersistentRecordException(string message)
            : base(message)
        {
        }
    }
}

public class IssuanceStateException : Exception
{
    public IssuanceStateException(string message)
        : base(message)
    {
    }

    public IssuanceStateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class ClockRollbackException : IssuanceStateException
{
    public ClockRollbackException(string message)
        : base(message)
    {
    }
}
