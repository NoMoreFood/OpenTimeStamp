using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Xml;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Infrastructure;

namespace OpenTimeStamp.Configuration;

public sealed class ConfigurationStore
{
    private const int MaximumConfigurationBytes = 1048576;
    private const string MissingGeneration = "missing";

    private readonly string path;
    private readonly string lockPath;

    public ConfigurationStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A settings file path is required.", nameof(path));
        }

        this.path = System.IO.Path.GetFullPath(path);
        lockPath = this.path + ".lock";
    }

    public string Path => path;

    public ServiceConfiguration Load() => Load(out _);

    public ServiceConfiguration Load(out string generation)
    {
        // Read and hash the same bytes while holding the writer lock. File length
        // and timestamps are not reliable generations after a same-size replace.
        using var storeLock = AcquireLock(TimeSpan.FromSeconds(10));
        var loaded = LoadFromDisk(out generation);
        Normalize(loaded);
        var errors = loaded.Validate();
        if (errors.Count != 0)
        {
            throw new ConfigurationErrorsException("The saved settings are invalid: " + string.Join(" ", errors));
        }

        return loaded;
    }

    public string GetGeneration()
    {
        using var storeLock = AcquireLock(TimeSpan.FromSeconds(10));
        return ReadGeneration();
    }

    public void Save(ServiceConfiguration configuration) =>
        SaveCore(configuration, null, false);

    public string Save(ServiceConfiguration configuration, string expectedGeneration)
    {
        if (string.IsNullOrWhiteSpace(expectedGeneration))
        {
            throw new ArgumentException("The expected settings version is required.", nameof(expectedGeneration));
        }

        return SaveCore(configuration, expectedGeneration, true);
    }

    private string SaveCore(ServiceConfiguration configuration, string expectedGeneration, bool compareGeneration)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        // Validate and serialize before taking the cross-process lock so malformed
        // candidates cannot block readers or another worker process.
        var copy = configuration.Clone();
        Normalize(copy);
        var errors = copy.Validate();
        if (errors.Count != 0) throw new ConfigurationErrorsException(string.Join(" ", errors));

        byte[] serialized;
        try
        {
            serialized = Serialize(copy);
        }
        catch (Exception ex) when (ex is SerializationException or XmlException or ArgumentException)
        {
            throw new ConfigurationErrorsException("OpenTimeStamp could not encode the settings file.", ex);
        }

        var newGeneration = ComputeGeneration(serialized);
        using var storeLock = AcquireLock(TimeSpan.FromSeconds(10));
        if (compareGeneration)
        {
            var currentGeneration = ReadGeneration();
            if (!string.Equals(currentGeneration, expectedGeneration, StringComparison.Ordinal))
            {
                throw new ConfigurationConflictException(
                    "Another administrator saved changes after this page loaded. Refresh the page, review the " +
                    "latest settings, and save again.");
            }
        }

        var directory = System.IO.Path.GetDirectoryName(path);
        Directory.CreateDirectory(directory);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            // A unique sibling prevents workers from trampling each other's
            // staging file. Flush data before the atomic replace/move.
            using (FileStream stream = new(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(serialized, 0, serialized.Length);
                stream.Flush(true);
            }

            if (File.Exists(path))
            {
                File.Replace(temporary, path, path + ".bak", true);
            }
            else
            {
                File.Move(temporary, path);
            }
        }
        finally
        {
            try
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                // The active configuration is already atomic. A uniquely
                // named abandoned staging file is safe to clean later.
            }
        }

        // Do not perform a fallible cache or metadata refresh after the commit.
        // Reporting an error here would falsely imply the new file is inactive.
        return newGeneration;
    }

    private ServiceConfiguration LoadFromDisk(out string generation)
    {
        if (!File.Exists(path))
        {
            generation = MissingGeneration;
            return new ServiceConfiguration();
        }

        try
        {
            var bytes = ReadConfigurationBytes();
            generation = ComputeGeneration(bytes);
            var configuration = Deserialize(bytes);
            if (configuration is null)
            {
                throw new ConfigurationErrorsException("The settings file is empty or does not contain valid settings.");
            }

            return configuration;
        }
        catch (ConfigurationErrorsException)
        {
            throw;
        }
        catch (Exception ex) when (ex is SerializationException or XmlException or IOException or
                                   UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new ConfigurationErrorsException(
                "OpenTimeStamp could not read the settings file. Verify the file permissions and XML contents.", ex);
        }
    }

    private string ReadGeneration()
    {
        if (!File.Exists(path)) return MissingGeneration;

        try
        {
            return ComputeGeneration(ReadConfigurationBytes());
        }
        catch (ConfigurationErrorsException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new ConfigurationErrorsException(
                "OpenTimeStamp could not read the settings version. Verify the settings file permissions.", ex);
        }
    }

    private byte[] ReadConfigurationBytes()
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 0 or > MaximumConfigurationBytes)
        {
            throw new ConfigurationErrorsException("The settings file is larger than 1 MiB.");
        }

        var bytes = new byte[(int)stream.Length];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read == 0) throw new EndOfStreamException("The settings file changed while it was being read. Try again.");
            offset += read;
        }

        return bytes;
    }

    private static ServiceConfiguration Deserialize(byte[] bytes)
    {
        DataContractSerializer serializer = new(typeof(ServiceConfiguration));
        XmlReaderSettings settings = new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using MemoryStream stream = new(bytes, false);
        using XmlReader reader = XmlReader.Create(stream, settings);
        reader.MoveToContent();
        var nil = reader.GetAttribute("nil", "http://www.w3.org/2001/XMLSchema-instance");
        if (string.Equals(nil, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(nil, "1", StringComparison.Ordinal))
        {
            throw new ConfigurationErrorsException("The settings file is empty or does not contain valid settings.");
        }

        return (ServiceConfiguration)serializer.ReadObject(reader);
    }

    private static byte[] Serialize(ServiceConfiguration configuration)
    {
        DataContractSerializer serializer = new(typeof(ServiceConfiguration));
        XmlWriterSettings settings = new()
        {
            Encoding = new UTF8Encoding(false),
            Indent = true,
            OmitXmlDeclaration = false,
            CloseOutput = false
        };
        using MemoryStream stream = new();
        using (XmlWriter writer = XmlWriter.Create(stream, settings))
        {
            serializer.WriteObject(writer, configuration);
        }

        if (stream.Length > MaximumConfigurationBytes)
        {
            throw new ConfigurationErrorsException("The settings file would be larger than 1 MiB.");
        }

        return stream.ToArray();
    }

    private FileStream AcquireLock(TimeSpan wait)
    {
        try
        {
            return FileSystemLock.Acquire(
                lockPath,
                wait,
                contention => new ConfigurationErrorsException(
                    "Another OpenTimeStamp process is updating settings. Try again shortly.",
                    contention),
                CancellationToken.None);
        }
        catch (ConfigurationErrorsException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException)
        {
            throw new ConfigurationErrorsException(
                "OpenTimeStamp could not lock the settings file. Verify the file permissions.", ex);
        }
    }

    private static string ComputeGeneration(byte[] bytes) =>
        "sha256:" + BitConverter.ToString(WindowsHash.ComputeSha256(bytes)).Replace("-", string.Empty).ToLowerInvariant();

    private static void Normalize(ServiceConfiguration configuration)
    {
        // Canonical values keep validation and later ordinal comparisons deterministic.
        configuration.AuthenticationMode = (configuration.AuthenticationMode ?? "Anonymous").Trim();
        configuration.CertificateStoreLocation = (configuration.CertificateStoreLocation ?? "LocalMachine").Trim();
        configuration.CertificateStoreName = (configuration.CertificateStoreName ?? "My").Trim();
        configuration.CertificateThumbprint = NormalizeThumbprint(configuration.CertificateThumbprint);
        configuration.CertificateSelectionMode = (configuration.CertificateSelectionMode ??
            ServiceConfiguration.ManualCertificateSelection).Trim();
        configuration.DefaultPolicyOid = NormalizeOptional(configuration.DefaultPolicyOid);
        configuration.AcceptedPolicyOids = NormalizeList(configuration.AcceptedPolicyOids, false);
        configuration.AllowedHashAlgorithms = NormalizeList(configuration.AllowedHashAlgorithms, true);
        configuration.SigningDigestAlgorithm = HashAlgorithmCatalog.NormalizeName(configuration.SigningDigestAlgorithm);
        configuration.LogRolloverInterval = (configuration.LogRolloverInterval ??
            ServiceConfiguration.DailyLogRollover).Trim();
        configuration.AdminAllowedWindowsGroups = NormalizeList(configuration.AdminAllowedWindowsGroups, false);
    }

    public static string NormalizeThumbprint(string value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : value.Replace(" ", string.Empty).Replace("\u200e", string.Empty).ToUpperInvariant();

    private static string NormalizeOptional(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static List<string> NormalizeList(IEnumerable<string> values, bool normalizeHashes)
    {
        List<string> result = new();
        if (values is null) return result;

        foreach (var value in values)
        {
            var normalized = normalizeHashes ? HashAlgorithmCatalog.NormalizeName(value) : NormalizeOptional(value);
            if (!string.IsNullOrWhiteSpace(normalized) && !result.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(normalized);
            }
        }

        return result;
    }

}

public class ConfigurationErrorsException : Exception
{
    public ConfigurationErrorsException(string message)
        : base(message)
    {
    }

    public ConfigurationErrorsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class ConfigurationConflictException : ConfigurationErrorsException
{
    public ConfigurationConflictException(string message)
        : base(message)
    {
    }
}
