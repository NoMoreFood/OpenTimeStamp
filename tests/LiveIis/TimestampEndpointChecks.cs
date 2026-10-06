using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OpenTimeStamp.Asn1;

// Standalone qualification uses the supported framework's networking and cryptography compatibility defaults.
[assembly: TargetFramework(".NETFramework,Version=v4.8")]

namespace OpenTimeStamp.LiveIis;

internal static class TimestampEndpointChecks
{
    // Exercise actual IIS applications and independently verify their cryptographic responses with OpenSSL.
    private static readonly (string Name, string Oid, int Length)[] Hashes =
    [
        ("MD5", "1.2.840.113549.2.5", 16), ("SHA1", "1.3.14.3.2.26", 20),
        ("SHA224", "2.16.840.1.101.3.4.2.4", 28), ("SHA256", "2.16.840.1.101.3.4.2.1", 32),
        ("SHA384", "2.16.840.1.101.3.4.2.2", 48), ("SHA512", "2.16.840.1.101.3.4.2.3", 64)
    ];
    private static readonly List<CheckResult> Results = [];
    private static readonly HashSet<string> Serials = new(StringComparer.Ordinal);
    private static EndpointManifest manifest;
    private static string outputDirectory;

    private static int Main(string[] arguments)
    {
        try
        {
            // Load the explicit VM manifest before making any network request.
            if (arguments.Length != 2) throw new ArgumentException("Supply a manifest and a new evidence directory.");
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(File.ReadAllText(arguments[0]))))
                manifest = (EndpointManifest)new DataContractJsonSerializer(typeof(EndpointManifest))
                    .ReadObject(stream);
            outputDirectory = Path.GetFullPath(arguments[1]);
            Directory.CreateDirectory(outputDirectory);
            ServicePointManager.DefaultConnectionLimit = 64;

            // Require explicit loopback targets so the qualification harness cannot reach production services.
            if (manifest?.Profiles is null || manifest.Profiles.Length == 0)
                throw new InvalidOperationException("No live IIS profiles were supplied.");
            if (!string.IsNullOrWhiteSpace(manifest.CertificateRequestFile))
                Check("Documented machine enrollment request", VerifyCertificateRequest);

            // Qualify each application's configuration and protocol contracts before testing shared load.
            foreach (var profile in manifest.Profiles)
            {
                var uri = new Uri(profile.BaseUrl, UriKind.Absolute);
                if (!uri.IsLoopback || uri.UserInfo.Length != 0 || uri.Query.Length != 0 ||
                    uri.Fragment.Length != 0)
                    throw new InvalidOperationException(
                        "Live IIS qualification requires explicit loopback application URLs.");
                Check(profile.Name + " readiness", () => VerifyReadiness(profile));
                VerifyProfile(profile);
            }

            // Send simultaneous requests to different applications and verify every granted receipt after the burst.
            Check("Concurrent endpoint isolation", VerifyConcurrentRequests);

            // Return failure when any independently recorded workflow failed.
            SaveResults();
            Console.WriteLine("Live IIS checks: " + Results.Count(result => result.Passed) + " passed, " +
                Results.Count(result => !result.Passed) + " failed.");
            return Results.All(result => result.Passed) ? 0 : 1;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static void VerifyProfile(EndpointProfile profile)
    {
        // Use a real data digest, fresh nonce, both AlgorithmIdentifier forms, and both certificate-request choices.
        foreach (var hash in Hashes)
        {
            foreach (var includeCertificate in new[] { true, false })
            {
                var name = profile.Name + " " + hash.Name +
                    (includeCertificate ? " certificates/NULL" : " no certificates/absent");
                Check(name, () =>
                {
                    var digest = CreateDigest(hash.Name, hash.Length);
                    var nonce = CreateNonce();
                    var request = CreateRequest(hash.Oid, digest, nonce, null, includeCertificate, includeCertificate);
                    var response = Send(profile, "/timestamp/rfc3161", "POST", request, "application/timestamp-query");
                    var expectedFailure = ExpectedFailure(profile, hash.Name);
                    if (expectedFailure.HasValue) VerifyRejection(response, expectedFailure.Value);
                    else VerifyGranted(profile, response, request, hash.Oid, digest, nonce, includeCertificate);
                });
            }
        }

        // Protocol errors must remain bounded, standards-compliant replies instead of unusable success responses.
        Check(profile.Name + " unknown hash", () => VerifyRejection(SendRfc(profile,
            CreateRequest("2.16.840.1.101.3.4.2.8", new byte[32], CreateNonce())), 0));
        Check(profile.Name + " wrong digest length", () => VerifyRejection(SendRfc(profile,
            CreateRequest(Hashes[3].Oid, new byte[31], CreateNonce())), 0));
        Check(profile.Name + " malformed DER", () => VerifyRejection(SendRfc(profile, [0x30, 0x01, 0xff]), 5));
        Check(profile.Name + " policy isolation", () => VerifyRejection(SendRfc(profile,
            CreateRequest(Hashes[3].Oid, new byte[32], CreateNonce(), "1.3.6.1.4.1.55555.999")), 15));

        // Verify HTTP routing, media types, size bounds, and the Windows-authentication boundary through IIS.
        Check(profile.Name + " HTTP method", () =>
            Require(Send(profile, "/timestamp/rfc3161", "GET").Status == 405));
        Check(profile.Name + " HTTP media type", () => Require(Send(profile, "/timestamp/rfc3161", "POST",
            [1], "application/octet-stream").Status == 415));
        Check(profile.Name + " HTTP body limit", () => Require(Send(profile, "/timestamp/rfc3161", "POST",
            new byte[65537], "application/timestamp-query").Status == 413));
        Check(profile.Name + " no protocol sniffing", () => Require(Send(profile, "/timestamp", "POST",
            [1], "application/timestamp-query").Status == 404));
        if (profile.WindowsAuthentication)
            Check(profile.Name + " anonymous denied", () => Require(Send(profile, "/health", "GET",
                authenticate: false).Status == 401));

        // Legacy requests contain a signature rather than an independently selected RFC message-imprint hash.
        Check(profile.Name + " Authenticode endpoint", () => VerifyAuthenticode(profile));
        if (!manifest.FipsEnabled && !profile.WindowsAuthentication)
        {
            Check(profile.Name + " native RFC 3161 signing", () => VerifyNativeSigning(profile, false));
            if (profile.AuthenticodeEnabled)
            {
                Check(profile.Name + " native legacy signing", () => VerifyNativeSigning(profile, true));

                // PowerShell's native timestamp transport is exercised only on an explicit compatibility URL.
                if (!string.IsNullOrWhiteSpace(profile.NativeClientBaseUrl) &&
                    new Uri(profile.NativeClientBaseUrl).Scheme == "http")
                    Check(profile.Name + " PowerShell legacy signing", () => VerifyPowerShellSigning(profile));
            }
        }
    }

    private static int? ExpectedFailure(EndpointProfile profile, string hashName)
    {
        // Request policy takes precedence over an unavailable CMS signer in the RFC rejection contract.
        if (!profile.AllowedHashes.Contains(hashName, StringComparer.Ordinal) ||
            (manifest.FipsEnabled && hashName is "MD5" or "SHA1")) return 0;
        return manifest.FipsEnabled && profile.SigningHash == "SHA1" ? 25 : null;
    }

    private static void VerifyReadiness(EndpointProfile profile)
    {
        // Health covers every enabled protocol, including legacy routes disabled by effective Windows FIPS policy.
        var timer = Stopwatch.StartNew();
        var expectedStatus = manifest.FipsEnabled &&
            (profile.SigningHash == "SHA1" || profile.AuthenticodeEnabled) ? 503 : 200;
        while (true)
        {
            var response = Send(profile, "/health", "GET");
            if (response.Status == expectedStatus)
            {
                Require(Encoding.UTF8.GetString(response.Body).Contains(
                    "\"fipsPolicy\":" + (manifest.FipsEnabled ? "true" : "false")),
                    "Unexpected effective FIPS policy.");
                Console.WriteLine(profile.Name + " readiness: " + timer.ElapsedMilliseconds + " ms");
                return;
            }

            // Permit bounded cold-start refreshes without accepting a permanently wrong health result.
            if (timer.Elapsed > TimeSpan.FromSeconds(45)) throw new InvalidOperationException("Readiness timed out.");
            Thread.Sleep(500);
        }
    }

    private static void VerifyGranted(EndpointProfile profile, HttpResult response, byte[] request,
        string hashOid, byte[] digest, byte[] nonce, bool includeCertificate, bool recordSerial = true)
    {
        // Reject malformed success envelopes before attempting CMS or independent native verification.
        Require(response.Status == 200 && response.ContentType == "application/timestamp-reply",
            "Invalid RFC response.");
        var outer = new DerReader(response.Body);
        var reply = outer.ReadSequence();
        var status = reply.ReadSequence();
        Require(status.ReadIntegerInt32() == 0, "The timestamp was not granted.");
        status.ThrowIfNotEmpty();
        var token = reply.ReadEncodedValue();
        reply.ThrowIfNotEmpty();
        outer.ThrowIfNotEmpty();

        // Verify the actual CMS signer, signature digest, certificate flag, and authenticated ESS attribute.
        using var certificate = new X509Certificate2(profile.CertificateFile);
        SignedCms cms = new();
        cms.Decode(token);
        cms.CheckSignature(new X509Certificate2Collection(certificate), true);
        Require(cms.SignerInfos.Count == 1 && cms.ContentInfo.ContentType.Value == "1.2.840.113549.1.9.16.1.4");
        var signingOid = Hashes.Single(hash => hash.Name == profile.SigningHash).Oid;
        Require(cms.SignerInfos[0].DigestAlgorithm.Value == signingOid, "The endpoint used another signing digest.");
        Require(includeCertificate ? cms.Certificates.Cast<X509Certificate2>().Any(item =>
            item.Thumbprint == certificate.Thumbprint) : cms.Certificates.Count == 0, "Wrong certificate inclusion.");
        var essOid = profile.SigningHash == "SHA1"
            ? "1.2.840.113549.1.9.16.2.12" : "1.2.840.113549.1.9.16.2.47";
        Require(cms.SignerInfos[0].SignedAttributes.Cast<CryptographicAttributeObject>().Any(item =>
            item.Oid.Value == essOid));

        // Compare the returned policy, original AlgorithmIdentifier, imprint, nonce, serial, and time.
        var info = new DerReader(cms.ContentInfo.Content).ReadSequence();
        Require(info.ReadIntegerInt32() == 1 && info.ReadObjectIdentifier() == profile.PolicyOid,
            "Wrong endpoint policy.");
        var imprint = info.ReadSequence();
        var encodedAlgorithm = imprint.ReadEncodedValue();
        var algorithm = new DerReader(encodedAlgorithm).ReadSequence();
        Require(algorithm.ReadObjectIdentifier() == hashOid && imprint.ReadOctetString().SequenceEqual(digest));

        // Preserve the original algorithm encoding and check that issuance identities and time remain fresh.
        var requestReader = new DerReader(request).ReadSequence();
        requestReader.ReadIntegerInt32();
        Require(encodedAlgorithm.SequenceEqual(requestReader.ReadSequence().ReadEncodedValue()));
        var serial = Convert.ToBase64String(info.ReadPositiveInteger());
        if (recordSerial) Require(Serials.Add(profile.Name + ":" + serial), "A timestamp serial was reused.");
        var encodedTime = info.ReadEncodedValue();
        var time = DateTime.ParseExact(Encoding.ASCII.GetString(encodedTime, 2, encodedTime.Length - 2),
            ["yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss.FFFFFFF'Z'"], CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        Require(Math.Abs((DateTime.UtcNow - time).TotalSeconds) < 60, "The timestamp time is stale.");
        Require(info.ReadPositiveInteger().SequenceEqual(nonce), "The nonce was changed.");
        info.ThrowIfNotEmpty();
        imprint.ThrowIfNotEmpty();

        // OpenSSL checks the signature, ESS binding, TSA purpose, chain, and every field represented by the query.
        var prefix = Path.Combine(outputDirectory, Guid.NewGuid().ToString("N"));
        File.WriteAllBytes(prefix + ".tsq", request);
        File.WriteAllBytes(prefix + ".tsr", response.Body);
        RunProcess(manifest.OpenSslPath, "ts", "-verify", "-queryfile", prefix + ".tsq", "-in", prefix + ".tsr",
            "-CAfile", profile.CertificatePemFile, "-untrusted", profile.CertificatePemFile);
        Require(!string.IsNullOrWhiteSpace(response.CorrelationId), "The response has no diagnostic identity.");
    }

    private static void VerifyRejection(HttpResult response, int failureBit)
    {
        // Decode the server's protocol rejection and require the precise failure category with no issued token.
        Require(response.Status == 200 && response.ContentType == "application/timestamp-reply");
        var outer = new DerReader(response.Body);
        var reply = outer.ReadSequence();
        var status = reply.ReadSequence();
        Require(status.ReadIntegerInt32() == 2, "A protocol rejection must carry PKI status 2.");
        if (status.PeekTag() == 0x30) status.ReadEncodedValue();
        var bits = status.ReadEncodedValue();
        Require(bits[0] == 0x03 && bits.Length > 3 + failureBit / 8 &&
            (bits[3 + failureBit / 8] & (0x80 >> (failureBit % 8))) != 0, "Wrong protocol failure bit.");
        status.ThrowIfNotEmpty();
        reply.ThrowIfNotEmpty();
        outer.ThrowIfNotEmpty();
    }

    private static void VerifyAuthenticode(EndpointProfile profile)
    {
        // Build the Windows legacy timestamp request around fresh signature bytes.
        var signature = CreateNonce();
        DerWriter writer = new();
        writer.WriteSequence(request =>
        {
            request.WriteObjectIdentifier("1.3.6.1.4.1.311.3.2.1");
            request.WriteSequence(content =>
            {
                content.WriteObjectIdentifier("1.2.840.113549.1.7.1");
                content.WriteContextSpecificConstructed(0, value => value.WriteOctetString(signature));
            });
        });

        // Match the legacy HTTP envelope used by SignTool and PowerShell, then verify the signed signature bytes.
        var response = Send(profile, "/timestamp/authenticode", "POST",
            Encoding.ASCII.GetBytes(Convert.ToBase64String(writer.Encode())), "application/octet-stream");
        if (!profile.AuthenticodeEnabled || manifest.FipsEnabled)
        {
            Require(response.Status == (!profile.AuthenticodeEnabled ? 404 : 503));
            return;
        }

        // Check that the reply belongs to the intended endpoint's signer and preserves the client's signature.
        Require(response.Status == 200 && response.ContentType == "application/octet-stream");
        SignedCms cms = new();
        cms.Decode(Convert.FromBase64String(Encoding.ASCII.GetString(response.Body)));
        using var certificate = new X509Certificate2(profile.CertificateFile);
        cms.CheckSignature(new X509Certificate2Collection(certificate), true);
        Require(cms.ContentInfo.Content.SequenceEqual(signature));
        Require(cms.SignerInfos[0].Certificate.Thumbprint == certificate.Thumbprint);
        Require(cms.SignerInfos[0].DigestAlgorithm.Value ==
            Hashes.Single(hash => hash.Name == profile.SigningHash).Oid);
    }

    private static void VerifyNativeSigning(EndpointProfile profile, bool legacy)
    {
        // Sign a disposable executable with Windows SDK SignTool and require Windows to validate its timestamp.
        var path = Path.Combine(outputDirectory, profile.Name + (legacy ? "-legacy.exe" : "-rfc3161.exe"));
        File.Copy(typeof(TimestampEndpointChecks).Assembly.Location, path, false);
        var arguments = new List<string>
        {
            "sign", "/sm", "/s", "My", "/sha1", manifest.SigningCertificateThumbprint, "/fd", "SHA256"
        };

        // Select the actual client's supported transport while keeping the server's protocol route explicit.
        var clientBaseUrl = string.IsNullOrWhiteSpace(profile.NativeClientBaseUrl)
            ? profile.BaseUrl : profile.NativeClientBaseUrl;
        Require(new Uri(clientBaseUrl, UriKind.Absolute).IsLoopback, "Native signing requires a loopback URL.");
        if (legacy) arguments.AddRange(["/t", clientBaseUrl + "/timestamp/authenticode"]);
        else arguments.AddRange(["/tr", clientBaseUrl + "/timestamp/rfc3161", "/td", "SHA256"]);
        arguments.Add(path);
        RunProcess(manifest.SignToolPath, [.. arguments]);
        RunProcess(manifest.SignToolPath, "verify", "/pa", "/all", "/tw", path);
    }

    private static void VerifyConcurrentRequests()
    {
        // Release all callers together so admission control and separate IIS application identities are exercised.
        using var start = new ManualResetEventSlim();
        var profiles = manifest.Profiles.Where(profile => ExpectedFailure(profile, "SHA256") is null).ToArray();
        var requests = profiles.SelectMany(profile => Enumerable.Range(0, 8).Select(index =>
        {
            var digest = Enumerable.Repeat((byte)index, 32).ToArray();
            var nonce = CreateNonce();
            var request = CreateRequest(Hashes[3].Oid, digest, nonce);
            return Task.Run(() =>
            {
                start.Wait();
                return (Profile: profile, Response: SendRfc(profile, request), Request: request,
                    Digest: digest, Nonce: nonce);
            });
        })).ToArray();
        start.Set();
        Require(Task.WaitAll(requests, TimeSpan.FromSeconds(45)), "The concurrent requests stalled.");

        // A capacity rejection must be explicit and retryable; successful replies must retain endpoint identity.
        foreach (var task in requests)
        {
            var result = task.Result;
            if (result.Response.Status == 503)
                Require(result.Response.RetryAfter == "5", "A busy response lacked its retry hint.");
            else VerifyGranted(result.Profile, result.Response, result.Request, Hashes[3].Oid,
                result.Digest, result.Nonce, true);
        }

        // Require progress from each usable profile while permitting the configured capacity bound.
        foreach (var profile in profiles)
            Require(requests.Any(task => task.Result.Profile == profile && task.Result.Response.Status == 200),
                "An endpoint made no progress during the burst.");
        Console.WriteLine("Concurrent requests: " + requests.Count(task => task.Result.Response.Status == 200) +
            " granted, " + requests.Count(task => task.Result.Response.Status == 503) + " busy.");
    }

    private static void VerifyPowerShellSigning(EndpointProfile profile)
    {
        // Use PowerShell's native signing API, whose timestamp transport requires a separate HTTP legacy URL.
        var baseUri = new Uri(profile.NativeClientBaseUrl, UriKind.Absolute);
        Require(baseUri.IsLoopback && baseUri.Scheme == "http", "The PowerShell fixture URL must use loopback HTTP.");
        var path = Path.Combine(outputDirectory, profile.Name + "-signed.ps1");
        File.WriteAllText(path, "'Timestamp endpoint qualification'\r\n", new UTF8Encoding(true));
        var command = "$ErrorActionPreference = 'Stop'; $certificate = Get-Item -LiteralPath " +
            "'Cert:\\LocalMachine\\My\\" + manifest.SigningCertificateThumbprint +
            "'; $signature = Set-AuthenticodeSignature -LiteralPath '" +
            path.Replace("'", "''") + "' -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer '" +
            (profile.NativeClientBaseUrl + "/timestamp/authenticode").Replace("'", "''") + "'; " +
            "[pscustomobject]@{Status=[string]$signature.Status; " +
            "TsaThumbprint=$signature.TimeStamperCertificate.Thumbprint} | ConvertTo-Json -Compress";

        // Inspect Windows' trust decision and compare the native timestamp certificate with the configured TSA.
        var output = RunProcess(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell\\v1.0\\powershell.exe"),
            "-NoProfile", "-NonInteractive", "-Command", command);
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(output));
        var receipt = (PowerShellReceipt)new DataContractJsonSerializer(typeof(PowerShellReceipt)).ReadObject(stream);
        using var tsa = new X509Certificate2(profile.CertificateFile);
        Require(receipt.Status == "Valid" && receipt.TsaThumbprint == tsa.Thumbprint,
            "PowerShell did not validate the intended legacy timestamp.");
        RunProcess(manifest.SignToolPath, "verify", "/pa", "/all", "/tw", path);
    }

    private static void VerifyCertificateRequest()
    {
        // Inspect the real PKCS #10 request generated by certreq from the documented INF, without a CA mock.
        var output = RunProcess(manifest.OpenSslPath, "req", "-in", manifest.CertificateRequestFile, "-text", "-noout");
        Require(output.Contains("Public-Key: (3072 bit)") &&
            output.Contains("X509v3 Extended Key Usage: critical") && output.Contains("Time Stamping") &&
            output.Contains("X509v3 Basic Constraints: critical") && output.Contains("CA:FALSE") &&
            output.Contains("sha256WithRSAEncryption"), "The documented request profile is incorrect.");
    }

    private static byte[] CreateDigest(string hashName, int length)
    {
        // Hash real fixture bytes independently of the server's algorithm and DER implementation.
        var prefix = Path.Combine(outputDirectory, Guid.NewGuid().ToString("N"));
        File.WriteAllText(prefix + ".data", "OpenTimeStamp live IIS qualification " + prefix, Encoding.UTF8);
        RunProcess(manifest.OpenSslPath, "dgst", "-" + hashName.ToLowerInvariant(), "-binary",
            "-out", prefix + ".hash", prefix + ".data");
        var digest = File.ReadAllBytes(prefix + ".hash");
        Require(digest.Length == length, "OpenSSL returned an unexpected digest size.");
        return digest;
    }

    private static byte[] CreateNonce()
    {
        // Generate a positive nonce that can distinguish live replies from a stale or mismatched receipt.
        var nonce = new byte[16];
        using (var random = RandomNumberGenerator.Create()) random.GetBytes(nonce);
        nonce[0] |= 1;
        return nonce;
    }

    private static byte[] CreateRequest(string hashOid, byte[] digest, byte[] nonce, string policy = null,
        bool includeCertificate = true, bool nullParameters = true)
    {
        // Encode both supported AlgorithmIdentifier forms and independently vary certificate inclusion.
        DerWriter writer = new();
        writer.WriteSequence(request =>
        {
            request.WriteInteger(1);
            request.WriteSequence(imprint =>
            {
                imprint.WriteSequence(algorithm =>
                {
                    algorithm.WriteObjectIdentifier(hashOid);
                    if (nullParameters) algorithm.WriteNull();
                });
                imprint.WriteOctetString(digest);
            });

            // Preserve the requested scope and bind each response to an independently generated nonce.
            if (policy != null) request.WriteObjectIdentifier(policy);
            request.WritePositiveInteger(nonce);
            if (includeCertificate) request.WriteBoolean(true);
        });
        return writer.Encode();
    }

    private static HttpResult SendRfc(EndpointProfile profile, byte[] body) =>
        Send(profile, "/timestamp/rfc3161", "POST", body, "application/timestamp-query");

    private static HttpResult Send(EndpointProfile profile, string path, string method, byte[] body = null,
        string contentType = null, bool authenticate = true)
    {
        // Keep request and native I/O deadlines finite; consume error responses so their protocol body is checked.
        var request = (HttpWebRequest)WebRequest.Create(profile.BaseUrl + path);
        request.Method = method;
        request.Timeout = 20000;
        request.ReadWriteTimeout = 20000;
        request.AllowAutoRedirect = false;
        request.UseDefaultCredentials = authenticate && profile.WindowsAuthentication;
        if (body != null)
        {
            request.ContentType = contentType;
            request.ContentLength = body.Length;
            using var stream = request.GetRequestStream();
            stream.Write(body, 0, body.Length);
        }


        // Keep HTTP failures available to assertions instead of discarding their status, body, or retry hints.
        HttpWebResponse response;
        try { response = (HttpWebResponse)request.GetResponse(); }
        catch (WebException exception) when (exception.Response != null)
        {
            response = (HttpWebResponse)exception.Response;
        }
        using (response)
        using (var stream = new MemoryStream())
        {
            response.GetResponseStream().CopyTo(stream);
            return new HttpResult((int)response.StatusCode, response.ContentType, stream.ToArray(),
                response.Headers["X-Correlation-ID"], response.Headers["Retry-After"]);
        }
    }

    private static string RunProcess(string executable, params string[] arguments)
    {
        // Launch only an explicit native test tool without a command shell or unbounded redirected-pipe waits.
        var information = new ProcessStartInfo(executable, string.Join(" ", arguments.Select(argument =>
            "\"" + argument.Replace("\"", "\\\"") + "\"")))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        using var process = Process.Start(information);
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(20000))
        {
            process.Kill();
            throw new TimeoutException("The native signing or verification tool timed out.");
        }

        // Bound redirected output completion and retain native diagnostics when a tool rejects the workflow.
        Require(Task.WaitAll([stdout, stderr], TimeSpan.FromSeconds(5)), "Native output pipes did not close.");
        if (process.ExitCode != 0)
            throw new InvalidOperationException(Path.GetFileName(executable) + ": " + stdout.Result + stderr.Result);
        return stdout.Result;
    }

    private static void Check(string name, Action action)
    {
        // Record each workflow independently so one failure does not hide the remaining endpoint coverage.
        var timer = Stopwatch.StartNew();
        try
        {
            action();
            Results.Add(new CheckResult
            {
                Name = name, Passed = true, DurationMilliseconds = timer.ElapsedMilliseconds
            });
        }
        catch (Exception exception)
        {
            Results.Add(new CheckResult
            {
                Name = name, Detail = exception.ToString(), DurationMilliseconds = timer.ElapsedMilliseconds
            });
        }

        // Emit progress and preserve the result immediately for bounded VM orchestration.
        Console.WriteLine((Results.Last().Passed ? "PASS " : "FAIL ") + name);
        SaveResults();
    }

    private static void SaveResults()
    {
        // Persist progress after every observable workflow so a stalled or interrupted VM run remains diagnosable.
        using var stream = File.Create(Path.Combine(outputDirectory, "results.json"));
        new DataContractJsonSerializer(typeof(List<CheckResult>)).WriteObject(stream, Results);
    }

    private static void Require(bool condition,
        string message = "The live endpoint did not satisfy the expected contract.")
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class HttpResult(int status, string contentType, byte[] body,
        string correlationId, string retryAfter)
    {
        // Preserve the observed HTTP contract as managed data before the response is disposed.
        internal int Status { get; } = status;
        internal string ContentType { get; } = contentType;
        internal byte[] Body { get; } = body;
        internal string CorrelationId { get; } = correlationId;
        internal string RetryAfter { get; } = retryAfter;
    }
}

// Manifests describe already configured disposable applications; the verifier does not change server settings.
[DataContract]
internal sealed class EndpointManifest
{
    [DataMember] public bool FipsEnabled { get; set; }
    [DataMember] public string OpenSslPath { get; set; }
    [DataMember] public string SignToolPath { get; set; }
    [DataMember] public string SigningCertificateThumbprint { get; set; }
    [DataMember] public string CertificateRequestFile { get; set; }
    [DataMember] public EndpointProfile[] Profiles { get; set; }
}

[DataContract]
internal sealed class EndpointProfile
{
    // Keep profile policy and certificate identity separate from the application's two client transports.
    [DataMember] public string Name { get; set; }
    [DataMember] public string BaseUrl { get; set; }
    [DataMember] public string NativeClientBaseUrl { get; set; }
    [DataMember] public string SigningHash { get; set; }
    [DataMember] public string PolicyOid { get; set; }
    [DataMember] public string CertificateFile { get; set; }
    [DataMember] public string CertificatePemFile { get; set; }
    [DataMember] public string[] AllowedHashes { get; set; }
    [DataMember] public bool AuthenticodeEnabled { get; set; }
    [DataMember] public bool WindowsAuthentication { get; set; }
}

[DataContract]
internal sealed class CheckResult
{
    // Evidence includes timing and failure diagnostics for the actual workflow rather than only its final exit code.
    [DataMember] public string Name { get; set; }
    [DataMember] public bool Passed { get; set; }
    [DataMember] public long DurationMilliseconds { get; set; }
    [DataMember] public string Detail { get; set; }
}

// The native PowerShell receipt preserves both Windows trust status and the actual timestamp signer identity.
[DataContract]
internal sealed class PowerShellReceipt
{
    [DataMember] public string Status { get; set; }
    [DataMember] public string TsaThumbprint { get; set; }
}
