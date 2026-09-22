using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Issuance;
using OpenTimeStamp.Protocols;
using OpenTimeStamp.Web.Infrastructure;

namespace OpenTimeStamp.Web.Handlers;

internal enum TimestampProtocol
{
    Rfc3161,
    Authenticode
}

internal sealed class TimestampAdmissionController : IDisposable
{
    private readonly AdmissionTier bodyIntake;
    private readonly AdmissionTier processing;

    internal TimestampAdmissionController(
        int bodyIntakeLimit,
        int processingLimit,
        int? perClientBodyIntakeLimit = null,
        int? perClientProcessingLimit = null,
        string admissionScopeName = null)
    {
        if (bodyIntakeLimit <= 0) throw new ArgumentOutOfRangeException(nameof(bodyIntakeLimit));
        if (processingLimit <= 0) throw new ArgumentOutOfRangeException(nameof(processingLimit));
        if (perClientBodyIntakeLimit.HasValue &&
            (perClientBodyIntakeLimit.Value <= 0 || perClientBodyIntakeLimit.Value > bodyIntakeLimit))
            throw new ArgumentOutOfRangeException(nameof(perClientBodyIntakeLimit));
        if (perClientProcessingLimit.HasValue &&
            (perClientProcessingLimit.Value <= 0 || perClientProcessingLimit.Value > processingLimit))
            throw new ArgumentOutOfRangeException(nameof(perClientProcessingLimit));
        var createdBodyIntake = new AdmissionTier(
            bodyIntakeLimit,
            perClientBodyIntakeLimit ?? bodyIntakeLimit,
            admissionScopeName,
            "body");
        try
        {
            processing = new AdmissionTier(
                processingLimit,
                perClientProcessingLimit ?? processingLimit,
                admissionScopeName,
                "processing");
            bodyIntake = createdBodyIntake;
        }
        catch
        {
            createdBodyIntake.Dispose();
            throw;
        }
    }

    internal IDisposable TryEnterBodyIntake(string clientKey = "<unknown>") => bodyIntake.TryEnter(clientKey);

    internal IDisposable TryEnterProcessing(string clientKey = "<unknown>") => processing.TryEnter(clientKey);

    internal int ActiveBodyClientCount => bodyIntake.ActiveClientCount;

    internal int ActiveProcessingClientCount => processing.ActiveClientCount;

    public void Dispose()
    {
        bodyIntake.Dispose();
        processing.Dispose();
    }

    private sealed class AdmissionTier : IDisposable
    {
        private readonly Dictionary<string, int> activeClients = new(StringComparer.Ordinal);
        private readonly object clientSync = new();
        private readonly SemaphoreSlim localGate;
        private readonly int perClientLimit;
        private readonly Semaphore sharedGate;
        private readonly string sharedPeerNamePrefix;

        internal AdmissionTier(int globalLimit, int perClientLimit, string sharedScopeName, string name)
        {
            this.perClientLimit = perClientLimit;
            if (string.IsNullOrWhiteSpace(sharedScopeName))
            {
                localGate = new SemaphoreSlim(globalLimit, globalLimit);
                return;
            }

            sharedGate = new Semaphore(globalLimit, globalLimit, sharedScopeName + "-" + name);
            sharedPeerNamePrefix = sharedScopeName + "-" + name + "-peer-";
        }

        internal int ActiveClientCount
        {
            get
            {
                lock (clientSync) return activeClients.Count;
            }
        }

        internal IDisposable TryEnter(string clientKey)
        {
            clientKey = string.IsNullOrWhiteSpace(clientKey) ? "<unknown>" : clientKey;
            if (!TryEnterGlobal()) return null;
            if (sharedGate != null) return TryEnterSharedClient(clientKey);

            try
            {
                lock (clientSync)
                {
                    activeClients.TryGetValue(clientKey, out var active);
                    if (active >= perClientLimit)
                    {
                        ReleaseGlobal();
                        return null;
                    }

                    activeClients[clientKey] = active + 1;
                }
            }
            catch
            {
                ReleaseGlobal();
                throw;
            }

            return new AdmissionLease(() => ReleaseClient(clientKey));
        }

        public void Dispose()
        {
            localGate?.Dispose();
            sharedGate?.Dispose();
        }

        private IDisposable TryEnterSharedClient(string clientKey)
        {
            Semaphore client = null;
            try
            {
                // A peer gate exists only while its globally admitted request is active,
                // bounding named kernel objects while enforcing limits across workers.
                var digest = WindowsHash.ComputeSha256(Encoding.UTF8.GetBytes(clientKey));
                var name = sharedPeerNamePrefix + HttpSupport.ToHex(digest).Substring(0, 32);
                client = new Semaphore(perClientLimit, perClientLimit, name);
                if (!client.WaitOne(0))
                {
                    client.Dispose();
                    ReleaseGlobal();
                    return null;
                }

                return new AdmissionLease(() =>
                {
                    try
                    {
                        client.Release();
                    }
                    finally
                    {
                        client.Dispose();
                        ReleaseGlobal();
                    }
                });
            }
            catch
            {
                client?.Dispose();
                ReleaseGlobal();
                throw;
            }
        }

        private void ReleaseClient(string clientKey)
        {
            lock (clientSync)
            {
                if (!activeClients.TryGetValue(clientKey, out var active))
                    throw new InvalidOperationException("An admission lease was released without an active client.");

                if (active == 1)
                    activeClients.Remove(clientKey);
                else
                    activeClients[clientKey] = active - 1;
            }

            ReleaseGlobal();
        }

        private bool TryEnterGlobal() => sharedGate?.WaitOne(0) ?? localGate.Wait(0);

        private void ReleaseGlobal()
        {
            if (sharedGate != null)
                sharedGate.Release();
            else
                localGate.Release();
        }
    }

    private sealed class AdmissionLease(Action release) : IDisposable
    {
        private Action heldRelease = release;

        public void Dispose()
        {
            Interlocked.Exchange(ref heldRelease, null)?.Invoke();
        }
    }
}

internal sealed class TimestampHandler(TimestampProtocol protocol) : HttpTaskAsyncHandler
{
    private static readonly Lazy<TimestampAdmissionController> Admission = new(() => new TimestampAdmissionController(
        ServiceRuntime.Settings.BodyIntakeLimit,
        ServiceRuntime.Settings.ProcessingLimit,
        ServiceRuntime.Settings.BodyIntakePerClientLimit,
        ServiceRuntime.Settings.ProcessingPerClientLimit,
        ServiceRuntime.AdmissionScopeName));

    public override bool IsReusable => false;

    internal static void InitializeAdmission() => _ = Admission.Value;

    internal static void ShutdownAdmission()
    {
        if (Admission.IsValueCreated) Admission.Value.Dispose();
    }

    public override async Task ProcessRequestAsync(HttpContext context)
    {
        // Establish a response trace before enforcing endpoint-wide preconditions.
        var correlationId = Guid.NewGuid().ToString("N");
        context.Response.Headers["X-Correlation-ID"] = correlationId;
        context.ThreadAbortOnTimeout = false;
        var stopwatch = Stopwatch.StartNew();
        ServiceConfiguration configuration = null;
        ServiceRuntimeSnapshot snapshot = null;
        RequestIdentity identity = null;
        var clientKey = HttpSupport.GetRemoteAddressKey(context.Request);
        using var admissions = new RequestAdmissions(clientKey);
        using var requestCancellation = CreateRequestCancellation(context);

        try
        {
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Headers["Allow"] = "POST";
                HttpSupport.WritePlainError(context, 405, "Timestamp requests must use POST.");
                return;
            }

            if (context.Request.QueryString.Count != 0)
            {
                HttpSupport.WritePlainError(context, 400, "Query parameters are not accepted.");
                return;
            }

            var contentEncoding = context.Request.Headers["Content-Encoding"];
            if (!string.IsNullOrWhiteSpace(contentEncoding) &&
                !string.Equals(contentEncoding, "identity", StringComparison.OrdinalIgnoreCase))
            {
                HttpSupport.WritePlainError(context, 415, "Compressed request bodies are not accepted.");
                return;
            }

            var expectedMediaType = protocol == TimestampProtocol.Rfc3161
                ? "application/timestamp-query"
                : "application/octet-stream";
            if (!HttpSupport.HasExactMediaType(context.Request, expectedMediaType))
            {
                var message = protocol == TimestampProtocol.Rfc3161
                    ? "RFC 3161 requests require application/timestamp-query."
                    : "Authenticode timestamp requests require application/octet-stream.";
                HttpSupport.WritePlainError(context, 415, message);
                return;
            }

            requestCancellation.Token.ThrowIfCancellationRequested();
            snapshot = ServiceRuntime.LoadSnapshot();
            configuration = snapshot.Configuration;
            requestCancellation.Token.ThrowIfCancellationRequested();
            identity = HttpSupport.GetRequestIdentity(context.Request);
            if (string.Equals(configuration.AuthenticationMode, "Windows", StringComparison.OrdinalIgnoreCase) &&
                !identity.IsAuthenticated)
            {
                if (!TryEnterProcessing(context, admissions)) return;
                WriteAudit(configuration, identity, context, correlationId, stopwatch, "rejected",
                    "Windows authentication is required.", null, null, null, null, null);
                context.Response.Headers["WWW-Authenticate"] = "Negotiate";
                HttpSupport.WritePlainError(context, 401, "Windows authentication is required.");
                return;
            }

            if (protocol == TimestampProtocol.Rfc3161 && !configuration.Rfc3161Enabled)
            {
                HttpSupport.WritePlainError(context, 404, "RFC 3161 timestamping is disabled.");
                return;
            }

            if (protocol == TimestampProtocol.Authenticode && !configuration.AuthenticodeEnabled)
            {
                HttpSupport.WritePlainError(context, 404, "Legacy Authenticode timestamping is disabled.");
                return;
            }

            if (protocol == TimestampProtocol.Authenticode && snapshot.FipsEnabled)
            {
                HttpSupport.WritePlainError(context, 503,
                    "Legacy Authenticode timestamping is disabled while Windows FIPS mode is enabled.");
                return;
            }

            // Bound slow body intake without consuming one of the scarcer signing
            // and durable-audit slots. Excess requests are rejected synchronously.
            admissions.Body = Admission.Value.TryEnterBodyIntake(clientKey);
            if (admissions.Body is null)
            {
                context.Response.Headers["Retry-After"] = "5";
                HttpSupport.WritePlainError(context, 503, "The timestamp service is busy. Retry later.");
                return;
            }

            // Dispatch a validated HTTP request to its protocol-specific processor.
            if (protocol == TimestampProtocol.Rfc3161)
                await ProcessRfc3161(context, snapshot, identity, correlationId, stopwatch, admissions,
                    requestCancellation.Token);
            else
                await ProcessAuthenticode(context, snapshot, identity, correlationId, stopwatch, admissions,
                    requestCancellation.Token);
        }
        catch (OperationCanceledException)
        {
            admissions.ReleaseBody();
            if (IsClientDisconnected(context)) return;
            BestEffortAuditBounded(configuration, identity, context, correlationId, stopwatch,
                "rejected", "The server request deadline expired.", admissions.HasProcessing);
            HttpSupport.WritePlainError(
                context,
                408,
                "The timestamp request did not complete before the server deadline.");
        }
        catch (Exception ex) when ((ex is HttpException or IOException or ObjectDisposedException) &&
                                   IsClientDisconnected(context))
        {
            admissions.ReleaseBody();
        }
        catch (AuditLogException)
        {
            admissions.ReleaseBody();
            HttpSupport.WritePlainError(
                context,
                503,
                "Timestamping stopped because the audit log cannot be written.");
        }
        catch (RequestBodyException ex)
        {
            admissions.ReleaseBody();
            BestEffortAuditBounded(configuration, identity, context, correlationId, stopwatch,
                "rejected", ex.Message, admissions.HasProcessing);
            if (!ex.ConnectionAborted)
                HttpSupport.WritePlainError(context, ex.StatusCode, ex.Message);
        }
        catch (AuthenticodeProtocolException ex)
        {
            admissions.ReleaseBody();
            BestEffortAuditBounded(configuration, identity, context, correlationId, stopwatch,
                "rejected", ex.Message, admissions.HasProcessing);
            HttpSupport.WritePlainError(context, 400, ex.Message);
        }
        catch (ConfigurationErrorsException ex)
        {
            admissions.ReleaseBody();
            BestEffortAuditBounded(configuration, identity, context, correlationId, stopwatch,
                "error", ex.Message, admissions.HasProcessing);
            HttpSupport.WritePlainError(context, 503, "The timestamp service settings are unavailable.");
        }
        catch (Exception ex) when (ex is CryptographicException or CertificateSelectionException or
                                   UnauthorizedAccessException or InvalidOperationException or IssuanceStateException or
                                   IOException or System.Security.SecurityException)
        {
            admissions.ReleaseBody();
            BestEffortAuditBounded(configuration, identity, context, correlationId, stopwatch,
                "error", ex.Message, admissions.HasProcessing);
            HttpSupport.WritePlainError(context, 503, "The timestamp authority is temporarily unavailable.");
        }
    }

    private async Task ProcessRfc3161(
        HttpContext context,
        ServiceRuntimeSnapshot snapshot,
        RequestIdentity identity,
        string correlationId,
        Stopwatch stopwatch,
        RequestAdmissions admissions,
        CancellationToken cancellationToken)
    {
        var configuration = snapshot.Configuration;
        var request = await ReadBoundedBodyAsync(
            context.Request,
            configuration.MaxRequestBytes,
            admissions,
            cancellationToken);
        if (!TryEnterProcessing(context, admissions)) return;
        cancellationToken.ThrowIfCancellationRequested();

        Rfc3161Result result;
        Rfc3161Request parsedRequest;
        Rfc3161TimestampProcessor processor = new();
        try
        {
            parsedRequest = Rfc3161Request.Parse(request);
        }
        catch (Rfc3161ProtocolException)
        {
            // Produce the standard DER rejection without opening a certificate store
            // or invoking a private-key provider for malformed protocol input.
            result = processor.Process(
                request,
                configuration,
                null,
                null,
                DateTime.UtcNow,
                cancellationToken);
            WriteRfc3161Result(context, configuration, identity, correlationId, stopwatch, result);
            return;
        }

        if (!processor.TryPreflight(parsedRequest, configuration, out result))
        {
            WriteRfc3161Result(context, configuration, identity, correlationId, stopwatch, result);
            return;
        }
        cancellationToken.ThrowIfCancellationRequested();

        X509Certificate2 certificate = null;
        try
        {
            // Let the RFC processor encode a standards-compliant rejection when no key is selected.
            try
            {
                certificate = ServiceRuntime.GetSelectedCertificate(snapshot, cancellationToken);
            }
            catch (CertificateSelectionException)
            {
                certificate = null;
            }

            result = processor.Process(
                parsedRequest,
                configuration,
                certificate,
                ServiceRuntime.IssuanceState,
                () => DateTime.UtcNow,
                cancellationToken);

            WriteRfc3161Result(context, configuration, identity, correlationId, stopwatch, result);
        }
        finally
        {
            certificate?.Dispose();
        }
    }

    private async Task ProcessAuthenticode(
        HttpContext context,
        ServiceRuntimeSnapshot snapshot,
        RequestIdentity identity,
        string correlationId,
        Stopwatch stopwatch,
        RequestAdmissions admissions,
        CancellationToken cancellationToken)
    {
        var configuration = snapshot.Configuration;
        var encodedBody = await ReadBoundedBodyAsync(
            context.Request,
            configuration.MaxRequestBytes,
            admissions,
            cancellationToken);
        if (!TryEnterProcessing(context, admissions)) return;
        cancellationToken.ThrowIfCancellationRequested();
        var request = LegacyAuthenticodeHttpCodec.DecodeRequestBody(encodedBody);
        var signature = AuthenticodeTimestampProcessor.ParseRequest(request);

        using (var certificate = ServiceRuntime.GetSelectedCertificate(snapshot, cancellationToken))
        {
            AuthenticodeResult result;
            try
            {
                result = new AuthenticodeTimestampProcessor().ProcessParsedSignature(
                    signature,
                    configuration,
                    certificate,
                    ServiceRuntime.IssuanceState,
                    () => DateTime.UtcNow,
                    cancellationToken);
            }
            catch (AuthenticodeProtocolException ex)
            {
                WriteAudit(configuration, identity, context, correlationId, stopwatch,
                    "rejected", ex.Message, null, null, null, null, null);
                HttpSupport.WritePlainError(context, 400, ex.Message);
                return;
            }

            // Persist the issuance before returning the SignTool-compatible response envelope.
            WriteAudit(configuration, identity, context, correlationId, stopwatch, "granted", "granted", null,
                HashAlgorithmCatalog.FindByName(configuration.SigningDigestAlgorithm)?.Oid, null,
                result.AuditSerialNumber, result.CertificateThumbprint);
            var response = LegacyAuthenticodeHttpCodec.EncodeResponseBody(result.EncodedResponse);
            context.Response.StatusCode = 200;
            context.Response.TrySkipIisCustomErrors = true;
            context.Response.ContentType = "application/octet-stream";
            context.Response.OutputStream.Write(response, 0, response.Length);
        }
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(
        HttpRequest request,
        int maximumBytes,
        RequestAdmissions admissions,
        CancellationToken cancellationToken)
    {
        try
        {
            return await HttpSupport.ReadBoundedBodyAsync(
                request,
                maximumBytes,
                ServiceRuntime.Settings.BodyReadDeadline,
                cancellationToken);
        }
        finally
        {
            // A completed or rejected body read immediately returns its intake slot;
            // parsing, signing, and durable audit use the independent processing gate.
            admissions.ReleaseBody();
        }
    }

    private static bool TryEnterProcessing(HttpContext context, RequestAdmissions admissions)
    {
        admissions.Processing = Admission.Value.TryEnterProcessing(admissions.ClientKey);
        if (admissions.Processing != null) return true;

        context.Response.Headers["Retry-After"] = "5";
        HttpSupport.WritePlainError(context, 503, "The timestamp service is at processing capacity. Retry later.");
        return false;
    }

    private static CancellationTokenSource CreateRequestCancellation(HttpContext context)
    {
        var clientDisconnected = CancellationToken.None;
        try
        {
            clientDisconnected = context.Response.ClientDisconnectedToken;
        }
        catch (PlatformNotSupportedException)
        {
            // Older IIS hosting modes do not expose disconnect notifications.
        }

        return CancellationTokenSource.CreateLinkedTokenSource(context.Request.TimedOutToken, clientDisconnected);
    }

    private static bool IsClientDisconnected(HttpContext context)
    {
        try
        {
            return context.Response.ClientDisconnectedToken.IsCancellationRequested ||
                   !context.Response.IsClientConnected;
        }
        catch (HttpException)
        {
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    private void WriteRfc3161Result(
        HttpContext context,
        ServiceConfiguration configuration,
        RequestIdentity identity,
        string correlationId,
        Stopwatch stopwatch,
        Rfc3161Result result)
    {
        // Persist the outcome before returning the DER timestamp response.
        WriteAudit(configuration, identity, context, correlationId, stopwatch,
            result.Granted ? "granted" : "rejected", result.Detail, result.PolicyOid,
            result.HashAlgorithmOid, result.MessageImprint, result.SerialNumber, result.CertificateThumbprint);
        context.Response.StatusCode = 200;
        context.Response.TrySkipIisCustomErrors = true;
        context.Response.ContentType = "application/timestamp-reply";
        context.Response.OutputStream.Write(result.EncodedResponse, 0, result.EncodedResponse.Length);
    }

    private sealed class RequestAdmissions : IDisposable
    {
        private IDisposable body;
        private IDisposable processing;

        internal RequestAdmissions(string clientKey)
        {
            ClientKey = clientKey;
        }

        internal string ClientKey { get; }

        internal IDisposable Body
        {
            get => body;
            set => body = value;
        }

        internal IDisposable Processing
        {
            get => processing;
            set => processing = value;
        }

        internal bool HasProcessing => processing != null;

        internal void ReleaseBody() => Interlocked.Exchange(ref body, null)?.Dispose();

        public void Dispose()
        {
            Interlocked.Exchange(ref processing, null)?.Dispose();
            ReleaseBody();
        }
    }

    private void WriteAudit(
        ServiceConfiguration configuration,
        RequestIdentity identity,
        HttpContext context,
        string correlationId,
        Stopwatch stopwatch,
        string result,
        string detail,
        string policyOid,
        string hashOid,
        byte[] imprint,
        byte[] serial,
        string certificateThumbprint)
    {
        // Record protocol, caller, cryptographic, and latency context in one durable event.
        AuditRecord record = new()
        {
            TimestampUtc = DateTime.UtcNow,
            EventType = "timestamp",
            Result = result,
            CorrelationId = correlationId,
            Protocol = protocol == TimestampProtocol.Rfc3161 ? "rfc3161" : "authenticode",
            Username = identity?.Name,
            UserSid = identity?.Sid,
            AuthenticationType = identity?.AuthenticationType,
            RemoteAddress = context.Request.ServerVariables["REMOTE_ADDR"],
            PolicyOid = policyOid,
            HashAlgorithmOid = hashOid,
            MessageImprintHex = configuration.LogMessageImprints ? HttpSupport.ToHex(imprint) : null,
            SerialHex = HttpSupport.ToHex(serial),
            CertificateThumbprint = certificateThumbprint,
            DurationMilliseconds = stopwatch.ElapsedMilliseconds,
            Detail = detail
        };
        if (ServiceRuntime.Audit.Write(record, configuration.LogRolloverInterval, configuration.PruneAuditLogs,
                configuration.LogRetentionDays, configuration.FailClosedOnAuditError))
        {
            ServiceRuntime.TryRecordRecentRequest(record);
        }
    }

    private void BestEffortAudit(
        ServiceConfiguration configuration,
        RequestIdentity identity,
        HttpContext context,
        string correlationId,
        Stopwatch stopwatch,
        string result,
        string detail)
    {
        try
        {
            var effective = configuration ?? new ServiceConfiguration();
            WriteAudit(effective, identity, context, correlationId, stopwatch,
                result, detail, null, null, null, null, null);
        }
        catch (AuditLogException)
        {
            // Preserve the original error response when optional best-effort audit logging fails.
        }
    }

    private void BestEffortAuditBounded(
        ServiceConfiguration configuration,
        RequestIdentity identity,
        HttpContext context,
        string correlationId,
        Stopwatch stopwatch,
        string result,
        string detail,
        bool processingAlreadyAdmitted)
    {
        if (processingAlreadyAdmitted)
        {
            BestEffortAudit(configuration, identity, context, correlationId, stopwatch, result, detail);
            return;
        }

        using (var auditAdmission = Admission.Value.TryEnterProcessing(
            HttpSupport.GetRemoteAddressKey(context.Request)))
        {
            // Preserve overload responsiveness instead of queuing an error-path fsync.
            if (auditAdmission != null)
                BestEffortAudit(configuration, identity, context, correlationId, stopwatch, result, detail);
        }
    }
}
