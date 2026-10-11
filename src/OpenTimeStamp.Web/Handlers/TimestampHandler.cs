using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Infrastructure;
using OpenTimeStamp.Issuance;
using OpenTimeStamp.Protocols;
using OpenTimeStamp.Web.Infrastructure;

namespace OpenTimeStamp.Web.Handlers;

internal enum TimestampProtocol
{
    Rfc3161,
    Authenticode
}

// Bounds concurrent work inside this worker process. The supported IIS deployment runs exactly
// one worker without overlapping rotation, so the limits need no cross-process coordination.
internal sealed class TimestampAdmissionController
{
    private readonly AdmissionTier bodyIntake;
    private readonly AdmissionTier processing;

    internal TimestampAdmissionController(
        int bodyIntakeLimit,
        int processingLimit,
        int? perClientBodyIntakeLimit = null,
        int? perClientProcessingLimit = null)
    {
        if (bodyIntakeLimit <= 0) throw new ArgumentOutOfRangeException(nameof(bodyIntakeLimit));
        if (processingLimit <= 0) throw new ArgumentOutOfRangeException(nameof(processingLimit));
        if (perClientBodyIntakeLimit is <= 0 || perClientBodyIntakeLimit > bodyIntakeLimit)
            throw new ArgumentOutOfRangeException(nameof(perClientBodyIntakeLimit));
        if (perClientProcessingLimit is <= 0 || perClientProcessingLimit > processingLimit)
            throw new ArgumentOutOfRangeException(nameof(perClientProcessingLimit));

        bodyIntake = new AdmissionTier(bodyIntakeLimit, perClientBodyIntakeLimit ?? bodyIntakeLimit);
        processing = new AdmissionTier(processingLimit, perClientProcessingLimit ?? processingLimit);
    }

    internal IDisposable TryEnterBodyIntake(string clientKey = "<unknown>") => bodyIntake.TryEnter(clientKey);

    internal IDisposable TryEnterProcessing(string clientKey = "<unknown>") => processing.TryEnter(clientKey);

    internal int ActiveBodyClientCount => bodyIntake.ActiveClientCount;

    internal int ActiveProcessingClientCount => processing.ActiveClientCount;

    private sealed class AdmissionTier(int globalLimit, int perClientLimit)
    {
        private readonly Dictionary<string, int> activeClients = new(StringComparer.Ordinal);
        private readonly object gate = new();
        private int active;

        internal int ActiveClientCount
        {
            get
            {
                lock (gate) return activeClients.Count;
            }
        }

        internal AdmissionLease TryEnter(string clientKey)
        {
            clientKey = string.IsNullOrWhiteSpace(clientKey) ? "<unknown>" : clientKey;
            lock (gate)
            {
                activeClients.TryGetValue(clientKey, out var clientActive);
                if (active >= globalLimit || clientActive >= perClientLimit) return null;

                active++;
                activeClients[clientKey] = clientActive + 1;
            }

            return new AdmissionLease(() => Release(clientKey));
        }

        private void Release(string clientKey)
        {
            lock (gate)
            {
                var clientActive = activeClients[clientKey];
                if (clientActive == 1)
                    activeClients.Remove(clientKey);
                else
                    activeClients[clientKey] = clientActive - 1;
                active--;
            }
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
        ServiceRuntime.Settings.ProcessingPerClientLimit));

    public override bool IsReusable => false;

    internal static void InitializeAdmission() => _ = Admission.Value;

    public override Task ProcessRequestAsync(HttpContext context) =>
        ProcessAsync(new HttpContextWrapper(context));

    internal async Task ProcessAsync(HttpContextBase context)
    {
        // Establish a response trace before enforcing endpoint-wide preconditions.
        var correlationId = HttpSupport.GetCorrelationId(context);
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
            if (configuration.RequiresWindowsAuthentication && !identity.IsAuthenticated)
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
        catch (Exception ex) when (CertificateRepository.IsSelectionFailure(ex) ||
                                   ex is InvalidOperationException or IssuanceStateException)
        {
            admissions.ReleaseBody();
            BestEffortAuditBounded(configuration, identity, context, correlationId, stopwatch,
                "error", ex.Message, admissions.HasProcessing);
            HttpSupport.WritePlainError(context, 503, "The timestamp authority is temporarily unavailable.");
        }
    }

    private async Task ProcessRfc3161(
        HttpContextBase context,
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

        Rfc3161Request parsedRequest;
        try
        {
            parsedRequest = Rfc3161Request.Parse(request);
        }
        catch (Rfc3161ProtocolException ex)
        {
            // Produce the standard DER rejection without opening a certificate store
            // or invoking a private-key provider for malformed protocol input.
            WriteRfc3161Result(context, configuration, identity, correlationId, stopwatch,
                Rfc3161TimestampProcessor.CreateRejection(ex.FailureInfo, ex.Message));
            return;
        }

        if (!Rfc3161TimestampProcessor.TryPreflight(parsedRequest, configuration, out var result))
        {
            WriteRfc3161Result(context, configuration, identity, correlationId, stopwatch, result);
            return;
        }
        cancellationToken.ThrowIfCancellationRequested();

        X509Certificate2 certificate;
        try
        {
            certificate = ServiceRuntime.GetSelectedCertificate(snapshot, cancellationToken);
        }
        catch (CertificateSelectionException ex)
        {
            // Answer with a standards-shaped rejection and keep the actual cause for the audit record.
            WriteRfc3161Result(context, configuration, identity, correlationId, stopwatch,
                Rfc3161TimestampProcessor.CreateRejection(Rfc3161FailureInfo.SystemFailure, ex.Message, parsedRequest));
            return;
        }

        using (certificate)
        {
            result = Rfc3161TimestampProcessor.Process(
                parsedRequest,
                configuration,
                certificate,
                ServiceRuntime.IssuanceState,
                () => DateTime.UtcNow,
                cancellationToken);
            WriteRfc3161Result(context, configuration, identity, correlationId, stopwatch, result);
        }
    }

    private async Task ProcessAuthenticode(
        HttpContextBase context,
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
                result = AuthenticodeTimestampProcessor.ProcessParsedSignature(
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
        HttpRequestBase request,
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

    private static bool TryEnterProcessing(HttpContextBase context, RequestAdmissions admissions)
    {
        admissions.Processing = Admission.Value.TryEnterProcessing(admissions.ClientKey);
        if (admissions.Processing is not null) return true;

        context.Response.Headers["Retry-After"] = "5";
        HttpSupport.WritePlainError(context, 503, "The timestamp service is at processing capacity. Retry later.");
        return false;
    }

    private static CancellationTokenSource CreateRequestCancellation(HttpContextBase context)
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

    private static bool IsClientDisconnected(HttpContextBase context)
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
        HttpContextBase context,
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

        internal bool HasProcessing => processing is not null;

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
        HttpContextBase context,
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
            MessageImprintHex = configuration.LogMessageImprints ? Hex.ToLower(imprint) : null,
            SerialHex = Hex.ToLower(serial),
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
        HttpContextBase context,
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
        HttpContextBase context,
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
            if (auditAdmission is not null)
                BestEffortAudit(configuration, identity, context, correlationId, stopwatch, result, detail);
        }
    }
}
