using System;
using System.Buffers;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace OpenTimeStamp.Web.Infrastructure;

internal sealed class RequestIdentity
{
    public string Name { get; set; }
    public string Sid { get; set; }
    public string AuthenticationType { get; set; }
    public bool IsAuthenticated { get; set; }
}

internal static class HttpSupport
{
    private static readonly TimeSpan AbortedReadObservationGrace = TimeSpan.FromMilliseconds(250);

    public static void ApplySecurityHeaders(HttpResponse response)
    {
        // Apply one restrictive response policy to protocol and administrative endpoints.
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
        response.Cache.SetCacheability(HttpCacheability.NoCache);
        response.Cache.SetNoStore();
        response.Cache.SetRevalidation(HttpCacheRevalidation.AllCaches);
    }

    public static bool HasExactMediaType(HttpRequest request, string expected) =>
        HasExactMediaTypeValue(request?.ContentType, expected);

    internal static bool HasExactMediaTypeValue(string contentType, string expected) =>
        MediaTypeHeaderValue.TryParse(contentType, out var parsed) &&
        string.Equals(parsed.MediaType, expected, StringComparison.OrdinalIgnoreCase) &&
        parsed.Parameters.All(HasValidMediaTypeParameter);

    private static bool HasValidMediaTypeParameter(NameValueHeaderValue parameter)
    {
        var value = parameter?.Value;
        if (string.IsNullOrWhiteSpace(value)) return false;
        return value[0] != '"' || value.Length >= 2 && value[value.Length - 1] == '"';
    }

    public static async Task<byte[]> ReadBoundedBodyAsync(
        HttpRequest request,
        int maximumBytes,
        TimeSpan deadline,
        CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var input = request.GetBufferlessInputStream(false);
        // HttpRequest.ContentLength is zero when no Content-Length header is present,
        // including normal chunked requests. Preserve that distinction so streamed
        // bodies use the pooled growth path instead of repeated exact-array growth.
        var declaredLength = request.Headers["Content-Length"] is null ? -1 : request.ContentLength;
        try
        {
            return await ReadBoundedStreamAsync(
                input,
                declaredLength,
                maximumBytes,
                deadline,
                () =>
                {
                    try
                    {
                        request.Abort();
                    }
                    catch (Exception ex) when (ex is HttpException or InvalidOperationException or ObjectDisposedException)
                    {
                        // The client or ASP.NET may already have torn down the request.
                    }
                    finally
                    {
                        try
                        {
                            input.Dispose();
                        }
                        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
                        {
                            // Disposing an already-aborted native request stream is harmless.
                        }
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                input.Dispose();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                // Preserve the read result after native request teardown.
            }
        }
    }

    internal static async Task<byte[]> ReadBoundedStreamAsync(
        Stream input,
        int declaredLength,
        int maximumBytes,
        TimeSpan deadline,
        Action abortPendingRead,
        CancellationToken cancellationToken,
        Action abandonedReadObserved = null,
        ArrayPool<byte> bufferPool = null)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        if (deadline <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(deadline));
        if (declaredLength > maximumBytes)
            throw new RequestBodyException(413, false, "The request body exceeds the configured limit.");

        // Exact-allocate honest Content-Length bodies. Unknown-length bodies use
        // cleared pooled growth buffers so overload cannot create avoidable LOH churn.
        var pooled = declaredLength < 0;
        bufferPool ??= ArrayPool<byte>.Shared;
        var initialLength = pooled ? Math.Min(8192, maximumBytes) : declaredLength;
        var output = pooled ? bufferPool.Rent(initialLength) : initialLength == 0 ? [] : new byte[initialLength];
        var capacity = pooled ? Math.Min(output.Length, maximumBytes) : output.Length;
        var overflow = new byte[1];
        var length = 0;
        var stopwatch = Stopwatch.StartNew();
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var remainingTime = deadline - stopwatch.Elapsed;
                if (remainingTime <= TimeSpan.Zero)
                {
                    AbortPendingRead(abortPendingRead);
                    throw TimedOutBody();
                }

                // HttpBufferlessInputStream supplies native BeginRead/EndRead methods on
                // ASP.NET 4.8, so this does not pin a worker thread while a client stalls.
                var probingForOverflow = length == capacity;
                var readTask = input.ReadAsync(
                    probingForOverflow ? overflow : output,
                    probingForOverflow ? 0 : length,
                    probingForOverflow ? 1 : capacity - length,
                    cancellationToken);
                int read;
                if (readTask.IsCompleted)
                {
                    read = await readTask.ConfigureAwait(false);
                }
                else
                {
                    using var delayCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    var delayTask = Task.Delay(remainingTime, delayCancellation.Token);
                    if (await Task.WhenAny(readTask, delayTask).ConfigureAwait(false) != readTask)
                    {
                        AbortPendingRead(abortPendingRead);

                        // Give ASP.NET's aborted native read a short window to complete,
                        // but never let a defective stream defeat the configured intake
                        // bound. A continuation observes any later fault after release.
                        await ObserveAbortedReadAsync(readTask, abandonedReadObserved).ConfigureAwait(false);

                        if (cancellationToken.IsCancellationRequested)
                            throw new OperationCanceledException(cancellationToken);
                        throw TimedOutBody();
                    }

                    delayCancellation.Cancel();
                    read = await readTask.ConfigureAwait(false);
                }

                if (read == 0) break;
                if (!probingForOverflow)
                {
                    length += read;
                    continue;
                }

                if (length >= maximumBytes)
                    throw new RequestBodyException(413, false, "The request body exceeds the configured limit.");

                var doubledLength = capacity <= maximumBytes / 2 ? capacity * 2 : maximumBytes;
                var expandedLength = Math.Max(length + 1, Math.Max(1, doubledLength));
                var expanded = pooled ? bufferPool.Rent(expandedLength) : new byte[expandedLength];
                if (length != 0) Buffer.BlockCopy(output, 0, expanded, 0, length);
                expanded[length++] = overflow[0];
                if (pooled)
                {
                    var previous = output;
                    output = expanded;
                    capacity = Math.Min(output.Length, maximumBytes);
                    bufferPool.Return(previous, true);
                }
                else
                {
                    output = expanded;
                    capacity = output.Length;
                }
            }

            if (!pooled && length == output.Length) return output;
            if (length == 0) return [];
            var result = new byte[length];
            Buffer.BlockCopy(output, 0, result, 0, length);
            return result;
        }
        finally
        {
            if (pooled) bufferPool.Return(output, true);
        }
    }

    internal static string GetRemoteAddressKey(HttpRequest request)
    {
        const string unknown = "<unknown>";
        if (request is null) return unknown;

        string remoteText;
        try
        {
            // Deliberately ignore all forwarding headers. IIS REMOTE_ADDR is the
            // transport peer and therefore the only suitable admission key here.
            remoteText = request.ServerVariables["REMOTE_ADDR"];
        }
        catch (Exception ex) when (ex is HttpException or InvalidOperationException)
        {
            return unknown;
        }

        if (!IPAddress.TryParse(remoteText, out var remote)) return unknown;
        if (remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();
        return remote.ToString();
    }

    private static void AbortPendingRead(Action abortPendingRead)
    {
        try
        {
            abortPendingRead?.Invoke();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException)
        {
            // The underlying stream may already have completed its own teardown.
        }
    }

    private static async Task ObserveAbortedReadAsync(Task<int> readTask, Action observed)
    {
        if (await Task.WhenAny(readTask, Task.Delay(AbortedReadObservationGrace)).ConfigureAwait(false) == readTask)
        {
            try
            {
                await readTask.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The expected result of aborting/discarding the request body.
            }

            observed?.Invoke();
            return;
        }

        _ = readTask.ContinueWith(
            completed =>
            {
                // Reading Exception marks a later native-read fault as observed. A
                // successful or canceled completion simply returns null here.
                _ = completed.Exception;
                observed?.Invoke();
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static RequestBodyException TimedOutBody() =>
        new(408, true, "The request body was not received before the configured deadline.");

    public static RequestIdentity GetRequestIdentity(HttpRequest request)
    {
        // Prefer the IIS logon token because it carries the authoritative Windows SID.
        try
        {
            var identity = request.LogonUserIdentity;
            if (identity is { IsAuthenticated: true })
            {
                return new RequestIdentity
                {
                    Name = identity.Name,
                    Sid = identity.User?.Value,
                    AuthenticationType = identity.AuthenticationType,
                    IsAuthenticated = true
                };
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Security.SecurityException)
        {
            // Fall back to the ASP.NET principal when IIS does not expose a logon token.
        }

        var principalIdentity = request.RequestContext?.HttpContext?.User?.Identity;
        return new RequestIdentity
        {
            Name = principalIdentity is { IsAuthenticated: true } ? principalIdentity.Name : null,
            AuthenticationType = principalIdentity?.AuthenticationType,
            IsAuthenticated = principalIdentity?.IsAuthenticated == true
        };
    }

    public static bool IsLocalAdminRequest(HttpRequest request)
    {
        // Never trust a request that advertises traversal through a forwarding proxy.
        if (!string.IsNullOrEmpty(request.Headers["Forwarded"]) ||
            !string.IsNullOrEmpty(request.Headers["X-Forwarded-For"]) ||
            !string.IsNullOrEmpty(request.Headers["X-Forwarded-Host"]) ||
            !string.IsNullOrEmpty(request.Headers["X-Forwarded-Proto"])) return false;

        var remoteText = request.ServerVariables["REMOTE_ADDR"];
        if (!IPAddress.TryParse(remoteText, out var remote)) return false;
        if (!IPAddress.IsLoopback(remote) && !request.IsLocal) return false;

        // Require an explicit local host name as a second defense against DNS rebinding.
        var host = NormalizeHost(request.Url?.DnsSafeHost);
        string[] allowed = ["localhost", "127.0.0.1", "::1", Environment.MachineName];
        var configured = (ConfigurationManager.AppSettings["AdminHostNames"] ?? string.Empty)
            .Split([',', ';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        foreach (var candidate in allowed.Concat(configured).Select(NormalizeHost))
        {
            if (candidate.Length != 0 && string.Equals(host, candidate, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    internal static string NormalizeHost(string value)
    {
        value = (value ?? string.Empty).Trim();
        return value.Length >= 2 && value[0] == '[' && value[value.Length - 1] == ']'
            ? value.Substring(1, value.Length - 2)
            : value;
    }

    public static void WritePlainError(HttpContext context, int statusCode, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.TrySkipIisCustomErrors = true;
        context.Response.ContentType = "text/plain; charset=utf-8";
        context.Response.Write(message ?? "Request failed.");
    }

    public static string ToHex(byte[] value)
    {
        if (value is null) return null;

        var builder = new StringBuilder(value.Length * 2);
        foreach (var item in value) builder.Append(item.ToString("x2", CultureInfo.InvariantCulture));

        return builder.ToString();
    }
}

internal sealed class RequestBodyException : Exception
{
    internal RequestBodyException(int statusCode, bool connectionAborted, string message)
        : base(message)
    {
        StatusCode = statusCode;
        ConnectionAborted = connectionAborted;
    }

    internal int StatusCode { get; }
    internal bool ConnectionAborted { get; }
}
