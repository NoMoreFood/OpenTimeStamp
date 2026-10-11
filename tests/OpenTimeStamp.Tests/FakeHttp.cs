using System;
using System.Collections;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Routing;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Web.Infrastructure;

namespace OpenTimeStamp.Tests;

// In-memory HTTP abstractions. The handlers take HttpContextBase, so their complete request
// flows run here without IIS.
internal sealed class FakeHttpContext : HttpContextBase
{
    private readonly Hashtable items = [];

    public FakeHttpContext(FakeHttpRequest request)
    {
        FakeRequest = request;
        FakeResponse = new FakeHttpResponse();
        request.RequestContext = new RequestContext(this, new RouteData());
    }

    public FakeHttpRequest FakeRequest { get; }

    public FakeHttpResponse FakeResponse { get; }

    public override HttpRequestBase Request => FakeRequest;

    public override HttpResponseBase Response => FakeResponse;

    public override IDictionary Items => items;

    public override IPrincipal User { get; set; }

    public override bool ThreadAbortOnTimeout { get; set; }
}

internal sealed class FakeHttpRequest : HttpRequestBase
{
    private readonly byte[] body;
    private readonly FakeUnvalidatedValues unvalidated = new();

    public FakeHttpRequest(string method, string url, byte[] body = null, string remoteAddress = "203.0.113.7")
    {
        HttpMethod = method;
        Url = new Uri(url);
        this.body = body ?? [];
        ServerVariables["REMOTE_ADDR"] = remoteAddress;
        if (body is not null) Headers["Content-Length"] = this.body.Length.ToString();
        foreach (var pair in Url.Query.TrimStart('?').Split(['&'], StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split(['='], 2);
            QueryString[parts[0]] = parts.Length == 2 ? parts[1] : string.Empty;
        }
    }

    // An IIS logon token whose requests arrived without authentication.
    public WindowsIdentity Identity { get; set; } = WindowsIdentity.GetAnonymous();

    public bool Aborted { get; private set; }

    public NameValueCollection FormValues => unvalidated.Form;

    public override string HttpMethod { get; }

    public override Uri Url { get; }

    public override Uri UrlReferrer => null;

    public override string Path => Url.AbsolutePath;

    public override string ApplicationPath => "/";

    public override string ContentType { get; set; }

    public override int ContentLength => body.Length;

    public override bool IsLocal => IsLoopback(ServerVariables["REMOTE_ADDR"]);

    public override bool IsSecureConnection => Url.Scheme == Uri.UriSchemeHttps;

    public override NameValueCollection QueryString { get; } = [];

    public override NameValueCollection Headers { get; } = [];

    public override NameValueCollection ServerVariables { get; } = [];

    public override HttpCookieCollection Cookies { get; } = [];

    public override UnvalidatedRequestValuesBase Unvalidated => unvalidated;

    public override WindowsIdentity LogonUserIdentity => Identity;

    public override RequestContext RequestContext { get; set; }

    public override CancellationToken TimedOutToken => CancellationToken.None;

    public override Stream GetBufferlessInputStream(bool disableMaxRequestLength) => new MemoryStream(body, false);

    public override void Abort() => Aborted = true;

    private static bool IsLoopback(string address) =>
        System.Net.IPAddress.TryParse(address, out var parsed) && System.Net.IPAddress.IsLoopback(parsed);

    private sealed class FakeUnvalidatedValues : UnvalidatedRequestValuesBase
    {
        public override NameValueCollection Form { get; } = [];
    }
}

internal sealed class FakeHttpResponse : HttpResponseBase
{
    private readonly MemoryStream output = new();
    private readonly FakeCachePolicy cache = new();

    public byte[] Body => output.ToArray();

    public string Text => Encoding.UTF8.GetString(output.ToArray());

    public override int StatusCode { get; set; } = 200;

    public override string ContentType { get; set; }

    public override string RedirectLocation { get; set; }

    public override bool TrySkipIisCustomErrors { get; set; }

    public override bool HeadersWritten => false;

    public override bool IsClientConnected => true;

    public override CancellationToken ClientDisconnectedToken => CancellationToken.None;

    public override NameValueCollection Headers { get; } = [];

    public override HttpCookieCollection Cookies { get; } = [];

    public override HttpCachePolicyBase Cache => cache;

    public override Stream OutputStream => output;

    public override void Write(string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
        output.Write(bytes, 0, bytes.Length);
    }

    public override void ClearContent() => output.SetLength(0);

    public override void Clear() => output.SetLength(0);

    private sealed class FakeCachePolicy : HttpCachePolicyBase
    {
        public override void SetCacheability(HttpCacheability cacheability)
        {
        }

        public override void SetNoStore()
        {
        }

        public override void SetRevalidation(HttpCacheRevalidation revalidation)
        {
        }
    }
}

// Points the process-wide service runtime at a private data directory for one test.
internal sealed class HandlerTestHost : IDisposable
{
    private readonly TemporaryDirectory directory = new();

    public HandlerTestHost(
        string authenticationMode = ServiceConfiguration.AnonymousAuthentication,
        Func<ServiceConfiguration, X509Certificate2> certificate = null)
    {
        ServiceRuntime.Restart(
            directory.Path,
            new WebRuntimeSettings(authenticationMode, TimeSpan.FromSeconds(5), 32, 4, 4, 2),
            certificate);
        ServiceRuntime.IssuanceState.Initialize();
    }

    public string DataDirectory => directory.Path;

    public void Configure(Action<ServiceConfiguration> edit)
    {
        var configuration = ServiceRuntime.LoadConfiguration(out var generation);
        edit(configuration);
        ServiceRuntime.PublishConfiguration(
            configuration,
            ServiceRuntime.Configuration.Save(configuration, generation));
    }

    public string[] AuditLines()
    {
        var logs = Path.Combine(directory.Path, "Logs");
        return Directory.Exists(logs)
            ? Directory.GetFiles(logs, "timestamp-*.jsonl").SelectMany(File.ReadAllLines).ToArray()
            : [];
    }

    public void Dispose()
    {
        ServiceRuntime.Shutdown();
        directory.Dispose();
    }
}
