using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Protocols;
using OpenTimeStamp.Web.Handlers;
using OpenTimeStamp.Web.Infrastructure;

namespace OpenTimeStamp.Tests;

// Drives each handler's complete request flow through in-memory HTTP abstractions.
[TestClass]
public sealed class HandlerTests
{
    private const string Rfc3161Url = "http://tsa.example.test/timestamp/rfc3161";
    private const string AuthenticodeUrl = "http://tsa.example.test/timestamp/authenticode";
    private const string AdminUrl = "http://localhost/admin";

    // Present in every interactive and service logon token, unlike BUILTIN\\Administrators,
    // which a non-elevated test process holds only as a deny-only group.
    private const string AuthenticatedUsersSid = "S-1-5-11";
    private const string UnrelatedGroupSid = "S-1-5-21-1111111111-2222222222-3333333333-4444";

    [TestMethod(DisplayName = "Timestamp endpoint rejects a wrong method, media type, or query")]
    public void TimestampRejectsMalformedHttp()
    {
        using var host = new HandlerTestHost();
        host.Configure(EnableRfc3161);
        var body = TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]);

        var get = Timestamp(new FakeHttpRequest("GET", Rfc3161Url), TimestampProtocol.Rfc3161);
        AssertEx.Equal(405, get.StatusCode);
        AssertEx.Equal("POST", get.Headers["Allow"]);

        var query = new FakeHttpRequest("POST", Rfc3161Url + "?debug=1", body)
        {
            ContentType = "application/timestamp-query"
        };
        AssertEx.Equal(400, Timestamp(query, TimestampProtocol.Rfc3161).StatusCode);

        var mediaType = new FakeHttpRequest("POST", Rfc3161Url, body) { ContentType = "application/octet-stream" };
        AssertEx.Equal(415, Timestamp(mediaType, TimestampProtocol.Rfc3161).StatusCode);

        var compressed = new FakeHttpRequest("POST", Rfc3161Url, body) { ContentType = "application/timestamp-query" };
        compressed.Headers["Content-Encoding"] = "gzip";
        AssertEx.Equal(415, Timestamp(compressed, TimestampProtocol.Rfc3161).StatusCode);

        AssertEx.Equal(0, host.AuditLines().Length, "Requests refused before protocol handling must not be audited.");
    }

    [TestMethod(DisplayName = "Timestamp endpoint is absent while its protocol is disabled")]
    public void TimestampProtocolDisabled()
    {
        using var host = new HandlerTestHost();
        var response = Timestamp(Rfc3161Post(TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32])),
            TimestampProtocol.Rfc3161);
        AssertEx.Equal(404, response.StatusCode);

        host.Configure(EnableRfc3161);
        var authenticode = new FakeHttpRequest("POST", AuthenticodeUrl, [0x00])
        {
            ContentType = "application/octet-stream"
        };
        AssertEx.Equal(404, Timestamp(authenticode, TimestampProtocol.Authenticode).StatusCode,
            "Enabling one protocol must not expose the other.");
    }

    [TestMethod(DisplayName = "Timestamp endpoint requires Windows authentication in Windows mode")]
    public void TimestampRequiresWindowsAuthentication()
    {
        using var certificate = new TimestampCertificateFixture();
        using var host = new HandlerTestHost(
            ServiceConfiguration.WindowsAuthentication,
            _ => new X509Certificate2(certificate.Certificate));
        host.Configure(EnableRfc3161);
        var body = TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]);

        var anonymous = Timestamp(Rfc3161Post(body), TimestampProtocol.Rfc3161);
        AssertEx.Equal(401, anonymous.StatusCode);
        AssertEx.Equal("Negotiate", anonymous.Headers["WWW-Authenticate"]);
        var rejected = host.AuditLines().Single();
        AssertEx.Contains("\"result\":\"rejected\"", rejected);
        AssertEx.Contains("Windows authentication is required.", rejected);

        var authenticatedRequest = Rfc3161Post(body);
        authenticatedRequest.Identity = WindowsIdentity.GetCurrent();
        var authenticated = Timestamp(authenticatedRequest, TimestampProtocol.Rfc3161);
        AssertEx.Equal(200, authenticated.StatusCode);
        AssertEx.Equal(0, TestFixtures.ExtractRfc3161Status(authenticated.Body));
        var granted = host.AuditLines().Last();
        AssertEx.Contains("\"result\":\"granted\"", granted);
        AssertEx.Contains("\"userSid\":\"" + WindowsIdentity.GetCurrent().User.Value + "\"", granted);
    }

    [TestMethod(DisplayName = "RFC 3161 endpoint issues an audited token")]
    public void Rfc3161IssuesAuditedToken()
    {
        using var certificate = new TimestampCertificateFixture();
        using var host = new HandlerTestHost(certificate: _ => new X509Certificate2(certificate.Certificate));
        host.Configure(EnableRfc3161);
        var digest = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        byte[] nonce = [0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        var request = Rfc3161Post(TestFixtures.BuildRfc3161Request(
            TestFixtures.Sha256Oid, digest, certificateRequested: true, signedNonce: nonce));

        var response = Timestamp(request, TimestampProtocol.Rfc3161);
        AssertEx.Equal(200, response.StatusCode);
        AssertEx.Equal("application/timestamp-reply", response.ContentType);
        AssertEx.False(string.IsNullOrEmpty(response.Headers["X-Correlation-ID"]));
        var cms = TestFixtures.DecodeCms(TestFixtures.ExtractGrantedRfc3161Token(response.Body));
        cms.CheckSignature(new X509Certificate2Collection(certificate.Certificate), true);

        var audit = host.AuditLines().Single();
        AssertEx.Contains("\"eventType\":\"timestamp\"", audit);
        AssertEx.Contains("\"result\":\"granted\"", audit);
        AssertEx.Contains("\"protocol\":\"rfc3161\"", audit);
        AssertEx.Contains("\"username\":\"anonymous\"", audit);
        AssertEx.Contains("\"remoteAddress\":\"203.0.113.7\"", audit);
        AssertEx.Contains("\"correlationId\":\"" + response.Headers["X-Correlation-ID"] + "\"", audit);
        AssertEx.Contains("\"messageImprint\":\"" + TestFixtures.Hex(digest).ToLowerInvariant() + "\"", audit);
        AssertEx.True(Regex.IsMatch(audit, "\"serial\":\"[0-9a-f]{32}\""), "The audit record must carry the serial.");

        // Two tokens never share a serial number.
        var second = Timestamp(
            Rfc3161Post(TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, digest)), TimestampProtocol.Rfc3161);
        AssertEx.Equal(0, TestFixtures.ExtractRfc3161Status(second.Body));
        var serials = host.AuditLines()
            .Select(line => Regex.Match(line, "\"serial\":\"([0-9a-f]{32})\"").Groups[1].Value);
        AssertEx.Equal(2, serials.Distinct(StringComparer.Ordinal).Count());
    }

    [TestMethod(DisplayName = "RFC 3161 endpoint answers a malformed request with an audited rejection")]
    public void Rfc3161RejectsMalformedRequest()
    {
        using var host = new HandlerTestHost(certificate: _ =>
            throw new InvalidOperationException("A malformed request must not reach certificate selection."));
        host.Configure(EnableRfc3161);

        var response = Timestamp(Rfc3161Post([0x30, 0x80]), TimestampProtocol.Rfc3161);
        AssertEx.Equal(200, response.StatusCode, "RFC 3161 reports protocol errors in the response body.");
        AssertEx.Equal("application/timestamp-reply", response.ContentType);
        AssertEx.Equal(2, TestFixtures.ExtractRfc3161Status(response.Body));
        AssertEx.Equal((int)Rfc3161FailureInfo.BadDataFormat, TestFixtures.ExtractRfc3161FailureBit(response.Body));
        AssertEx.Contains("\"result\":\"rejected\"", host.AuditLines().Single());

        // A hash the service does not allow is refused before any key is touched.
        var disallowed = Timestamp(
            Rfc3161Post(TestFixtures.BuildRfc3161Request("1.3.14.3.2.26", new byte[20])), TimestampProtocol.Rfc3161);
        AssertEx.Equal((int)Rfc3161FailureInfo.BadAlgorithm, TestFixtures.ExtractRfc3161FailureBit(disallowed.Body));
    }

    [TestMethod(DisplayName = "RFC 3161 endpoint audits why certificate selection failed")]
    public void Rfc3161AuditsCertificateFailure()
    {
        const string reason = "The selected certificate cannot be used: it expired last week.";
        using var host = new HandlerTestHost(certificate: _ => throw new CertificateSelectionException(reason));
        host.Configure(EnableRfc3161);

        var response = Timestamp(
            Rfc3161Post(TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32])),
            TimestampProtocol.Rfc3161);
        AssertEx.Equal(200, response.StatusCode);
        AssertEx.Equal(2, TestFixtures.ExtractRfc3161Status(response.Body));
        AssertEx.Equal((int)Rfc3161FailureInfo.SystemFailure, TestFixtures.ExtractRfc3161FailureBit(response.Body));
        AssertEx.False(Encoding.ASCII.GetString(response.Body).Contains("expired"),
            "The cause is for the audit trail only; clients receive a generic status.");
        var audit = host.AuditLines().Single();
        AssertEx.Contains("\"result\":\"rejected\"", audit);
        AssertEx.Contains(reason, audit, "The audit record must say why no certificate could be selected.");
    }

    [TestMethod(DisplayName = "Timestamp endpoint withholds a token whose audit record cannot be written")]
    public void TimestampFailsClosedOnAuditFailure()
    {
        using var certificate = new TimestampCertificateFixture();
        using var host = new HandlerTestHost(certificate: _ => new X509Certificate2(certificate.Certificate));
        host.Configure(EnableRfc3161);

        // A file where the log directory belongs makes every audit write fail.
        File.WriteAllText(Path.Combine(host.DataDirectory, "Logs"), string.Empty);
        var response = Timestamp(
            Rfc3161Post(TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32])),
            TimestampProtocol.Rfc3161);
        AssertEx.Equal(503, response.StatusCode);
        AssertEx.Contains("audit log cannot be written", response.Text);
        AssertEx.True(response.ContentType.StartsWith("text/plain", StringComparison.Ordinal),
            "A token must not be returned when its audit record was not committed.");

        // With fail-open auditing the same failure does not block issuance.
        host.Configure(configuration => configuration.FailClosedOnAuditError = false);
        var failOpen = Timestamp(
            Rfc3161Post(TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32])),
            TimestampProtocol.Rfc3161);
        AssertEx.Equal(200, failOpen.StatusCode);
        AssertEx.Equal(0, TestFixtures.ExtractRfc3161Status(failOpen.Body));
    }

    [TestMethod(DisplayName = "Timestamp endpoint bounds the request body")]
    public void TimestampBoundsRequestBody()
    {
        using var host = new HandlerTestHost(certificate: _ =>
            throw new InvalidOperationException("An oversized request must not reach certificate selection."));
        host.Configure(configuration =>
        {
            EnableRfc3161(configuration);
            configuration.MaxRequestBytes = 1024;
        });

        var declared = Timestamp(Rfc3161Post(new byte[1025]), TimestampProtocol.Rfc3161);
        AssertEx.Equal(413, declared.StatusCode);

        // A chunked request declares no length, so the bound applies while the body streams in.
        var chunkedRequest = Rfc3161Post(new byte[1025]);
        chunkedRequest.Headers.Remove("Content-Length");
        AssertEx.Equal(413, Timestamp(chunkedRequest, TimestampProtocol.Rfc3161).StatusCode);
    }

    [TestMethod(DisplayName = "Authenticode endpoint issues an audited countersignature")]
    public void AuthenticodeIssuesAuditedCountersignature()
    {
        if (!PlatformSecurityPolicy.IsLegacyAuthenticodeAllowed)
            Assert.Inconclusive("Legacy Authenticode is unavailable while Windows FIPS mode is enabled.");

        using var certificate = new TimestampCertificateFixture();
        using var host = new HandlerTestHost(certificate: _ => new X509Certificate2(certificate.Certificate));
        host.Configure(configuration => configuration.AuthenticodeEnabled = true);
        byte[] signature = [0x10, 0x20, 0x30, 0x40];

        // SignTool posts NUL-terminated base64 text.
        var text = Convert.ToBase64String(TestFixtures.BuildAuthenticodeRequest(signature)) + "\0";
        var request = new FakeHttpRequest("POST", AuthenticodeUrl, Encoding.ASCII.GetBytes(text))
        {
            ContentType = "application/octet-stream"
        };
        var response = Timestamp(request, TimestampProtocol.Authenticode);
        AssertEx.Equal(200, response.StatusCode);
        AssertEx.Equal("application/octet-stream", response.ContentType);
        var cms = TestFixtures.DecodeCms(Convert.FromBase64String(Encoding.ASCII.GetString(response.Body)));
        cms.CheckSignature(new X509Certificate2Collection(certificate.Certificate), true);
        AssertEx.SequenceEqual(signature, cms.ContentInfo.Content);
        var audit = host.AuditLines().Single();
        AssertEx.Contains("\"protocol\":\"authenticode\"", audit);
        AssertEx.Contains("\"result\":\"granted\"", audit);

        var malformed = new FakeHttpRequest("POST", AuthenticodeUrl, Encoding.ASCII.GetBytes("not base64!"))
        {
            ContentType = "application/octet-stream"
        };
        AssertEx.Equal(400, Timestamp(malformed, TimestampProtocol.Authenticode).StatusCode);
    }

    [TestMethod(DisplayName = "Admin console is limited to the local server and authorized groups")]
    public void AdminRequiresLocalAuthorizedCaller()
    {
        using var host = new HandlerTestHost();
        host.Configure(configuration => configuration.AdminAllowedWindowsGroups = [AuthenticatedUsersSid]);

        var remote = new FakeHttpRequest("GET", "http://tsa.example.test/admin")
        {
            Identity = WindowsIdentity.GetCurrent()
        };
        AssertEx.Equal(403, Admin(remote).StatusCode, "A request from another machine must be refused.");

        // A local proxy forwards remote traffic from a loopback address.
        var proxied = AdminGet();
        proxied.Headers["X-Forwarded-For"] = "198.51.100.9";
        AssertEx.Equal(403, Admin(proxied).StatusCode);

        // The connection is local but the Host header is not a name this server administers under.
        var rebound = new FakeHttpRequest("GET", "http://attacker.example.test/admin", remoteAddress: "127.0.0.1")
        {
            Identity = WindowsIdentity.GetCurrent()
        };
        AssertEx.Equal(403, Admin(rebound).StatusCode);

        var anonymous = AdminGet();
        anonymous.Identity = WindowsIdentity.GetAnonymous();
        var challenge = Admin(anonymous);
        AssertEx.Equal(401, challenge.StatusCode);
        AssertEx.Equal("Negotiate", challenge.Headers["WWW-Authenticate"]);

        AssertEx.Equal(200, Admin(AdminGet()).StatusCode);

        host.Configure(configuration => configuration.AdminAllowedWindowsGroups = [UnrelatedGroupSid]);
        var outsider = Admin(AdminGet());
        AssertEx.Equal(403, outsider.StatusCode);
        AssertEx.False(outsider.Text.Contains("<form"), "Settings must not be disclosed to an unauthorized account.");
    }

    [TestMethod(DisplayName = "Admin console renders settings, certificates, and a CSRF token")]
    public void AdminRendersSettings()
    {
        using var host = new HandlerTestHost();
        host.Configure(configuration =>
        {
            configuration.AdminAllowedWindowsGroups = [AuthenticatedUsersSid];
            configuration.DefaultPolicyOid = TestFixtures.DefaultPolicyOid;
            configuration.AcceptedPolicyOids = [TestFixtures.DefaultPolicyOid];
        });

        var response = Admin(AdminGet());
        AssertEx.Equal(200, response.StatusCode);
        AssertEx.True(response.ContentType.StartsWith("text/html", StringComparison.Ordinal));
        AssertEx.Contains("value=\"" + TestFixtures.DefaultPolicyOid + "\"", response.Text);
        AssertEx.Contains(
            "name=\"generation\" value=\"" + ServiceRuntime.Configuration.GetGeneration() + "\"", response.Text);

        var cookie = response.Cookies["OpenTimeStamp.AdminCsrf"];
        AssertEx.NotNull(cookie, "The page must issue its CSRF cookie.");
        AssertEx.True(cookie.HttpOnly);
        AssertEx.Equal(SameSiteMode.Strict, cookie.SameSite);
        AssertEx.Contains("name=\"csrf\" value=\"" + cookie.Value + "\"", response.Text);

        // Every certificate in the stores is listed; one that cannot be selected says why.
        var listed = ServiceRuntime.Certificates.ListCertificates(true, "SHA256", false);
        foreach (var certificate in listed.Where(item => !string.IsNullOrEmpty(item.Thumbprint)))
        {
            AssertEx.Contains(certificate.Thumbprint, response.Text);
        }

        var ineligible = listed.FirstOrDefault(
            item => !item.IsEligible && !string.IsNullOrEmpty(item.IneligibilityReason));
        if (ineligible is not null)
        {
            AssertEx.Contains(HttpUtility.HtmlEncode(ineligible.IneligibilityReason), response.Text);
        }
    }

    [TestMethod(DisplayName = "Admin console rejects unverified state changes")]
    public void AdminRejectsUnverifiedPost()
    {
        using var host = new HandlerTestHost();
        host.Configure(configuration => configuration.AdminAllowedWindowsGroups = [AuthenticatedUsersSid]);
        var page = Admin(AdminGet());
        var before = ServiceRuntime.Configuration.GetGeneration();

        var missingToken = AdminPost(page, form => form.Remove("csrf"));
        AssertEx.Equal(403, Admin(missingToken).StatusCode);

        var forgedToken = AdminPost(page, form => form["csrf"] = "AAAA" + form["csrf"].Substring(4));
        AssertEx.Equal(403, Admin(forgedToken).StatusCode);

        var crossOrigin = AdminPost(page);
        crossOrigin.Headers["Origin"] = "http://attacker.example.test";
        AssertEx.Equal(403, Admin(crossOrigin).StatusCode);

        var noOrigin = AdminPost(page);
        noOrigin.Headers.Remove("Origin");
        AssertEx.Equal(403, Admin(noOrigin).StatusCode);

        // A token issued to one account is useless to another.
        var otherAccount = AdminPost(page);
        otherAccount.Cookies.Clear();
        var otherIdentity = new RequestIdentity
        {
            Name = "CONTOSO\\other",
            Sid = "S-1-5-21-1-2-3-1001",
            IsAuthenticated = true
        };
        var otherToken = Convert.ToBase64String(System.Web.Security.MachineKey.Protect(
                CsrfTokenManager.CreatePayload(otherIdentity, DateTime.UtcNow), "OpenTimeStamp.AdminCsrf.v1"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        otherAccount.Cookies.Add(new HttpCookie("OpenTimeStamp.AdminCsrf", otherToken));
        otherAccount.FormValues["csrf"] = otherToken;
        AssertEx.Equal(403, Admin(otherAccount).StatusCode);

        AssertEx.Equal(
            before, ServiceRuntime.Configuration.GetGeneration(), "A refused request must not change settings.");
        AssertEx.Equal(0, host.AuditLines().Length);
    }

    [TestMethod(DisplayName = "Admin console saves settings and audits each changed value")]
    public void AdminSavesAndAudits()
    {
        using var host = new HandlerTestHost();
        host.Configure(configuration => configuration.AdminAllowedWindowsGroups = [AuthenticatedUsersSid]);
        var page = Admin(AdminGet());
        var before = ServiceRuntime.Configuration.GetGeneration();

        var response = Admin(AdminPost(page, form =>
        {
            form["logRetentionDays"] = "90";
            form.Remove("failClosedAudit");
        }));
        AssertEx.Equal(303, response.StatusCode);
        AssertEx.Equal("/admin?saved=1", response.RedirectLocation);

        var saved = ServiceRuntime.Configuration.Load(out var generation);
        AssertEx.NotEqual(before, generation);
        AssertEx.Equal(90, saved.LogRetentionDays);
        AssertEx.False(saved.FailClosedOnAuditError);
        AssertEx.Equal(90, ServiceRuntime.LoadConfiguration().LogRetentionDays,
            "The running service must use the saved settings.");

        var audit = host.AuditLines();
        AssertEx.Equal(2, audit.Length);
        AssertEx.Contains("\"eventType\":\"configuration-change\"", audit[0]);
        AssertEx.Contains("\"result\":\"requested\"", audit[0]);
        AssertEx.Contains("\"result\":\"applied\"", audit[1]);
        foreach (var line in audit)
        {
            AssertEx.Contains("baseGeneration=" + before, line);
            AssertEx.Contains("FailClosedOnAuditError: True -> False", line);
            AssertEx.Contains("LogRetentionDays: 365 -> 90", line);
            AssertEx.Contains("\"userSid\":\"" + WindowsIdentity.GetCurrent().User.Value + "\"", line);
        }

        AssertEx.Contains("generation=" + generation, audit[1]);
        AssertEx.Equal(
            Regex.Match(audit[0], "\"correlationId\":\"([0-9a-f]+)\"").Groups[1].Value,
            Regex.Match(audit[1], "\"correlationId\":\"([0-9a-f]+)\"").Groups[1].Value,
            "The request and its outcome must share one correlation identifier.");

        // An invalid value is explained and nothing is saved.
        var invalid = Admin(AdminPost(Admin(AdminGet()), form => form["logRetentionDays"] = "0"));
        AssertEx.Equal(400, invalid.StatusCode);
        AssertEx.Contains("Audit log retention in days must be a whole number", invalid.Text);
        AssertEx.Equal(generation, ServiceRuntime.Configuration.GetGeneration());
    }

    [TestMethod(DisplayName = "Admin console rejects a stale settings version and self-lockout")]
    public void AdminRejectsStaleAndLockout()
    {
        using var host = new HandlerTestHost();
        host.Configure(configuration => configuration.AdminAllowedWindowsGroups = [AuthenticatedUsersSid]);
        var page = Admin(AdminGet());

        // Another administrator saves after this page was loaded.
        host.Configure(configuration => configuration.LogRetentionDays = 30);
        var current = ServiceRuntime.Configuration.GetGeneration();
        var stale = Admin(AdminPost(page, form => form["logRetentionDays"] = "90"));
        AssertEx.Equal(409, stale.StatusCode);
        AssertEx.Contains("Another administrator saved changes", stale.Text);
        AssertEx.Equal(current, ServiceRuntime.Configuration.GetGeneration());

        var lockout = Admin(AdminPost(Admin(AdminGet()), form => form["adminGroups"] = UnrelatedGroupSid));
        AssertEx.Equal(403, lockout.StatusCode);
        AssertEx.Contains("Keep at least one Windows group that includes your account.", lockout.Text);
        AssertEx.Equal(current, ServiceRuntime.Configuration.GetGeneration());
        AssertEx.Equal(0, host.AuditLines().Length);
    }

    [TestMethod(DisplayName = "Landing and health endpoints answer safe methods only")]
    public void LandingAndHealthEndpoints()
    {
        using var host = new HandlerTestHost();

        var home = new FakeHttpContext(new FakeHttpRequest("GET", "http://tsa.example.test/"));
        HomeHandler.Process(home);
        AssertEx.Equal(200, home.FakeResponse.StatusCode);
        AssertEx.Contains("/timestamp/rfc3161", home.FakeResponse.Text);
        AssertEx.False(home.FakeResponse.Text.Contains("Open Administration"),
            "The landing page must not advertise administration to a remote caller.");

        var post = new FakeHttpContext(new FakeHttpRequest("POST", "http://tsa.example.test/", []));
        HomeHandler.Process(post);
        AssertEx.Equal(405, post.FakeResponse.StatusCode);

        // Outside IIS no background probe can run, so health must report degraded, never healthy.
        var health = new FakeHttpContext(new FakeHttpRequest("GET", "http://tsa.example.test/health"));
        HealthHandler.Process(health);
        AssertEx.Equal(503, health.FakeResponse.StatusCode);
        AssertEx.Contains("\"status\":\"degraded\"", health.FakeResponse.Text);

        var healthPost = new FakeHttpContext(new FakeHttpRequest("POST", "http://tsa.example.test/health", []));
        HealthHandler.Process(healthPost);
        AssertEx.Equal(405, healthPost.FakeResponse.StatusCode);
    }

    private static void EnableRfc3161(ServiceConfiguration configuration)
    {
        configuration.Rfc3161Enabled = true;
        configuration.DefaultPolicyOid = TestFixtures.DefaultPolicyOid;
        configuration.AcceptedPolicyOids = [TestFixtures.DefaultPolicyOid];
    }

    private static FakeHttpRequest Rfc3161Post(byte[] body) =>
        new("POST", Rfc3161Url, body) { ContentType = "application/timestamp-query" };

    private static FakeHttpResponse Timestamp(FakeHttpRequest request, TimestampProtocol protocol)
    {
        var context = new FakeHttpContext(request);
        new TimestampHandler(protocol).ProcessAsync(context).GetAwaiter().GetResult();
        return context.FakeResponse;
    }

    private static FakeHttpRequest AdminGet() =>
        new("GET", AdminUrl, remoteAddress: "127.0.0.1") { Identity = WindowsIdentity.GetCurrent() };

    private static FakeHttpResponse Admin(FakeHttpRequest request)
    {
        var context = new FakeHttpContext(request);
        new AdminHandler().Process(context);
        return context.FakeResponse;
    }

    // Submits the form a rendered page would post, optionally edited first.
    private static FakeHttpRequest AdminPost(FakeHttpResponse page, Action<NameValueCollection> edit = null)
    {
        var request = new FakeHttpRequest("POST", AdminUrl, [], "127.0.0.1")
        {
            Identity = WindowsIdentity.GetCurrent()
        };
        request.Headers["Origin"] = "http://localhost";
        request.Cookies.Add(new HttpCookie("OpenTimeStamp.AdminCsrf", page.Cookies["OpenTimeStamp.AdminCsrf"].Value));

        var form = request.FormValues;
        foreach (Match input in Regex.Matches(page.Text, "<input\\b[^>]*>"))
        {
            var name = Attribute(input.Value, "name");
            var type = Attribute(input.Value, "type");
            if (name is null || input.Value.Contains(" disabled")) continue;
            if ((type is "checkbox" or "radio") && !input.Value.Contains(" checked")) continue;
            form.Add(name, HttpUtility.HtmlDecode(Attribute(input.Value, "value") ?? "on"));
        }

        foreach (Match area in Regex.Matches(
            page.Text, "<textarea\\b[^>]*name=\"([^\"]+)\"[^>]*>(.*?)</textarea>", RegexOptions.Singleline))
        {
            form.Add(area.Groups[1].Value, HttpUtility.HtmlDecode(area.Groups[2].Value));
        }

        foreach (Match select in Regex.Matches(
            page.Text, "<select\\b[^>]*name=\"([^\"]+)\"[^>]*>(.*?)</select>", RegexOptions.Singleline))
        {
            var chosen = Regex.Match(select.Groups[2].Value, "<option value=\"([^\"]*)\" selected");
            if (!chosen.Success) chosen = Regex.Match(select.Groups[2].Value, "<option value=\"([^\"]*)\"");
            form.Add(select.Groups[1].Value, HttpUtility.HtmlDecode(chosen.Groups[1].Value));
        }

        edit?.Invoke(form);
        return request;
    }

    private static string Attribute(string element, string name)
    {
        var match = Regex.Match(element, "\\b" + name + "=\"([^\"]*)\"");
        return match.Success ? match.Groups[1].Value : null;
    }
}
