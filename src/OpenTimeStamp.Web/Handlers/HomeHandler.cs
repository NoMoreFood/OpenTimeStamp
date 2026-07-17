using System;
using System.Text;
using System.Web;
using OpenTimeStamp.Web.Infrastructure;

namespace OpenTimeStamp.Web.Handlers;

internal sealed class HomeHandler : IHttpHandler
{
    private const string Styles = """
        :root{color-scheme:light;--ink:#17212b;--muted:#5b6b7c;--primary:#0b5cab;--primary-dark:#08477f;
        --accent:#0e8a76;--border:#d7e0e8;--surface:#fff;--surface-soft:#f7f9fc;
        --shadow:0 12px 30px rgba(32,55,79,.08)}
        *{box-sizing:border-box}
        body{margin:0;background:linear-gradient(180deg,#edf4fb 0,#f5f7fa 18rem);color:var(--ink);
        font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
        main{max-width:92rem;margin:auto;padding:clamp(1rem,3vw,2.5rem)}
        h1,h2,h3{line-height:1.2}h1{margin:.1rem 0 .35rem;font-size:clamp(1.9rem,4vw,2.7rem);
        letter-spacing:-.04em}h2{margin:0;font-size:1.5rem;letter-spacing:-.02em}
        h3{margin:.75rem 0 .35rem;font-size:1.2rem}p{margin:.35rem 0}a{color:var(--primary);text-underline-offset:.18em}
        .page-header{display:flex;gap:1rem;align-items:center;margin-bottom:2rem;padding:1.35rem 1.5rem;
        background:linear-gradient(135deg,#fff 35%,#f1f7fc);border:1px solid rgba(11,92,171,.16);
        border-radius:1rem;box-shadow:var(--shadow)}
        .brand-mark{display:grid;place-items:center;flex:0 0 3.25rem;height:3.25rem;border-radius:.8rem;
        background:linear-gradient(135deg,var(--primary),#1785bd);color:#fff;font-size:.8rem;font-weight:800;
        letter-spacing:.08em;box-shadow:0 8px 18px rgba(11,92,171,.22)}
        .eyebrow{margin:0 0 .25rem;color:var(--primary);font-size:.72rem;font-weight:800;letter-spacing:.11em;
        text-transform:uppercase}.muted{color:var(--muted)}.page-header .muted{margin:0;max-width:62rem}
        .section-title{margin:0 0 1rem}.section-title .muted{margin:.35rem 0 0;max-width:64rem}
        .endpoints{display:grid;grid-template-columns:repeat(auto-fit,minmax(17rem,1fr));gap:1rem;margin-bottom:1rem}
        .endpoint{display:flex;flex-direction:column;min-width:0;padding:1.25rem;background:var(--surface);
        border:1px solid var(--border);border-top:3px solid #8da4b8;border-radius:.8rem;
        box-shadow:0 5px 18px rgba(32,55,79,.05)}
        .endpoint.recommended{border-top-color:var(--accent)}.endpoint.legacy{border-top-color:#7867b7}
        .endpoint.health{border-top-color:var(--primary)}.endpoint.admin{border-top-color:#d29222}
        .endpoint-heading{display:flex;align-items:center;justify-content:space-between;gap:.75rem}
        .method{display:inline-flex;align-items:center;padding:.2rem .5rem;border-radius:999px;background:#e8f2fb;
        color:var(--primary-dark);font-size:.7rem;font-weight:800;letter-spacing:.055em}
        .recommended .method{background:#e8f5f1;color:#087161}.legacy .method{background:#f0edfa;color:#5f4fa2}
        .admin .method{background:#fff3db;color:#8a5b08}.endpoint .muted{flex:1}
        .path{display:block;margin:.8rem 0;padding:.62rem .7rem;overflow-wrap:anywhere;background:var(--surface-soft);
        border:1px solid #e0e6ec;border-radius:.45rem;color:#29445c;font-size:.88rem}
        .detail{margin:.25rem 0 0;color:#40586e;font-size:.88rem}.detail strong{color:#26394a}
        .action{display:inline-flex;align-self:flex-start;margin-top:.9rem;padding:.48rem .72rem;border:1px solid #b9cee2;
        border-radius:999px;background:#fff;font-weight:750;text-decoration:none}.action:hover{border-color:var(--primary)}
        .quick-start{margin-top:1rem;padding:1.35rem 1.5rem;background:var(--surface);border:1px solid var(--border);
        border-radius:.8rem;box-shadow:0 5px 18px rgba(32,55,79,.04)}
        .quick-start>p{max-width:64rem}.examples{display:grid;grid-template-columns:repeat(auto-fit,minmax(22rem,1fr));
        gap:1rem;margin-top:1rem}.example{min-width:0;padding:1rem;background:var(--surface-soft);
        border:1px solid #e0e6ec;border-radius:.55rem}.example h3{margin-top:0}.example .muted{min-height:3rem}
        .command{display:block;margin:.75rem 0 0;padding:1rem;overflow:auto;
        background:#17212b;border-radius:.55rem;color:#eaf2f8;font:13px/1.55 Consolas,monospace;
        white-space:pre-wrap;overflow-wrap:anywhere}
        .note{margin-top:1rem;padding:.85rem 1rem;background:#eef6fd;border:1px solid #c9deef;
        border-radius:.55rem;color:#314b61}
        @media(max-width:46rem){main{padding:1rem}.page-header{align-items:flex-start;padding:1rem}.brand-mark{flex-basis:2.75rem;
        height:2.75rem}.endpoints{grid-template-columns:1fr}.quick-start{padding:1rem}}
        """;

    public bool IsReusable => false;

    public void ProcessRequest(HttpContext context)
    {
        // Limit discovery responses to safe, cache-free retrieval methods.
        if (!string.Equals(context.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(context.Request.HttpMethod, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers["Allow"] = "GET, HEAD";
            HttpSupport.WritePlainError(context, 405, "The service landing page accepts only GET and HEAD requests.");
            return;
        }

        context.Response.StatusCode = 200;
        context.Response.TrySkipIisCustomErrors = true;
        context.Response.ContentType = "text/html; charset=utf-8";
        if (string.Equals(context.Request.HttpMethod, "HEAD", StringComparison.OrdinalIgnoreCase)) return;

        // Advertise public endpoints without exposing local administration remotely.
        var application = context.Request.ApplicationPath == "/"
            ? string.Empty
            : context.Request.ApplicationPath.TrimEnd('/');
        var authority = context.Request.Url.GetLeftPart(UriPartial.Authority);
        context.Response.Write(Render(application, authority, HttpSupport.IsLocalAdminRequest(context.Request)));
    }

    internal static string Render(string application, string authority, bool showAdministration)
    {
        application = (application ?? string.Empty).TrimEnd('/');
        authority = (authority ?? string.Empty).TrimEnd('/');
        var root = authority + application;
        var rfc3161Path = application + "/timestamp/rfc3161";
        var authenticodePath = application + "/timestamp/authenticode";
        var healthPath = application + "/health";
        var adminPath = application + "/admin";
        var rfc3161Url = root + "/timestamp/rfc3161";
        var authenticodeUrl = root.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            ? root + "/timestamp/authenticode"
            : "http://<server>" + authenticodePath;

        StringBuilder builder = new(12288);
        builder.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
                "<meta name=\"viewport\" content=\"width=device-width\"><title>OpenTimeStamp</title><style>")
            .Append(Styles)
            .Append("</style></head><body><main>" +
                "<header class=\"page-header\"><div class=\"brand-mark\" aria-hidden=\"true\">OTS</div><div>" +
                "<p class=\"eyebrow\">Timestamp Service</p><h1>OpenTimeStamp</h1>" +
                "<p class=\"muted\">This server issues cryptographic timestamps that prove when a file or " +
                "signature existed. Use RFC 3161 unless your software specifically requires the legacy " +
                "Authenticode protocol.</p></div></header>" +
                "<section aria-labelledby=\"endpoint-heading\"><div class=\"section-title\">" +
                "<p class=\"eyebrow\">Service Directory</p><h2 id=\"endpoint-heading\">Timestamp Endpoints</h2>" +
                "<p class=\"muted\">Send timestamp requests to the endpoint supported by your client. " +
                "Endpoint availability and authentication are controlled by the server administrator.</p></div>" +
                "<div class=\"endpoints\">" +
                "<article class=\"endpoint recommended\"><div class=\"endpoint-heading\"><h3>RFC 3161</h3>" +
                "<span class=\"method\">POST · RECOMMENDED</span></div>" +
                "<p class=\"muted\">The current standard for timestamping signed files and documents. " +
                "Use this endpoint with SignTool <code>/tr</code> and specify a timestamp hash with <code>/td</code>.</p>" +
                "<code class=\"path\">")
            .Append(H(rfc3161Path))
            .Append("</code><p class=\"detail\"><strong>Request:</strong> application/timestamp-query<br>" +
                "<strong>Response:</strong> application/timestamp-reply</p></article>" +
                "<article class=\"endpoint legacy\"><div class=\"endpoint-heading\"><h3>Legacy Authenticode</h3>" +
                "<span class=\"method\">POST · LEGACY</span></div>" +
                "<p class=\"muted\">For older Microsoft signing clients that require SignTool <code>/t</code>. " +
                "This endpoint can be disabled by server policy and is unavailable in Windows FIPS mode.</p>" +
                "<code class=\"path\">")
            .Append(H(authenticodePath))
            .Append("</code><p class=\"detail\"><strong>Content type:</strong> application/octet-stream</p></article>" +
                "<article class=\"endpoint health\"><div class=\"endpoint-heading\"><h3>Service Health</h3>" +
                "<span class=\"method\">GET</span></div>" +
                "<p class=\"muted\">Returns a compact JSON health result for monitoring systems and load balancers. " +
                "HTTP 200 means healthy; HTTP 503 means degraded.</p><code class=\"path\">")
            .Append(H(healthPath))
            .Append("</code><a class=\"action\" href=\"")
            .Append(HA(healthPath))
            .Append("\">Check Service Health</a></article>");

        if (showAdministration)
        {
            builder.Append("<article class=\"endpoint admin\"><div class=\"endpoint-heading\">" +
                    "<h3>Local Administration</h3><span class=\"method\">GET · POST</span></div>" +
                    "<p class=\"muted\">Configure endpoints, certificates, audit logging, and service policy. " +
                    "The admin console is available only on this server and requires an authorized Windows account.</p>" +
                    "<code class=\"path\">")
                .Append(H(adminPath))
                .Append("</code><a class=\"action\" href=\"")
                .Append(HA(adminPath))
                .Append("\">Open Administration</a></article>");
        }

        builder.Append("</div></section><section class=\"quick-start\" aria-labelledby=\"quick-start-heading\">" +
                "<p class=\"eyebrow\">Client Examples</p><h2 id=\"quick-start-heading\">Common Client Commands</h2>" +
                "<p class=\"muted\">Use these examples from a Windows client. Replace the sample file names " +
                "and add the authentication options required by your administrator.</p><div class=\"examples\">" +
                "<article class=\"example\"><h3>SignTool — Timestamp a Signed File</h3>" +
                "<p class=\"muted\">Applies an RFC 3161 timestamp using SHA-256. The file must already have " +
                "an Authenticode signature.</p><code class=\"command\">")
            .Append(H("signtool timestamp /tr " + rfc3161Url + " /td SHA256 signed-file.exe"))
            .Append("</code></article><article class=\"example\"><h3>PowerShell — Sign and Timestamp a Script</h3>" +
                "<p class=\"muted\">Signs a PowerShell script with a code-signing certificate, then uses the " +
                "legacy Authenticode endpoint to timestamp the signature. Replace the certificate thumbprint " +
                "and server placeholder as needed. This cmdlet requires the legacy endpoint over HTTP.</p>" +
                "<code class=\"command\">")
            .Append(H("$certificate = Get-Item 'Cert:\\CurrentUser\\My\\<code-signing-thumbprint>'" +
                Environment.NewLine + Environment.NewLine +
                "Set-AuthenticodeSignature `" + Environment.NewLine +
                "    -FilePath '.\\script.ps1' `" + Environment.NewLine +
                "    -Certificate $certificate `" + Environment.NewLine +
                "    -HashAlgorithm SHA256 `" + Environment.NewLine +
                "    -IncludeChain All `" + Environment.NewLine +
                "    -TimestampServer '" + authenticodeUrl + "'"))
            .Append("</code></article></div><div class=\"note\"><strong>Client authentication:</strong> " +
                "Your administrator may require Windows credentials. Configure the calling application or service " +
                "account accordingly.</div></section></main></body></html>");
        return builder.ToString();
    }

    private static string H(string value) => HttpUtility.HtmlEncode(value ?? string.Empty);

    private static string HA(string value) => HttpUtility.HtmlAttributeEncode(value ?? string.Empty);
}
