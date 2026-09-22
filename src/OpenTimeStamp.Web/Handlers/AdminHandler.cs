using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Web;
using OpenTimeStamp.Audit;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Issuance;
using OpenTimeStamp.Web.Infrastructure;

namespace OpenTimeStamp.Web.Handlers;

internal sealed class AdminHandler : IHttpHandler
{
    private const int RecentUserDisplayLimit = 20;
    private const int RecentRequestDisplayLimit = 50;
    private static readonly PropertyInfo[] AuditedConfigurationProperties =
        typeof(ServiceConfiguration).GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(property => property.IsDefined(typeof(DataMemberAttribute), false))
            .OrderBy(property => property.GetCustomAttribute<DataMemberAttribute>().Order)
            .ToArray();

    public bool IsReusable => false;

    public void ProcessRequest(HttpContext context)
    {
        // Enforce the local-network boundary before loading or disclosing configuration.
        if (!HttpSupport.IsLocalAdminRequest(context.Request))
        {
            HttpSupport.WritePlainError(context, 403, "The admin console is available only on the local server.");
            return;
        }

        ServiceConfiguration configuration;
        string generation;
        string loadError = null;
        try
        {
            configuration = ServiceRuntime.LoadConfiguration(out generation);
        }
        catch (ConfigurationErrorsException ex)
        {
            configuration = new ServiceConfiguration();
            loadError = ex.Message;
            try
            {
                generation = ServiceRuntime.Configuration.GetGeneration();
            }
            catch (ConfigurationErrorsException generationError)
            {
                generation = null;
                loadError += " " + generationError.Message;
            }
        }

        // Require an authenticated Windows administrator even in anonymous service mode.
        var identity = HttpSupport.GetRequestIdentity(context.Request);
        if (!IsAuthorized(configuration, context, identity)) return;

        if (string.Equals(context.Request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
        {
            var notice = context.Request.QueryString["saved"] == "1" ? "Settings saved." : loadError;
            Render(context, configuration, generation, notice, loadError == null ? null : "error");
            return;
        }

        if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers["Allow"] = "GET, POST";
            HttpSupport.WritePlainError(context, 405, "The admin console accepts only GET and POST requests.");
            return;
        }

        // Authenticate the state-changing request independently of the Windows session.
        if (!ValidateOrigin(context.Request) ||
            !CsrfTokenManager.Validate(context, context.Request.Form["csrf"], identity))
        {
            HttpSupport.WritePlainError(context, 403,
                "The request could not be verified. Refresh the page and try again.");
            return;
        }

        try
        {
            var submittedGeneration = Bounded(context.Request.Form["generation"], 80);
            if (string.IsNullOrEmpty(generation) ||
                !string.Equals(submittedGeneration, generation, StringComparison.Ordinal))
            {
                context.Response.StatusCode = 409;
                Render(context, configuration, generation,
                    "Another administrator saved changes after this page loaded. The latest settings are shown; " +
                    "review them before saving again.",
                    "error");
                return;
            }

            // Parse and validate the complete candidate configuration before any durable write.
            var fipsEnabled = PlatformSecurityPolicy.IsFipsEnabled;
            var updated = ReadConfiguration(context.Request, configuration, fipsEnabled);
            var errors = updated.Validate();
            var signingHash = HashAlgorithmCatalog.FindByName(updated.SigningDigestAlgorithm);
            if (!PlatformSecurityPolicy.IsSigningHashAllowed(signingHash))
                errors.Add("Windows FIPS mode does not allow the selected timestamp signing hash.");

            if (errors.Count == 0 &&
                (updated.Rfc3161Enabled || updated.AuthenticodeEnabled) &&
                !HealthPolicy.IsConfigurationPolicyUsable(updated, fipsEnabled))
            {
                errors.Add("The enabled timestamp endpoints have no allowed hash algorithms while Windows FIPS mode is enabled.");
            }

            if (errors.Count != 0)
            {
                context.Response.StatusCode = 400;
                Render(context, updated, generation, string.Join(" ", errors), "error");
                return;
            }

            if (updated.Rfc3161Enabled || updated.AuthenticodeEnabled)
            {
                if (!ServiceRuntime.Certificates.ValidateSelection(
                        updated,
                        HealthPolicy.GetRuntimeCertificateValidationTimeUtc(updated, DateTime.UtcNow),
                        out var reason))
                {
                    throw new ConfigurationErrorsException(reason);
                }
            }

            // Fail closed if the proposed group list would exclude the administrator applying it.
            if (!IsAuthorized(updated, context, identity)) return;

            var changeCorrelationId = Guid.NewGuid().ToString("N");
            var changeDetail = DescribeConfigurationChange(configuration, updated);
            var auditFailClosed = configuration.FailClosedOnAuditError || updated.FailClosedOnAuditError;
            var configurationSaved = false;
            string savedGeneration = null;
            try
            {
                // Record intent before the compare-and-swap, then record the durable
                // outcome with the same correlation identifier.
                WriteConfigurationAudit(context, identity, configuration, updated, changeCorrelationId,
                    "requested", changeDetail, auditFailClosed);
                savedGeneration = ServiceRuntime.Configuration.Save(updated, submittedGeneration);
                configurationSaved = true;
                ServiceRuntime.PublishConfiguration(updated, savedGeneration);
                HealthHandler.Invalidate();
                WriteConfigurationAudit(context, identity, updated, updated, changeCorrelationId,
                    "applied", changeDetail + "; generation=" + savedGeneration, auditFailClosed);
            }
            catch (Exception ex) when (ex is ConfigurationErrorsException or AuditLogException or
                                       UnauthorizedAccessException or System.IO.IOException or
                                       System.Security.Cryptography.CryptographicException)
            {
                TryWriteConfigurationFailureAudit(context, identity, configuration, updated,
                    changeCorrelationId, changeDetail, ex);

                if (ex is ConfigurationConflictException)
                {
                    context.Response.StatusCode = 409;
                    ReloadForConflict(out configuration, out generation);
                    Render(context, configuration, generation, ex.Message, "error");
                    return;
                }

                context.Response.StatusCode = ex is ConfigurationErrorsException ? 400 : 503;
                if (configurationSaved)
                {
                    Render(context, updated, savedGeneration,
                        "Settings were saved, but the change could not be recorded in the audit log. " +
                        "Verify the audit log before making additional changes.",
                        "error");
                }
                else
                {
                    Render(context, configuration, generation, ex.Message, "error");
                }

                return;
            }

            var adminPath = (context.Request.ApplicationPath == "/" ? string.Empty : context.Request.ApplicationPath.TrimEnd('/')) + "/admin?saved=1";
            context.Response.StatusCode = 303;
            context.Response.RedirectLocation = adminPath;
            context.Response.TrySkipIisCustomErrors = true;
        }
        catch (Exception ex) when (ex is ConfigurationErrorsException or AuditLogException or
                                   UnauthorizedAccessException or System.IO.IOException or
                                   System.Security.Cryptography.CryptographicException or IssuanceStateException)
        {
            context.Response.StatusCode = ex is ConfigurationErrorsException ? 400 : 503;
            Render(context, configuration, generation, ex.Message, "error");
        }
    }

    private static void ReloadForConflict(out ServiceConfiguration configuration, out string generation)
    {
        try
        {
            configuration = ServiceRuntime.LoadConfiguration(out generation);
        }
        catch (ConfigurationErrorsException)
        {
            configuration = new ServiceConfiguration();
            try
            {
                generation = ServiceRuntime.Configuration.GetGeneration();
            }
            catch (ConfigurationErrorsException)
            {
                generation = null;
            }
        }
    }

    private static void WriteConfigurationAudit(
        HttpContext context,
        RequestIdentity identity,
        ServiceConfiguration retentionConfiguration,
        ServiceConfiguration targetConfiguration,
        string correlationId,
        string result,
        string detail,
        bool failClosed)
    {
        ServiceRuntime.Audit.Write(new AuditRecord
        {
            TimestampUtc = DateTime.UtcNow,
            EventType = "configuration-change",
            Result = result,
            CorrelationId = correlationId,
            Protocol = "admin",
            Username = identity.Name,
            UserSid = identity.Sid,
            AuthenticationType = identity.AuthenticationType,
            RemoteAddress = context.Request.ServerVariables["REMOTE_ADDR"],
            CertificateThumbprint = targetConfiguration.CertificateThumbprint,
            Detail = detail
        }, retentionConfiguration.LogRolloverInterval, retentionConfiguration.PruneAuditLogs,
            retentionConfiguration.LogRetentionDays, failClosed);
    }

    private static void TryWriteConfigurationFailureAudit(
        HttpContext context,
        RequestIdentity identity,
        ServiceConfiguration retentionConfiguration,
        ServiceConfiguration targetConfiguration,
        string correlationId,
        string detail,
        Exception exception)
    {
        try
        {
            WriteConfigurationAudit(context, identity, retentionConfiguration, targetConfiguration,
                correlationId, "failed", detail + "; failure=" + exception.GetType().Name, false);
        }
        catch (AuditLogException)
        {
            // Preserve the original save or audit failure.
        }
    }

    internal static string DescribeConfigurationChange(ServiceConfiguration before, ServiceConfiguration after)
    {
        List<string> changed = [];
        foreach (var property in AuditedConfigurationProperties)
        {
            if (!SameConfigurationValue(property, property.GetValue(before), property.GetValue(after)))
                changed.Add(property.Name);
        }

        return "before=" + ConfigurationDigest(before) +
               "; after=" + ConfigurationDigest(after) +
               "; changed=" + (changed.Count == 0 ? "none" : string.Join(",", changed));
    }

    private static string ConfigurationDigest(ServiceConfiguration configuration)
    {
        StringBuilder canonical = new();
        foreach (var property in AuditedConfigurationProperties)
            AppendConfigurationDigestValue(canonical, property, property.GetValue(configuration));
        return HttpSupport.ToHex(WindowsHash.ComputeSha256(Encoding.UTF8.GetBytes(canonical.ToString())));
    }

    private static bool SameConfigurationValue(PropertyInfo property, object left, object right)
    {
        if (property.PropertyType == typeof(string)) return Same((string)left, (string)right);
        if (typeof(IEnumerable<string>).IsAssignableFrom(property.PropertyType))
            return SameList((IEnumerable<string>)left, (IEnumerable<string>)right);
        return Equals(left, right);
    }

    private static void AppendConfigurationDigestValue(StringBuilder builder, PropertyInfo property, object value)
    {
        if (property.PropertyType == typeof(string))
        {
            var text = (string)value;
            if (property.Name == nameof(ServiceConfiguration.CertificateThumbprint))
                text = ConfigurationStore.NormalizeThumbprint(text);
            AppendComparableDigestValue(builder, text);
            return;
        }

        if (typeof(IEnumerable<string>).IsAssignableFrom(property.PropertyType))
        {
            AppendComparableDigestList(builder, (IEnumerable<string>)value);
            return;
        }

        AppendDigestValue(builder, value);
    }

    private static void AppendComparableDigestList(StringBuilder builder, IEnumerable<string> values)
    {
        var list = values?.ToList() ?? [];
        AppendDigestValue(builder, list.Count);
        foreach (var value in list) AppendComparableDigestValue(builder, value);
    }

    private static void AppendComparableDigestValue(StringBuilder builder, string value) =>
        AppendDigestValue(builder, Comparable(value));

    private static void AppendDigestValue(StringBuilder builder, object value)
    {
        var text = Convert.ToString(value, CultureInfo.InvariantCulture) ?? "<null>";
        builder.Append(text.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(text).Append('|');
    }

    private static bool Same(string left, string right) =>
        string.Equals(Comparable(left), Comparable(right), StringComparison.Ordinal);

    private static bool SameList(IEnumerable<string> left, IEnumerable<string> right) =>
        (left ?? []).Select(Comparable).SequenceEqual((right ?? []).Select(Comparable), StringComparer.Ordinal);

    private static string Comparable(string value) =>
        (value ?? string.Empty).Trim().ToUpperInvariant();

    private static bool IsAuthorized(ServiceConfiguration configuration, HttpContext context, RequestIdentity identity)
    {
        // Use the IIS logon token for group checks rather than trusting supplied identity text.
        WindowsIdentity windowsIdentity = null;
        try
        {
            windowsIdentity = context.Request.LogonUserIdentity;
        }
        catch (System.Security.SecurityException)
        {
            // The authorization check below fails closed when IIS withholds the token.
        }

        if (!identity.IsAuthenticated || windowsIdentity == null || !windowsIdentity.IsAuthenticated)
        {
            context.Response.Headers["WWW-Authenticate"] = "Negotiate";
            HttpSupport.WritePlainError(context, 401, "Windows authentication is required to open the admin console.");
            return false;
        }

        try
        {
            var principal = new WindowsPrincipal(windowsIdentity);
            var groups = configuration.AdminAllowedWindowsGroups ?? [];
            if (groups.Count == 0 || !groups.Any(group => IsInRole(principal, group)))
            {
                HttpSupport.WritePlainError(context, 403,
                    "Your account is not a member of a Windows group allowed to administer OpenTimeStamp.");
                return false;
            }
        }
        catch (System.Security.SecurityException)
        {
            HttpSupport.WritePlainError(context, 403,
                "Windows could not verify your administrative group membership.");
            return false;
        }

        return true;
    }

    private static bool IsInRole(WindowsPrincipal principal, string configuredGroup)
    {
        if (principal == null || string.IsNullOrWhiteSpace(configuredGroup)) return false;

        try
        {
            var value = configuredGroup.Trim();
            var sid = value.StartsWith("S-", StringComparison.OrdinalIgnoreCase)
                ? new SecurityIdentifier(value)
                : (SecurityIdentifier)new NTAccount(value).Translate(typeof(SecurityIdentifier));

            return principal.IsInRole(sid);
        }
        catch (Exception ex) when (ex is ArgumentException or IdentityNotMappedException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool ValidateOrigin(HttpRequest request)
    {
        var source = request.Headers["Origin"];
        if (string.IsNullOrWhiteSpace(source)) source = request.UrlReferrer?.GetLeftPart(UriPartial.Authority);
        if (string.IsNullOrWhiteSpace(source)) return false;

        return Uri.TryCreate(source, UriKind.Absolute, out var parsed) &&
               request.Url != null &&
               string.Equals(parsed.Scheme, request.Url.Scheme, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(parsed.Host, request.Url.Host, StringComparison.OrdinalIgnoreCase) &&
               parsed.Port == request.Url.Port &&
               string.IsNullOrEmpty(parsed.UserInfo);
    }

    private static ServiceConfiguration ReadConfiguration(
        HttpRequest request,
        ServiceConfiguration original,
        bool fipsEnabled)
    {
        // Read protocol and policy controls while preserving FIPS-disabled legacy values.
        var updated = original.Clone();
        updated.Rfc3161Enabled = IsChecked(request, "rfc3161");
        updated.AuthenticodeEnabled = ResolveAuthenticodeEnabled(
            fipsEnabled,
            original.AuthenticodeEnabled,
            IsChecked(request, "authenticode"));
        updated.DefaultPolicyOid = Bounded(request.Form["defaultPolicy"], 256);
        updated.AcceptedPolicyOids = SplitList(request.Form["acceptedPolicies"], 64, 256);
        if (!string.IsNullOrWhiteSpace(updated.DefaultPolicyOid) && !updated.AcceptedPolicyOids.Contains(updated.DefaultPolicyOid, StringComparer.Ordinal))
            updated.AcceptedPolicyOids.Add(updated.DefaultPolicyOid);

        updated.AllowedHashAlgorithms = ResolveAllowedHashAlgorithms(
            fipsEnabled,
            original.AllowedHashAlgorithms,
            request.Form.GetValues("hash") ?? []);

        // Parse bounded operational and audit controls from the form.
        updated.SigningDigestAlgorithm = Bounded(request.Form["signingHash"], 16);
        updated.IncludeCertificateChain = IsChecked(request, "includeChain");
        updated.AccuracySeconds = ParseInteger(
            request.Form["accuracySeconds"], 0, 86400, "Published time accuracy in seconds");
        updated.AccuracyMilliseconds = ParseInteger(
            request.Form["accuracyMilliseconds"], 0, 999, "Published time accuracy in milliseconds");
        updated.Ordering = IsChecked(request, "ordering");
        updated.MaxRequestBytes = ParseInteger(
            request.Form["maxRequestBytes"], 1024, 1048576, "Maximum request size in bytes");
        updated.LogRetentionDays = ParseInteger(
            request.Form["logRetentionDays"], 1, 3650, "Audit log retention in days");
        updated.LogRolloverInterval = Bounded(request.Form["logRolloverInterval"], 16);
        updated.PruneAuditLogs = IsChecked(request, "pruneAuditLogs");
        updated.FailClosedOnAuditError = IsChecked(request, "failClosedAudit");
        updated.LogMessageImprints = IsChecked(request, "logImprints");
        updated.ClockRollbackToleranceSeconds = ParseInteger(
            request.Form["clockTolerance"], 0, 300, "Allowed backward clock adjustment in seconds");
        updated.AdminAllowedWindowsGroups = SplitList(request.Form["adminGroups"], 32, 256);
        updated.AllowUntrustedDevelopmentCertificate = IsChecked(request, "allowUntrustedDevelopmentCertificate");
        updated.CertificateSelectionMode = Bounded(request.Form["certificateSelectionMode"], 16);

        // Decode the compound store-location and thumbprint certificate selection.
        var certificate = Bounded(request.Form["certificate"], 256);
        if (string.Equals(certificate, "none", StringComparison.Ordinal))
        {
            updated.CertificateThumbprint = null;
        }
        else if (!string.IsNullOrEmpty(certificate))
        {
            var separator = certificate.IndexOf('|');
            if (separator <= 0 || separator == certificate.Length - 1)
            {
                throw new ConfigurationErrorsException("Select a valid timestamp signing certificate.");
            }

            updated.CertificateStoreLocation = certificate.Substring(0, separator);
            updated.CertificateStoreName = "My";
            updated.CertificateThumbprint = certificate.Substring(separator + 1);
        }

        return updated;
    }

    internal static bool ResolveAuthenticodeEnabled(
        bool fipsEnabled,
        bool originallyEnabled,
        bool submittedEnabled) =>
        fipsEnabled ? originallyEnabled && submittedEnabled : submittedEnabled;

    internal static List<string> ResolveAllowedHashAlgorithms(
        bool fipsEnabled,
        IEnumerable<string> originallyAllowed,
        IEnumerable<string> submitted)
    {
        var originalLegacy = new HashSet<string>(
            (originallyAllowed ?? [])
            .Select(HashAlgorithmCatalog.NormalizeName)
            .Where(value => HashAlgorithmCatalog.FindByName(value)?.IsLegacy == true),
            StringComparer.Ordinal);

        return (submitted ?? [])
            .Select(HashAlgorithmCatalog.NormalizeName)
            .Where(value =>
            {
                var algorithm = HashAlgorithmCatalog.FindByName(value);
                return algorithm != null &&
                       (!fipsEnabled || !algorithm.IsLegacy || originalLegacy.Contains(value));
            })
            .Distinct(StringComparer.Ordinal)
            .Take(16)
            .ToList();
    }

    private static void Render(
        HttpContext context,
        ServiceConfiguration configuration,
        string generation,
        string notice,
        string noticeClass)
    {
        var csrf = CsrfTokenManager.GetOrCreate(context, HttpSupport.GetRequestIdentity(context.Request));
        var certificates = ServiceRuntime.Certificates.ListCertificates(
            false,
            configuration.SigningDigestAlgorithm,
            configuration.AuthenticodeEnabled);

        // Build the fixed administrative shell and its current status notices.
        var builder = new StringBuilder(16384);
        builder.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>OpenTimeStamp Administration</title>")
            .Append("<style>:root{color-scheme:light;--ink:#17212b;--muted:#5b6b7c;--primary:#0b5cab;--primary-dark:#08477f;--accent:#0e8a76;--border:#d7e0e8;--surface:#fff;--surface-soft:#f7f9fc;--shadow:0 12px 30px rgba(32,55,79,.08)}*{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#edf4fb 0,#f5f7fa 18rem);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:92rem;margin:auto;padding:clamp(1rem,3vw,2.5rem)}h1,h2{line-height:1.2}h1{margin:.1rem 0 .35rem;font-size:clamp(1.7rem,3vw,2.35rem);letter-spacing:-.035em}h2{margin:0;font-size:1.35rem;letter-spacing:-.015em}a{color:var(--primary);text-underline-offset:.18em}.page-header{display:flex;gap:1rem;align-items:center;margin-bottom:2rem;padding:1.35rem 1.5rem;background:linear-gradient(135deg,#fff 35%,#f1f7fc);border:1px solid rgba(11,92,171,.16);border-radius:1rem;box-shadow:var(--shadow)}.brand-mark{display:grid;place-items:center;flex:0 0 3.25rem;height:3.25rem;border-radius:.8rem;background:linear-gradient(135deg,var(--primary),#1785bd);color:#fff;font-size:.8rem;font-weight:800;letter-spacing:.08em;box-shadow:0 8px 18px rgba(11,92,171,.22)}.eyebrow{margin:0 0 .25rem;color:var(--primary);font-size:.72rem;font-weight:800;letter-spacing:.11em;text-transform:uppercase}.page-header .muted{margin:0}.section-title{display:flex;align-items:end;justify-content:space-between;gap:1rem;margin:0 0 1rem}.section-title .muted{margin:.35rem 0 0}.refresh{display:inline-flex;align-items:center;flex:0 0 auto;padding:.5rem .8rem;border:1px solid #b9cee2;border-radius:999px;background:rgba(255,255,255,.8);font-weight:700;text-decoration:none}.refresh:hover{background:#fff;border-color:var(--primary)}.dashboard{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1rem;margin:0 0 1rem}.card{min-width:0;padding:1rem 1.1rem;background:var(--surface);border:1px solid var(--border);border-top:3px solid #8da4b8;border-radius:.75rem;box-shadow:0 5px 16px rgba(32,55,79,.045)}.card.status{border-top-color:#d29222}.card.certificate{border-top-color:#7867b7}.card.outcomes{border-top-color:var(--accent)}.card.worker{border-top-color:var(--primary)}.card-label{color:var(--muted);font-size:.76rem;font-weight:750;letter-spacing:.055em;text-transform:uppercase}.card strong{display:block;margin:.3rem 0 .1rem;font-size:1.2rem;line-height:1.25}.card .muted{display:block;overflow-wrap:anywhere}.generation{display:block;margin-top:.15rem;color:#40586e}.section,fieldset{background:var(--surface);border:1px solid var(--border);border-radius:.8rem;box-shadow:0 5px 18px rgba(32,55,79,.04)}.section{margin:1rem 0;padding:1.25rem 1.4rem}.section h2{margin-bottom:.4rem}.section .muted{margin-top:0}form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}fieldset{min-width:0;margin:0;padding:1rem 1.25rem 1.2rem}fieldset:last-of-type{grid-column:1/-1}legend{padding:0 .35rem;color:#26394a;font-weight:800}label{display:block;margin:.75rem 0;color:#314355;font-weight:650}.inline{display:inline-flex;align-items:flex-start;gap:.3rem;margin:.35rem 1rem .35rem 0;font-weight:500}input[type=checkbox],input[type=radio]{margin-top:.28rem;accent-color:var(--primary)}input[type=text],input[type=number],select,textarea{display:block;width:100%;max-width:48rem;margin-top:.3rem;padding:.62rem .7rem;background:#fbfcfe;border:1px solid #aebbc7;border-radius:.4rem;color:var(--ink);font:inherit;transition:border-color .15s,box-shadow .15s}input[type=text]:focus,input[type=number]:focus,select:focus,textarea:focus{outline:0;border-color:var(--primary);box-shadow:0 0 0 3px rgba(11,92,171,.14)}textarea{min-height:5.5rem;resize:vertical}.help{margin:.2rem 0 1rem;padding:.85rem 1rem;background:#eef6fd;border:1px solid #c9deef;border-radius:.55rem;color:#314b61}.help p{margin:0 0 .45rem}.help ul{margin:.35rem 0 0;padding-left:1.2rem}.help li+li{margin-top:.35rem}.table-wrap{overflow:auto;border:1px solid #e0e6ec;border-radius:.55rem}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;border-bottom:1px solid #e0e6ec;padding:.65rem .7rem;vertical-align:top}th{background:var(--surface-soft);color:#314355;font-size:.78rem;letter-spacing:.025em}tbody tr:last-child td{border-bottom:0}tbody tr:hover td{background:#fafcfe}td[colspan]{color:var(--muted)}.muted{color:var(--muted)}.notice,.warning{margin:1rem 0;padding:.8rem 1rem;border-radius:.45rem}.notice{background:#e8f5e9;border-left:4px solid #2e7d32}.notice.error{background:#ffebee;border-color:#b71c1c}.warning{background:#fff8e1;border-left:4px solid #d99a12}button{grid-column:1/-1;justify-self:start;padding:.75rem 1.15rem;background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff;border:0;border-radius:.45rem;font:inherit;font-weight:750;box-shadow:0 7px 16px rgba(11,92,171,.2);cursor:pointer}button:hover{filter:brightness(1.08)}button:focus-visible,.refresh:focus-visible{outline:3px solid rgba(11,92,171,.28);outline-offset:2px}code{font-size:.9em;overflow-wrap:anywhere}@media(max-width:64rem){.dashboard{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:46rem){main{padding:1rem}.page-header{align-items:flex-start;padding:1rem}.brand-mark{flex-basis:2.75rem;height:2.75rem}.section-title{align-items:flex-start;flex-direction:column}.dashboard,form{grid-template-columns:1fr}fieldset:last-of-type{grid-column:auto}.section{padding:1rem}.refresh{align-self:flex-start}}</style></head><body><main>")
            .Append("<header class=\"page-header\"><div class=\"brand-mark\" aria-hidden=\"true\">OTS</div><div><p class=\"eyebrow\">Local Management Console</p><h1>OpenTimeStamp Administration</h1><p class=\"muted\">This console is available only on the local server. IIS controls authentication; it cannot be changed here.</p></div></header>");
        if (!string.IsNullOrEmpty(notice))
        {
            builder.Append("<div class=\"notice ").Append(H(noticeClass)).Append("\">").Append(H(notice)).Append("</div>");
        }

        if (PlatformSecurityPolicy.IsFipsEnabled)
        {
            builder.Append("<div class=\"warning\"><strong>Windows FIPS mode is enabled.</strong> " +
                "Legacy Authenticode, MD5 and SHA-1 request hashes, and SHA-1 timestamp signatures are disabled " +
                "regardless of the saved settings.</div>");
        }

        AppendDashboard(builder, context, configuration, generation);

        // Render service, algorithm, time, and audit policy controls.
        builder.Append("<form method=\"post\" action=\"").Append(H(CsrfTokenManager.AdminPath(context.Request)))
            .Append("\"><input type=\"hidden\" name=\"csrf\" value=\"").Append(H(csrf)).Append("\">")
            .Append("<input type=\"hidden\" name=\"generation\" value=\"").Append(H(generation)).Append("\">")
            .Append("<fieldset><legend>Timestamp Endpoints</legend><p><strong>IIS authentication mode:</strong> ").Append(H(configuration.AuthenticationMode)).Append("</p>")
            .Append(Check("rfc3161", "Enable the RFC 3161 endpoint", configuration.Rfc3161Enabled, false))
            .Append(Check("authenticode", "Enable the legacy Authenticode endpoint", configuration.AuthenticodeEnabled,
                PlatformSecurityPolicy.IsFipsEnabled && !configuration.AuthenticodeEnabled))
            .Append("<label>Default RFC 3161 Policy OID<input name=\"defaultPolicy\" type=\"text\" maxlength=\"256\" value=\"").Append(H(configuration.DefaultPolicyOid)).Append("\" placeholder=\"Your organization’s assigned policy OID\"></label>")
            .Append("<label>Allowed RFC 3161 Policy OIDs (One per Line)<textarea name=\"acceptedPolicies\" maxlength=\"8192\">").Append(H(string.Join(Environment.NewLine, configuration.AcceptedPolicyOids ?? []))).Append("</textarea></label></fieldset>")
            .Append("<fieldset><legend>Cryptography</legend><p>Allowed request hash algorithms:</p>");
        foreach (var algorithm in HashAlgorithmCatalog.All)
        {
            var configured = (configuration.AllowedHashAlgorithms ?? [])
                .Contains(algorithm.Name, StringComparer.OrdinalIgnoreCase);
            var disabled = PlatformSecurityPolicy.IsFipsEnabled && algorithm.IsLegacy && !configured;
            var label = FormatHashName(algorithm.Name) + (algorithm.IsLegacy ? " (legacy)" : string.Empty);
            builder.Append(Check("hash", label, configured, disabled, algorithm.Name));
        }

        builder.Append("<label>Timestamp Signing Hash Algorithm<select name=\"signingHash\">");
        foreach (var algorithm in HashAlgorithmCatalog.All.Where(item => item.CmsSigningSupported && (!PlatformSecurityPolicy.IsFipsEnabled || !item.IsLegacy)))
        {
            builder.Append("<option value=\"").Append(H(algorithm.Name)).Append("\"")
                .Append(string.Equals(algorithm.Name, HashAlgorithmCatalog.NormalizeName(configuration.SigningDigestAlgorithm), StringComparison.Ordinal) ? " selected" : string.Empty)
                .Append(">").Append(H(FormatHashName(algorithm.Name))).Append("</option>");
        }

        builder.Append("</select></label>").Append(Check("includeChain",
                "Include intermediate CA certificates in timestamp responses when requested",
                configuration.IncludeCertificateChain,
                false))
            .Append("</fieldset><fieldset><legend>Time and Request Limits</legend>")
            .Append("<div class=\"help\"><p><strong>Recommended:</strong> Keep these defaults unless your " +
                "timestamp policy or clients require different behavior.</p><ul>")
            .Append("<li><strong>Published time accuracy:</strong> Leave both values at zero unless your " +
                "organization documents and monitors a guaranteed clock accuracy. These values are included " +
                "in RFC 3161 responses.</li>")
            .Append("<li><strong>Timestamp ordering:</strong> Leave this off unless clients require every " +
                "timestamp to be later than the previous timestamp.</li>")
            .Append("<li><strong>Backward clock adjustment:</strong> Two seconds allows small Windows Time " +
                "corrections. Use a larger value only when your time-sync policy requires it. This value cannot " +
                "exceed the published time accuracy.</li>")
            .Append("<li><strong>Maximum request size:</strong> 65,536 bytes works for most clients. " +
                "Increase it only for known larger requests; smaller limits reduce unnecessary input " +
                "processing.</li></ul></div>")
            .Append(Number("accuracySeconds", "Published Time Accuracy (Seconds)", configuration.AccuracySeconds, 0, 86400))
            .Append(Number("accuracyMilliseconds", "Published Time Accuracy (Milliseconds)", configuration.AccuracyMilliseconds, 0, 999))
            .Append(Check("ordering", "Require each timestamp to be later than the previous timestamp", configuration.Ordering, false))
            .Append(Number("clockTolerance", "Allowed Backward Clock Adjustment (Seconds)", configuration.ClockRollbackToleranceSeconds, 0, 300))
            .Append(Number("maxRequestBytes", "Maximum Request Size (Bytes)", configuration.MaxRequestBytes, 1024, 1048576)).Append("</fieldset>")
            .Append("<fieldset><legend>Audit Logging</legend><label>Audit Log Rotation<select name=\"logRolloverInterval\">")
            .Append(Option(ServiceConfiguration.DailyLogRollover, configuration.LogRolloverInterval))
            .Append(Option(ServiceConfiguration.HourlyLogRollover, configuration.LogRolloverInterval))
            .Append(Option(ServiceConfiguration.WeeklyLogRollover, configuration.LogRolloverInterval))
            .Append("</select></label>")
            .Append(Check("pruneAuditLogs", "Automatically delete audit logs after the retention period", configuration.PruneAuditLogs, false))
            .Append(Number("logRetentionDays", "Keep Audit Logs (Days)", configuration.LogRetentionDays, 1, 3650))
            .Append(Check("failClosedAudit", "Stop timestamping if the audit log cannot be written", configuration.FailClosedOnAuditError, false))
            .Append(Check("logImprints", "Include request hashes in the audit log", configuration.LogMessageImprints, false))
            .Append("<label>Windows Groups or SIDs Allowed to Administer OpenTimeStamp (One per Line)<textarea name=\"adminGroups\" maxlength=\"8192\">").Append(H(string.Join(Environment.NewLine, configuration.AdminAllowedWindowsGroups ?? []))).Append("</textarea></label></fieldset>")
            .Append("<fieldset><legend>Timestamp Signing Certificate</legend><label>Selection Mode<select name=\"certificateSelectionMode\">")
            .Append(Option(ServiceConfiguration.ManualCertificateSelection, configuration.CertificateSelectionMode))
            .Append(Option(ServiceConfiguration.AutomaticCertificateSelection, configuration.CertificateSelectionMode))
            .Append("</select></label><p class=\"muted\">Automatic mode uses the eligible certificate with the " +
                "latest expiration date and checks again periodically. Manual mode uses the certificate selected below.</p>")
            .Append(Check("allowUntrustedDevelopmentCertificate",
                "Development only — allow an untrusted certificate or one whose revocation status cannot be verified",
                configuration.AllowUntrustedDevelopmentCertificate,
                false))
            .Append(configuration.AllowUntrustedDevelopmentCertificate
                ? "<div class=\"warning\"><strong>Development certificate checks are relaxed.</strong> " +
                    "Do not use this setting on a production timestamp server.</div>"
                : string.Empty)
            .Append("<p class=\"muted\">" +
                "Certificates are read from the Local Computer\\Personal store and the IIS application pool " +
                "account’s Current User\\Personal store. A certificate must be valid, have a critical Time Stamping " +
                "enhanced key usage (EKU) with no other EKUs, and use an RSA key of at least 2048 bits or a supported " +
                "pure ML-DSA key. " +
                "ML-DSA is RFC 3161-only; legacy Authenticode requires RSA. " +
                "Saving verifies certificate trust and that the service account can use the private key.</p>" +
                "<div class=\"table-wrap\"><table><thead><tr>" +
                "<th>Select</th><th>Store</th><th>Subject</th><th>Expires</th><th>Thumbprint</th><th>Status</th>" +
                "</tr></thead><tbody>");

        var normalizedSelectedThumbprint = ConfigurationStore.NormalizeThumbprint(configuration.CertificateThumbprint);
        var selectedCertificateAvailable = certificates.Any(certificate =>
            certificate.IsEligible &&
            string.Equals(certificate.Thumbprint, normalizedSelectedThumbprint, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(certificate.StoreLocation.ToString(), configuration.CertificateStoreLocation, StringComparison.OrdinalIgnoreCase));
        builder.Append("<tr><td><input type=\"radio\" name=\"certificate\" value=\"none\"")
            .Append(string.IsNullOrEmpty(normalizedSelectedThumbprint) || !selectedCertificateAvailable ? " checked" : string.Empty)
            .Append("></td><td colspan=\"4\">No certificate selected for Manual mode</td>" +
                "<td>Automatic mode does not require a selected certificate. Manual mode does.</td></tr>");

        // Render eligible certificates and metadata from both supported Windows stores.
        foreach (var certificate in certificates)
        {
            var selected = certificate.Thumbprint != null &&
                string.Equals(certificate.Thumbprint, normalizedSelectedThumbprint, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(certificate.StoreLocation.ToString(), configuration.CertificateStoreLocation, StringComparison.OrdinalIgnoreCase);
            builder.Append("<tr><td>");
            if (certificate.IsEligible)
            {
                builder.Append("<input type=\"radio\" name=\"certificate\" value=\"").Append(H(certificate.StoreLocation + "|" + certificate.Thumbprint)).Append("\"")
                    .Append(selected ? " checked" : string.Empty).Append(">");
            }
            builder.Append("</td><td>").Append(H(FormatCertificateStore(certificate.StoreLocation)))
                .Append("</td><td>").Append(H(certificate.Subject))
                .Append("</td><td>").Append(H(certificate.NotAfter == default ? string.Empty : certificate.NotAfter.ToString("u", CultureInfo.InvariantCulture)))
                .Append("</td><td><code>").Append(H(certificate.Thumbprint)).Append("</code></td><td>")
                .Append(certificate.IsEligible
                    ? "Eligible; trust and private-key access are verified when settings are saved"
                    : H(certificate.IneligibilityReason)).Append("</td></tr>");
        }

        if (certificates.Count == 0)
            builder.Append("<tr><td colspan=\"6\">No eligible timestamp signing certificates were found.</td></tr>");

        // Complete and emit the escaped administrative document.
        builder.Append("</tbody></table></div></fieldset><button type=\"submit\">Save Configuration</button>" +
            "</form></main></body></html>");
        context.Response.TrySkipIisCustomErrors = true;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers["Referrer-Policy"] = "same-origin";
        context.Response.Write(builder.ToString());
    }

    private static void AppendDashboard(
        StringBuilder builder,
        HttpContext context,
        ServiceConfiguration configuration,
        string generation)
    {
        var health = HealthHandler.GetHealth();
        var requests = ServiceRuntime.GetRecentRequests(ServiceRuntime.RecentRequestCapacity);
        var manualThumbprint = ConfigurationStore.NormalizeThumbprint(configuration.CertificateThumbprint);
        var certificateStatus = configuration.UsesAutomaticCertificateSelection
            ? "The service automatically uses the eligible certificate with the latest expiration date."
            : string.IsNullOrEmpty(manualThumbprint)
                ? "No certificate is selected for Manual mode."
                : "Manual mode uses the certificate selected below.";
        var healthStatus = !health.HasSnapshot
            ? health.Refreshing ? "Checking" : "Degraded"
            : health.Healthy ? "Healthy" : "Degraded";
        var healthDetail = !health.HasSnapshot
            ? health.Refreshing
                ? "The initial service health check is running."
                : "No service health result is available."
            : !health.Healthy && !string.IsNullOrWhiteSpace(health.Detail)
                ? "Issue: " + health.Detail + (health.Refreshing
                    ? " A new health check is running."
                    : health.Stale ? " This result is out of date." : string.Empty)
                : health.Refreshing || health.Stale
                    ? "The service is healthy; a new health check is running."
                    : "All enabled timestamp endpoints are ready.";
        DateTime? certificateExpirationUtc = null;
        string certificateSha256Thumbprint = null;
        try
        {
            using var certificate = ServiceRuntime.Certificates.GetSelectedCertificate(configuration);
            certificateExpirationUtc = certificate.NotAfter.ToUniversalTime();
            certificateSha256Thumbprint = FormatCertificateSha256Thumbprint(certificate.RawData);
        }
        catch (Exception ex) when (ex is CertificateSelectionException or
                                   System.Security.Cryptography.CryptographicException or
                                   System.IO.IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException)
        {
            // Certificate availability is already represented by service health; keep the dashboard usable.
        }

        var application = context.Request.ApplicationPath == "/"
            ? string.Empty
            : context.Request.ApplicationPath.TrimEnd('/');
        builder.Append("<div class=\"section-title\"><div><p class=\"eyebrow\">Operations</p><h2>Dashboard</h2>" +
                "<p class=\"muted\">Current service status and recent timestamp activity. Recent activity resets " +
                "when the IIS application pool restarts. Times on this page use the server’s local time and UTC " +
                "offset; audit logs use UTC.</p></div><a class=\"refresh\" href=\"")
            .Append(H(application + "/admin"))
            .Append("\">Refresh</a></div><div class=\"dashboard\">")
            .Append("<div class=\"card status\"><span class=\"card-label\">Service Health</span><strong>")
            .Append(H(healthStatus))
            .Append("</strong><span class=\"muted\">").Append(H(healthDetail)).Append(" Windows FIPS mode: ")
            .Append(health.FipsEnabled ? "Enabled." : "Disabled.")
            .Append("</span></div><div class=\"card certificate\"><span class=\"card-label\">Certificate Selection</span><strong>")
            .Append(H(configuration.CertificateSelectionMode))
            .Append("</strong><span class=\"muted\">")
            .Append(H(certificateStatus))
            .Append("</span></div>");
        AppendCertificateCard(builder, certificateExpirationUtc, certificateSha256Thumbprint);
        builder.Append("<div class=\"card worker\"><span class=\"card-label\">Service Started</span>" +
                "<strong style=\"white-space:nowrap;font-size:clamp(.95rem,1.25vw,1.12rem);" +
                "font-variant-numeric:tabular-nums\">")
            .Append(H(FormatAdminTime(ServiceRuntime.StartedUtc)))
            .Append("</strong><span class=\"muted\">Configuration ID<code class=\"generation\" " +
                "style=\"white-space:nowrap\" title=\"")
            .Append(H(generation ?? "Unavailable"))
            .Append("\">")
            .Append(H(FormatConfigurationId(generation)))
            .Append("</code></span></div></div>");

        AppendRecentActivity(builder, requests);
        builder.Append("<div class=\"section-title configuration-title\"><div><p class=\"eyebrow\">Service Settings</p>" +
            "<h2>Configuration</h2><p class=\"muted\">Configure timestamp endpoints, security, time, " +
            "audit logging, and certificate selection.</p></div></div>");
    }

    internal static void AppendCertificateCard(
        StringBuilder builder,
        DateTime? expirationUtc,
        string sha256Thumbprint)
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));

        builder.Append("<div class=\"card\" style=\"border-top-color:var(--accent)\">" +
            "<span class=\"card-label\">Certificate</span>");
        if (!expirationUtc.HasValue || string.IsNullOrEmpty(sha256Thumbprint))
        {
            builder.Append("<strong>Unavailable</strong><span class=\"muted\">" +
                "No usable timestamp signing certificate is available.</span></div>");
            return;
        }

        builder.Append("<strong style=\"white-space:nowrap;font-size:clamp(.9rem,1.15vw,1.08rem);" +
                "font-variant-numeric:tabular-nums\">Expires ")
            .Append(H(FormatAdminTime(expirationUtc.Value)))
            .Append("</strong><span class=\"muted\">SHA-256 Thumbprint</span>" +
                "<code style=\"display:block;margin-top:.15rem;color:#40586e;word-break:break-all\">")
            .Append(H(sha256Thumbprint))
            .Append("</code></div>");
    }

    internal static string FormatCertificateSha256Thumbprint(byte[] rawCertificate)
    {
        if (rawCertificate is null) throw new ArgumentNullException(nameof(rawCertificate));
        return BitConverter.ToString(WindowsHash.ComputeSha256(rawCertificate)).Replace("-", string.Empty);
    }

    internal static void AppendRecentActivity(
        StringBuilder builder,
        IReadOnlyList<RecentRequestActivity> requests)
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        if (requests is null) throw new ArgumentNullException(nameof(requests));

        builder.Append("<div class=\"section\"><h2>Recent Activity by User</h2>" +
            "<p class=\"muted\">The summary covers up to ")
            .Append(ServiceRuntime.RecentRequestCapacity.ToString(CultureInfo.InvariantCulture))
            .Append(" timestamp results recorded during the past ")
            .Append(ServiceRuntime.RecentRequestMaximumAgeHours.ToString(CultureInfo.InvariantCulture))
            .Append(" hours; up to ")
            .Append(RecentUserDisplayLimit.ToString(CultureInfo.InvariantCulture))
            .Append(" users are shown. Requests rejected before audit logging are not included.</p>" +
                "<div class=\"table-wrap\"><table><thead><tr>" +
                "<th>User</th><th>Authentication Type</th><th>Last Client Address</th>" +
                "<th>Last Request (Local Time)</th>" +
                "<th>Recent Result Count</th></tr></thead><tbody>");
        var users = requests
            .GroupBy(
                record => !string.IsNullOrWhiteSpace(record.UserSid)
                    ? "sid|" + record.UserSid
                    : string.IsNullOrWhiteSpace(record.Username)
                    ? "anonymous|" + (record.RemoteAddress ?? string.Empty)
                    : "user|" + record.Username,
                StringComparer.OrdinalIgnoreCase)
            .Select(group => new { Latest = group.First(), Count = group.Count() })
            .Take(RecentUserDisplayLimit)
            .ToList();
        foreach (var user in users)
        {
            builder.Append("<tr><td>").Append(H(string.IsNullOrWhiteSpace(user.Latest.Username) ? "Anonymous" : user.Latest.Username))
                .Append("</td><td>").Append(H(user.Latest.AuthenticationType))
                .Append("</td><td><code>").Append(H(user.Latest.RemoteAddress))
                .Append("</code></td><td>").Append(H(FormatAdminTime(user.Latest.TimestampUtc)))
                .Append("</td><td>").Append(user.Count.ToString(CultureInfo.InvariantCulture)).Append("</td></tr>");
        }

        if (users.Count == 0)
            builder.Append("<tr><td colspan=\"5\">No timestamp requests have been recorded since the service started.</td></tr>");

        var displayedRequestCount = Math.Min(requests.Count, RecentRequestDisplayLimit);
        builder.Append("</tbody></table></div></div><div class=\"section\"><h2>Recent Timestamp Results</h2>" +
            "<p class=\"muted\">Showing ")
            .Append(displayedRequestCount.ToString(CultureInfo.InvariantCulture)).Append(" of ")
            .Append(requests.Count.ToString(CultureInfo.InvariantCulture))
            .Append(" results in recent history.</p><div class=\"table-wrap\"><table>" +
                "<thead><tr><th>Time (Local)</th><th>User</th><th>Client Address</th><th>Protocol</th><th>Result</th>" +
                "<th>Processing Time</th><th>Correlation ID</th></tr></thead><tbody>");
        foreach (var request in requests.Take(displayedRequestCount))
        {
            builder.Append("<tr><td>").Append(H(FormatAdminTime(request.TimestampUtc)))
                .Append("</td><td>").Append(H(string.IsNullOrWhiteSpace(request.Username) ? "Anonymous" : request.Username))
                .Append("</td><td><code>").Append(H(request.RemoteAddress))
                .Append("</code></td><td>").Append(H(FormatProtocol(request.Protocol)))
                .Append("</td><td>").Append(H(FormatResult(request.Result)))
                .Append("</td><td>").Append(request.DurationMilliseconds.ToString(CultureInfo.InvariantCulture))
                .Append(" ms</td><td><code>").Append(H(request.CorrelationId)).Append("</code></td></tr>");
        }

        if (requests.Count == 0)
            builder.Append("<tr><td colspan=\"7\">No timestamp results are available in recent history.</td></tr>");
        builder.Append("</tbody></table></div></div>");
    }

    private static string Option(string value, string selected) =>
        "<option value=\"" + H(value) + "\"" +
        (string.Equals(value, selected, StringComparison.OrdinalIgnoreCase) ? " selected" : string.Empty) +
        ">" + H(value) + "</option>";

    internal static string FormatConfigurationId(string generation)
    {
        if (string.IsNullOrWhiteSpace(generation)) return "Unavailable";
        const string prefix = "sha256:";
        return generation.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            generation.Length > prefix.Length + 12
                ? prefix + generation.Substring(prefix.Length, 12)
                : generation;
    }

    internal static string FormatHashName(string name) =>
        HashAlgorithmCatalog.NormalizeName(name) switch
        {
            "SHA1" => "SHA-1",
            "SHA224" => "SHA-224",
            "SHA256" => "SHA-256",
            "SHA384" => "SHA-384",
            "SHA512" => "SHA-512",
            var normalized => normalized
        };

    internal static string FormatProtocol(string protocol) =>
        (protocol ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "rfc3161" => "RFC 3161",
            "authenticode" => "Authenticode",
            var value => value
        };

    internal static string FormatResult(string result) =>
        (result ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "granted" => "Successful",
            "rejected" => "Rejected",
            "error" => "Error",
            var value => value
        };

    private static string FormatCertificateStore(StoreLocation location) =>
        location == StoreLocation.LocalMachine ? "Local Computer\\Personal" : "Current User\\Personal";

    internal static string FormatAdminTime(DateTime timestampUtc)
    {
        var utc = timestampUtc.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(timestampUtc, DateTimeKind.Utc)
            : timestampUtc.ToUniversalTime();
        return new DateTimeOffset(utc).ToLocalTime()
            .ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
    }

    private static string Check(string name, string label, bool isChecked, bool disabled, string value = "on") =>
        "<label class=\"inline\"><input type=\"checkbox\" name=\"" + H(name) + "\" value=\"" + H(value) + "\"" +
        (isChecked ? " checked" : string.Empty) + (disabled ? " disabled" : string.Empty) + "> " + H(label) + "</label>";

    private static string Number(string name, string label, int value, int minimum, int maximum) =>
        "<label>" + H(label) + "<input name=\"" + H(name) + "\" type=\"number\" min=\"" + minimum.ToString(CultureInfo.InvariantCulture) +
        "\" max=\"" + maximum.ToString(CultureInfo.InvariantCulture) + "\" value=\"" + value.ToString(CultureInfo.InvariantCulture) + "\"></label>";

    private static bool IsChecked(HttpRequest request, string name) => request.Form.GetValues(name) != null;

    private static int ParseInteger(string value, int minimum, int maximum, string label)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed < minimum || parsed > maximum)
            throw new ConfigurationErrorsException(label + " must be a whole number from " +
                minimum.ToString(CultureInfo.InvariantCulture) + " through " +
                maximum.ToString(CultureInfo.InvariantCulture) + ".");

        return parsed;
    }

    private static string Bounded(string value, int maximumLength)
    {
        value = (value ?? string.Empty).Trim();
        if (value.Length > maximumLength)
            throw new ConfigurationErrorsException("A submitted value is longer than the admin console allows.");

        return value.Length == 0 ? null : value;
    }

    private static List<string> SplitList(string value, int maximumItems, int maximumItemLength)
    {
        List<string> result = [];
        foreach (var item in (value ?? string.Empty).Split(['\r', '\n', ',', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            var normalized = item.Trim();
            if (normalized.Length > maximumItemLength)
                throw new ConfigurationErrorsException("A submitted list entry is longer than the admin console allows.");

            if (normalized.Length != 0 && !result.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(normalized);
                if (result.Count > maximumItems)
                    throw new ConfigurationErrorsException("A submitted list contains more entries than the admin console allows.");
            }
        }

        return result;
    }

    private static string H(object value) =>
        HttpUtility.HtmlEncode(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty);
}
