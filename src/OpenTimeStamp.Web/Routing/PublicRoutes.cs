using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Text.RegularExpressions;
using System.Web.Routing;
using OpenTimeStamp.Web.Handlers;

namespace OpenTimeStamp.Web.Routing;

internal sealed class PublicRoutes
{
    private static readonly Lazy<PublicRoutes> Configured = new(() => new(ConfigurationManager.AppSettings));

    internal static PublicRoutes Current => Configured.Value;

    internal string Timestamp { get; }
    internal string Rfc3161 { get; }
    internal string Authenticode { get; }
    internal string Health { get; }

    internal PublicRoutes(NameValueCollection settings)
    {
        // Reject aliases that collide with administration, IIS hidden segments, or another endpoint.
        HashSet<string> used = new(StringComparer.OrdinalIgnoreCase);
        Timestamp = Read("TimestampPath", "/timestamp");
        Rfc3161 = Read("Rfc3161Path", "/timestamp/rfc3161");
        Authenticode = Read("AuthenticodePath", "/timestamp/authenticode");
        Health = Read("HealthPath", "/health");

        string Read(string key, string fallback)
        {
            var path = settings[key] ?? fallback;
            if (path.Length > 256 || !Regex.IsMatch(path, @"\A/?[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\z") ||
                Regex.IsMatch(path,
                    @"(?:\A|/)(?:admin|bin|App_Data|App_Code|App_GlobalResources|App_LocalResources|" +
                    @"App_WebReferences|App_Browsers|aspnet_client)(?:/|\z)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
                !used.Add(path.TrimStart('/')))
            {
                throw new ConfigurationErrorsException(
                    key + " must be a unique path of letters, numbers, underscores, or hyphens, " +
                    "separated by slashes, outside reserved IIS and admin paths.");
            }
            return "/" + path.TrimStart('/');
        }
    }

    internal void Register(RouteCollection routes)
    {
        routes.Add("Timestamp", new Route(Timestamp.TrimStart('/'), new HandlerRouteHandler(
            () => new TimestampHandler(TimestampProtocol.Automatic))));
        routes.Add("Rfc3161", new Route(Rfc3161.TrimStart('/'), new HandlerRouteHandler(
            () => new TimestampHandler(TimestampProtocol.Rfc3161))));
        routes.Add("Authenticode", new Route(Authenticode.TrimStart('/'), new HandlerRouteHandler(
            () => new TimestampHandler(TimestampProtocol.Authenticode))));
        routes.Add("Health", new Route(Health.TrimStart('/'), new HandlerRouteHandler(() => new HealthHandler())));
        routes.Add("Admin", new Route("admin", new HandlerRouteHandler(() => new AdminHandler())));
        routes.Add("Home", new Route(string.Empty, new HandlerRouteHandler(() => new HomeHandler())));
    }
}
