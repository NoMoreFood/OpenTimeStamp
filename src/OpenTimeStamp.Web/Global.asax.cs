using System;
using System.Web;
using System.Web.Hosting;
using System.Web.Routing;
using OpenTimeStamp.Web.Handlers;
using OpenTimeStamp.Web.Infrastructure;
using OpenTimeStamp.Web.Routing;

namespace OpenTimeStamp.Web;

public class Global : HttpApplication
{
    protected void Application_Start(object sender, EventArgs e) => ApplicationStartup.Initialize();

    protected void Application_BeginRequest(object sender, EventArgs e) =>
        HttpSupport.ApplySecurityHeaders(Context.Response);

    protected void Application_EndRequest(object sender, EventArgs e) => RemoveFrameworkHeaders();

    protected void Application_PreSendRequestHeaders(object sender, EventArgs e) => RemoveFrameworkHeaders();

    protected void Application_End(object sender, EventArgs e)
    {
        TimestampHandler.ShutdownAdmission();
        ServiceRuntime.Shutdown();
    }

    protected void Application_Error(object sender, EventArgs e)
    {
        var exception = Server.GetLastError();
        if (exception == null || Context.Response.HeadersWritten) return;

        // Replace unhandled failures with a stable response that reveals no implementation detail.
        Server.ClearError();
        Context.Response.Clear();
        Context.Response.TrySkipIisCustomErrors = true;
        HttpSupport.WritePlainError(Context, 500, "The timestamp service encountered an internal error.");
    }

    private void RemoveFrameworkHeaders()
    {
        // Remove framework-disclosure headers at both IIS response boundaries.
        Context.Response.Headers.Remove("X-Powered-By");
        Context.Response.Headers.Remove("X-AspNet-Version");
        Context.Response.Headers.Remove("X-SourceFiles");
    }
}

public sealed class OpenTimeStampPreloadClient : IProcessHostPreloadClient
{
    public void Preload(string[] parameters) => ApplicationStartup.Initialize();
}

internal static class ApplicationStartup
{
    private static readonly object Gate = new();
    private static bool initialized;

    internal static void Initialize()
    {
        lock (Gate)
        {
            if (initialized) return;

            // Initialize process-wide services and routes before IIS exposes the application.
            ServiceRuntime.Initialize(HttpRuntime.AppDomainAppPath);
            TimestampHandler.InitializeAdmission();

            var routes = RouteTable.Routes;
            routes.RouteExistingFiles = false;
            routes.Add("Rfc3161", new Route("timestamp/rfc3161", new HandlerRouteHandler(() => new TimestampHandler(TimestampProtocol.Rfc3161))));
            routes.Add("Authenticode", new Route("timestamp/authenticode", new HandlerRouteHandler(() => new TimestampHandler(TimestampProtocol.Authenticode))));
            routes.Add("Admin", new Route("admin", new HandlerRouteHandler(() => new AdminHandler())));
            routes.Add("Health", new Route("health", new HandlerRouteHandler(() => new HealthHandler())));
            routes.Add("Home", new Route(string.Empty, new HandlerRouteHandler(() => new HomeHandler())));
            _ = HealthHandler.GetHealth();
            initialized = true;
        }
    }
}
