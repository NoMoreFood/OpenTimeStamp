using System;
using System.Web;
using System.Web.Routing;

namespace OpenTimeStamp.Web.Routing;

internal sealed class HandlerRouteHandler(Func<IHttpHandler> factory) : IRouteHandler
{
    private readonly Func<IHttpHandler> factory = factory ?? throw new ArgumentNullException(nameof(factory));

    public IHttpHandler GetHttpHandler(RequestContext requestContext) => factory();
}
