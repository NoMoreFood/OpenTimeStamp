using System;
using System.IO;
using System.Security;
using System.Threading;

namespace OpenTimeStamp.Infrastructure;

/// <summary>Names the exception sets that catch filters across the service agree on.</summary>
public static class ExceptionFilters
{
    /// <summary>A file, directory, or ACL operation failed for an environmental reason.</summary>
    public static bool IsFileAccessFailure(this Exception exception) =>
        exception is IOException or UnauthorizedAccessException or SecurityException;

    /// <summary>The failure may be contained; process-fatal conditions must keep propagating.</summary>
    public static bool IsContainable(this Exception exception) =>
        exception is not OutOfMemoryException and not StackOverflowException and not ThreadAbortException;
}
