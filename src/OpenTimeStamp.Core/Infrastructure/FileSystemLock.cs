using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace OpenTimeStamp.Infrastructure;

internal static class FileSystemLock
{
    public static FileStream Acquire(
        string path,
        TimeSpan wait,
        Func<IOException, Exception> createTimeoutException,
        CancellationToken cancellationToken)
    {
        var timer = Stopwatch.StartNew();
        IOException lastContention = null;
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        while (true)
        {
            try
            {
                // A stable sibling inherits the protected parent ACL, while FileShare.None
                // coordinates every process and Windows session using the same path.
                return new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.None);
            }
            catch (IOException ex) when (IsContention(ex))
            {
                lastContention = ex;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (timer.Elapsed >= wait) throw createTimeoutException(lastContention);

            if (!cancellationToken.CanBeCanceled)
            {
                Thread.Sleep(25);
            }
            else if (cancellationToken.WaitHandle.WaitOne(25))
            {
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
    }

    // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION are the only retryable open failures.
    private static bool IsContention(IOException exception) =>
        (exception.HResult & 0xffff) is 32 or 33;
}
