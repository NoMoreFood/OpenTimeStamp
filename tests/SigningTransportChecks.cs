namespace OpenTimeStamp.Clients
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Reflection;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public static class SigningTransportChecks
    {
        public static void Run()
        {
            // Disposal must interrupt an accepted connection whose request is incomplete.
            using (var transport = new TimestampTransport("https://127.0.0.1/timestamp/rfc3161"))
            using (var client = new TcpClient())
            {
                var endpoint = new Uri(transport.Url);
                client.Connect(endpoint.Host, endpoint.Port);
                client.ReceiveTimeout = 5000;
                var stream = client.GetStream();
                var headers = Encoding.ASCII.GetBytes("POST " + endpoint.AbsolutePath +
                    " HTTP/1.1\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n");
                stream.Write(headers, 0, headers.Length);
                ReadHeaders(stream);
                var timer = Stopwatch.StartNew();
                transport.Dispose();
                if (timer.Elapsed > TimeSpan.FromSeconds(3))
                    throw new Exception("Transport disposal waited for the incomplete request to time out.");
            }

            // Exercise the actual Framework response stream against a peer that stalls after its headers.
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            using (var release = new ManualResetEventSlim())
            {
                var server = Task.Run(() =>
                {
                    using (var peer = listener.AcceptTcpClient())
                    using (var stream = peer.GetStream())
                    {
                        peer.ReceiveTimeout = 10000;
                        ReadHeaders(stream);
                        var headers = Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n" +
                            "Content-Length: 2\r\nConnection: close\r\n\r\n");
                        stream.Write(headers, 0, headers.Length);
                        release.Wait(TimeSpan.FromSeconds(40));
                    }
                });
                try
                {
                    using (var transport = new TimestampTransport("https://127.0.0.1/timestamp/rfc3161"))
                    using (var client = new TcpClient())
                    {
                        // Substitute only the loopback test peer; production construction still requires HTTPS.
                        typeof(TimestampTransport).GetField("upstream", BindingFlags.NonPublic | BindingFlags.Instance)
                            .SetValue(transport, new Uri("http://127.0.0.1:" +
                                ((IPEndPoint)listener.LocalEndpoint).Port + "/timestamp/rfc3161"));
                        var endpoint = new Uri(transport.Url);
                        client.Connect(endpoint.Host, endpoint.Port);
                        client.ReceiveTimeout = 35000;
                        var request = Encoding.ASCII.GetBytes("POST " + endpoint.AbsolutePath +
                            " HTTP/1.1\r\nContent-Length: 1\r\nContent-Type: application/timestamp-query\r\n\r\nx");
                        var stream = client.GetStream();
                        stream.Write(request, 0, request.Length);
                        using (var reader = new StreamReader(stream))
                        {
                            var response = reader.ReadToEnd();
                            if (!response.StartsWith("HTTP/1.1 502", StringComparison.Ordinal) ||
                                string.IsNullOrEmpty(transport.Error))
                                throw new Exception("A stalled upstream response was not rejected at the deadline.");
                        }
                    }
                }
                finally
                {
                    release.Set();
                    listener.Stop();
                    server.GetAwaiter().GetResult();
                }
            }
        }

        private static void ReadHeaders(Stream stream)
        {
            var header = new StringBuilder();
            while (header.Length < 8192)
            {
                int value = stream.ReadByte();
                if (value < 0) throw new IOException("The test peer disconnected before completing its headers.");
                header.Append((char)value);
                if (header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal)) return;
            }
            throw new IOException("The test peer's headers exceeded the limit.");
        }
    }
}
