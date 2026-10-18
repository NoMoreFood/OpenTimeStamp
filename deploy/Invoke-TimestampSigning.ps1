#Requires -Version 5.1

<#
.SYNOPSIS
Signs and verifies a file using an HTTP or HTTPS OpenTimeStamp server.
.DESCRIPTION
Stages the signature before replacing the input file. HTTPS uses a temporary,
loopback-only transport for native signers that accept only HTTP timestamp URLs.
The upstream connection verifies the server's TLS certificate and never follows
redirects. Certificate stores and application security settings are not changed.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [Parameter(Mandatory = $true)][uri]$ServerUrl,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CertificateThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CertificateStoreLocation = 'CurrentUser',
    [ValidateSet('SignTool', 'PowerShell')][string]$Tool = 'SignTool',
    [string]$SignToolPath,
    [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$ExpectedTsaThumbprint,
    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ClientConfiguration.Common.ps1')
$endpoints = Get-ClientServerEndpoints -ServerUrl $ServerUrl -AllowInsecureHttp:$AllowInsecureHttp
$timestampUrl = if ($Tool -eq 'PowerShell') { $endpoints.AuthenticodeUrl } else { $endpoints.Rfc3161Url }
$file = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
if ($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReadOnly) {
    throw 'Select a writable file to sign.'
}
$certificate = Get-Item -LiteralPath "Cert:\$CertificateStoreLocation\My\$CertificateThumbprint"
if (-not $certificate.HasPrivateKey) { throw 'The signing certificate has no private key.' }
if ($Tool -eq 'SignTool') {
    if (-not $SignToolPath) {
        $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if (-not $command) { throw 'Supply SignToolPath or place SignTool on PATH.' }
        $SignToolPath = $command.Source
    }
    $SignToolPath = (Get-Item -LiteralPath $SignToolPath -ErrorAction Stop).FullName
}
if (-not $PSCmdlet.ShouldProcess($file.FullName, "Sign and verify with '$timestampUrl'")) { return }

if (-not ('OpenTimeStamp.Clients.TimestampTransport' -as [type])) {
    $compilerParameters = @{}
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $compilerParameters.ReferencedAssemblies = @('System.dll', 'System.Core.dll', 'System.Net.Http.dll')
    }
    Add-Type @compilerParameters -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenTimeStamp.Clients
{
    public sealed class TimestampTransport : IDisposable
    {
        private readonly TcpListener listener;
        private readonly Uri upstream;
        private readonly string path;
        private readonly Task worker;
        private readonly CancellationTokenSource shutdown = new CancellationTokenSource();
        private int disposed;
        public string Url { get; private set; }
        public string Error { get; private set; }

        public TimestampTransport(string url)
        {
            upstream = new Uri(url, UriKind.Absolute);
            if (upstream.Scheme != "https") throw new ArgumentException("An HTTPS upstream is required.");
            path = "/" + Guid.NewGuid().ToString("N");
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + path;
            worker = Task.Factory.StartNew(Run, CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        private void Run()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                {
                    if (!listener.Pending()) { shutdown.Token.WaitHandle.WaitOne(20); continue; }
                    using (var client = listener.AcceptTcpClient())
                    using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token))
                    using (deadline.Token.Register(client.Close))
                    {
                        // Bound the whole exchange as well as individual socket operations.
                        deadline.CancelAfter(TimeSpan.FromSeconds(45));
                        client.ReceiveTimeout = 10000;
                        client.SendTimeout = 10000;
                        using (var stream = client.GetStream())
                        {
                            try { Forward(stream, deadline.Token); }
                            catch (Exception exception)
                            {
                                if (shutdown.IsCancellationRequested) return;
                                Error = exception.GetBaseException().Message;
                                try
                                {
                                    Reply(stream, 502, "text/plain", Encoding.UTF8.GetBytes("Timestamp retrieval failed."));
                                }
                                catch (IOException) { }
                                catch (ObjectDisposedException) { }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                if (!shutdown.IsCancellationRequested) Error = exception.GetBaseException().Message;
            }
        }

        private void Forward(NetworkStream stream, CancellationToken cancellationToken)
        {
            // Bound the local request and accept only the private endpoint for this signing operation.
            var header = new StringBuilder();
            while (header.Length < 8192)
            {
                int value = stream.ReadByte();
                if (value < 0) throw new IOException("The timestamp client disconnected.");
                header.Append((char)value);
                if (header.Length >= 4 && header.ToString(header.Length - 4, 4) == "\r\n\r\n") break;
            }
            if (!header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
                throw new IOException("The timestamp request headers are too large.");
            var lines = header.ToString().Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines[0] != "POST " + path + " HTTP/1.1" && lines[0] != "POST " + path + " HTTP/1.0")
                throw new IOException("An unexpected timestamp request was rejected.");
            int length = -1;
            string contentType = "application/octet-stream";
            bool continueExpected = false;
            foreach (var line in lines)
            {
                int separator = line.IndexOf(':');
                if (separator < 0) continue;
                string name = line.Substring(0, separator).Trim();
                string value = line.Substring(separator + 1).Trim();
                if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    if (length != -1 || !int.TryParse(value, out length) || length <= 0 || length > 65536)
                        throw new IOException("The timestamp request length is invalid.");
                }
                if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Chunked timestamp requests are not accepted.");
                if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) contentType = value;
                if (name.Equals("Expect", StringComparison.OrdinalIgnoreCase))
                    continueExpected = value.Equals("100-continue", StringComparison.OrdinalIgnoreCase);
            }
            if (length <= 0) throw new IOException("The timestamp request length is missing.");
            if (continueExpected)
            {
                var acknowledgement = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
                stream.Write(acknowledgement, 0, acknowledgement.Length);
            }
            var body = new byte[length];
            for (int offset = 0; offset < length;)
            {
                int read = stream.Read(body, offset, length - offset);
                if (read == 0) throw new IOException("The timestamp request body is incomplete.");
                offset += read;
            }

            // Validate TLS independently of any caller-supplied certificate bypass and reject redirects.
            using (var handler = new HttpClientHandler())
            using (var request = new HttpRequestMessage(HttpMethod.Post, upstream))
            {
                handler.AllowAutoRedirect = false;
                handler.SslProtocols = SslProtocols.Tls12;
                handler.ServerCertificateCustomValidationCallback = (message, certificate, chain, errors) =>
                    errors == SslPolicyErrors.None;
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
                using (var http = new HttpClient(handler))
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(30));
                    http.Timeout = TimeSpan.FromSeconds(30);
                    using (var response = http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                        .GetAwaiter().GetResult())
                    // Closing the response also interrupts streams that ignore read cancellation.
                    using (timeout.Token.Register(response.Dispose))
                    {
                        if (response.StatusCode != HttpStatusCode.OK)
                            throw new IOException("The timestamp server did not return HTTP 200.");
                        using (var input = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                        using (var result = new MemoryStream())
                        {
                            var buffer = new byte[8192];
                            int read;
                            while ((read = input.ReadAsync(buffer, 0, buffer.Length, timeout.Token)
                                .GetAwaiter().GetResult()) > 0)
                            {
                                if (result.Length + read > 1048576)
                                    throw new IOException("The timestamp response is too large.");
                                result.Write(buffer, 0, read);
                            }
                            Reply(stream, 200, response.Content.Headers.ContentType.ToString(), result.ToArray());
                        }
                    }
                }
            }
        }

        private static void Reply(NetworkStream stream, int status, string contentType, byte[] body)
        {
            string reason = status == 200 ? "OK" : "Bad Gateway";
            var header = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + " " + reason + "\r\nContent-Type: " +
                contentType + "\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n");
            stream.Write(header, 0, header.Length);
            stream.Write(body, 0, body.Length);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            shutdown.Cancel();
            listener.Stop();
            if (worker.Wait(TimeSpan.FromSeconds(5))) shutdown.Dispose();
        }
    }
}
'@
}

$stage = Join-Path $file.DirectoryName ('.opentimestamp-' + [guid]::NewGuid().ToString('N') + '-' + $file.Name)
$transport = $null
try {
    $originalHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    [IO.File]::Copy($file.FullName, $stage, $false)
    if (([uri]$timestampUrl).Scheme -eq 'https') {
        $transport = New-Object OpenTimeStamp.Clients.TimestampTransport $timestampUrl
        $nativeTimestampUrl = $transport.Url
    }
    else { $nativeTimestampUrl = $timestampUrl }
    if ($Tool -eq 'PowerShell') {
        $signature = Set-AuthenticodeSignature -LiteralPath $stage -Certificate $certificate `
            -HashAlgorithm SHA256 -TimestampServer $nativeTimestampUrl
    }
    else {
        $arguments = @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $CertificateThumbprint,
            '/tr', $nativeTimestampUrl, '/td', 'SHA256')
        if ($CertificateStoreLocation -eq 'LocalMachine') { $arguments += '/sm' }
        $arguments += $stage
        $previousErrorAction = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = & $SignToolPath @arguments 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $previousErrorAction }
        if ($exitCode -ne 0) { throw "SignTool failed ($exitCode): $($output -join ' ')" }
        $signature = Get-AuthenticodeSignature -LiteralPath $stage
    }
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint -or
        -not $signature.TimeStamperCertificate -or
        ($ExpectedTsaThumbprint -and $signature.TimeStamperCertificate.Thumbprint -ne $ExpectedTsaThumbprint)) {
        throw 'A valid signature with the intended timestamp was not obtained.'
    }
    if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $originalHash) {
        throw 'The input file changed during signing; its newer contents were preserved.'
    }
    [IO.File]::Replace($stage, $file.FullName, [NullString]::Value)
    [pscustomobject]@{
        FilePath = $file.FullName
        Tool = $Tool
        TimestampUrl = $timestampUrl
        Status = [string]$signature.Status
        TsaThumbprint = $signature.TimeStamperCertificate.Thumbprint
        HttpsTransport = $null -ne $transport
        PowerShellArchitecture = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
    }
}
catch {
    if ($transport -and $transport.Error) { throw "HTTPS timestamp retrieval failed: $($transport.Error)" }
    throw
}
finally {
    if ($transport) { $transport.Dispose() }
    if ([IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
}
