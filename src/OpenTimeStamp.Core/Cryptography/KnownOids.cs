namespace OpenTimeStamp.Cryptography;

// Protocol identifiers are fixed by their standards, so they are constants rather than
// values looked up in the machine's OID registry.
internal static class KnownOids
{
    internal const string Md5 = "1.2.840.113549.2.5";
    internal const string Sha1 = "1.3.14.3.2.26";
    internal const string Sha224 = "2.16.840.1.101.3.4.2.4";
    internal const string Sha256 = "2.16.840.1.101.3.4.2.1";
    internal const string Sha384 = "2.16.840.1.101.3.4.2.2";
    internal const string Sha512 = "2.16.840.1.101.3.4.2.3";
    internal const string MlDsa44 = "2.16.840.1.101.3.4.3.17";
    internal const string MlDsa65 = "2.16.840.1.101.3.4.3.18";
    internal const string MlDsa87 = "2.16.840.1.101.3.4.3.19";
    internal const string TimeStampingEku = "1.3.6.1.5.5.7.3.8";
    internal const string Pkcs7Data = "1.2.840.113549.1.7.1";
    internal const string Pkcs7SignedData = "1.2.840.113549.1.7.2";
    internal const string AuthenticodeCounterSignature = "1.3.6.1.4.1.311.3.2.1";
    internal const string TstInfoContentType = "1.2.840.113549.1.9.16.1.4";
    internal const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    internal const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    internal const string CmsAlgorithmProtection = "1.2.840.113549.1.9.52";
}
