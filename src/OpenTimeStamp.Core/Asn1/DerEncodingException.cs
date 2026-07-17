using System;

namespace OpenTimeStamp.Asn1;

public class DerEncodingException : FormatException
{
    public DerEncodingException(string message)
        : base(message)
    {
    }
}

public sealed class DerSizeLimitException : DerEncodingException
{
    public DerSizeLimitException(string message)
        : base(message)
    {
    }
}
