using System;

namespace OpenTimeStamp.Asn1;

public class DerEncodingException(string message) : FormatException(message);

public sealed class DerSizeLimitException(string message) : DerEncodingException(message);
