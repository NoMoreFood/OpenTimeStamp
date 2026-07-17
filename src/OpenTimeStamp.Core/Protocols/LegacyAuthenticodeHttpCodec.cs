using System;
using System.Text;

namespace OpenTimeStamp.Protocols;

public static class LegacyAuthenticodeHttpCodec
{
    public static byte[] DecodeRequestBody(byte[] body)
    {
        if (body is null) throw new ArgumentNullException(nameof(body));

        // SignTool NUL-terminates its base64 MIME text on the wire.
        var textLength = body.Length;
        if (textLength != 0 && body[textLength - 1] == 0) textLength--;

        // Reject embedded terminators and non-ASCII input before invoking the MIME decoder.
        for (var index = 0; index < textLength; index++)
        {
            if (body[index] == 0 || body[index] > 0x7f)
            {
                throw new AuthenticodeProtocolException("The Authenticode request is not ASCII base64.");
            }
        }

        try
        {
            return Convert.FromBase64String(Encoding.ASCII.GetString(body, 0, textLength));
        }
        catch (FormatException ex)
        {
            throw new AuthenticodeProtocolException("The Authenticode request is not valid base64.", ex);
        }
    }

    public static byte[] EncodeResponseBody(byte[] encodedCms)
    {
        if (encodedCms is null) throw new ArgumentNullException(nameof(encodedCms));

        return Encoding.ASCII.GetBytes(Convert.ToBase64String(encodedCms));
    }
}
