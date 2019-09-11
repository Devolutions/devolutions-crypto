namespace Devolutions.Cryptography
{
    using System;
    using System.Text;
    internal static partial class Utils
    {
        public static byte[] StringToByteArray(string data)
        {
            if (data == null)
            {
                return null;
            }

            return Encoding.UTF8.GetBytes(data);
        }

        public static string ToBase64String(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            return Convert.ToBase64String(bytes);
        }

        public static byte[] Base64StringToByteArray(string data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            try
            {
                return Convert.FromBase64String(data);
            }
            catch
            {
                return null;
            }
        }

        public static string ByteArrayToString(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            return Encoding.UTF8.GetString(data);
        }
    }
}