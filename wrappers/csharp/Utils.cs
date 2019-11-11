namespace Devolutions.Cryptography
{
    using System;
    using System.Text;
    
    public static partial class Utils
    {
        public static bool ValidateCiphertextSignature(byte[] data, DataType type = DataType.Cipher)
        {
            if(data == null)
            {
                return false;
            }

            if(data.Length >= 8)
            {
                byte[] typeBytes = BitConverter.GetBytes((UInt16) type);
                if(!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(typeBytes);
                }

                return data[0] == '\xD' && data[1] == '\xC' && data[2] == typeBytes[0] && data[3] == typeBytes[1];
            }

            return false;
        }

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

            return Encode(bytes);
        }

        public static byte[] Base64StringToByteArray(string data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            return Decode(data);
        }

        public static string ByteArrayToString(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            try
            {
                return Encoding.UTF8.GetString(data);
            }
            catch
            {
                return null;
            }
        }

        public static byte[] Decode(string data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            int length = GetDecodedLength(data);

            if(length == 0)
            {
                return null;
            }

            byte[] buffer = new byte[length];

            long decode_res = Native.DecodeNative(data, (UIntPtr)data.Length, buffer, (UIntPtr)buffer.Length);

            if (decode_res == -1)
                return null;
            
            return buffer;
        }

        public static string Encode(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            int length = GetEncodedLength(data);

            if(length == 0)
            {
                return null;
            }
            
            byte[] buffer = new byte[length];

            long encode_res = Native.EncodeNative(data, (UIntPtr)data.Length, buffer, (UIntPtr)buffer.Length);

            return ByteArrayToString(buffer);
        }

        public static int GetEncodedLength(byte[] buffer)
        {
            if(buffer == null)
            {
                return 0;
            }

            return ((4 * buffer.Length / 3) + 3) & ~3;
        }

        public static int GetDecodedLength(string base64)
        {
            if (string.IsNullOrEmpty(base64)) 
            { 
                return 0; 
            }

            int characterCount = base64.Length;

            int result = Convert.ToInt32(3 * ((double)characterCount/4));
		
            int index = characterCount - 1;

            int loopCount = 1;

            while(base64[index] == '=' && loopCount <= 2)
            {
                result--;
                index--;
                loopCount++;
            }

            return  result;
        }
    }
}