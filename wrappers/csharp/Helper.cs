using System;
using System.Runtime.InteropServices;
using Devolutions.Cryptography;

namespace DevolutionsCrypto
{
    public static class Helper
    {

        public static IntPtr[] GetArrayReferences(ref byte[][] shares, int nbShares, int secretLength)
        {
            var uSecretLength = (int)Native.GenerateSharedKeySizeNative((UIntPtr)secretLength);

            GCHandle[] handles = new GCHandle[(int)nbShares];
            for (int i = 0; i < shares.Length; i++)
            {
                handles[i] = GCHandle.Alloc(shares[i], GCHandleType.Pinned);
            }

            IntPtr[] pointers = new IntPtr[(int)nbShares];
            for (int i = 0; i < handles.Length; i++)
            {
                pointers[i] = handles[i].AddrOfPinnedObject();
            }

            return pointers;
        }

        public static IntPtr[] InitializeArray(ref byte[][] shares, int nbShares, int secretLength)
        {
            var uSecretLength = (int)Native.GenerateSharedKeySizeNative((UIntPtr)secretLength);

            for (int i = 0; i < nbShares; i++)
            {
                shares[i] = new byte[uSecretLength];
            }

            GCHandle[] handles = new GCHandle[(int)nbShares];
            for (int i = 0; i < shares.Length; i++)
            {
                handles[i] = GCHandle.Alloc(shares[i], GCHandleType.Pinned);
            }

            IntPtr[] pointers = new IntPtr[(int)nbShares];
            for (int i = 0; i < handles.Length; i++)
            {
                pointers[i] = handles[i].AddrOfPinnedObject();
            }

            return pointers;
        }
    }
}
