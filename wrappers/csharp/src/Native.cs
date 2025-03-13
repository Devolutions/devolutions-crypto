#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Cryptography
{
    using System;

#if NETFRAMEWORK
    using System.IO;
    using System.Runtime.InteropServices;
#endif
    using System.Reflection;

    /// <summary>
    /// Contains the bindings to the native rust library.
    /// </summary>
    public static partial class Native
    {
#if NETFRAMEWORK
        [DllImport("Kernel32", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string path);
#endif

#if !DEBUG
        private const string NativeVersion = "||NATIVE_VERSION||";
        private const string ManagedVersion = "||MANAGED_VERSION||";
#endif

        static Native()
        {
#if NETFRAMEWORK
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DEVOLUTIONS_CRYPTO_SKIP_NATIVE_PRELOAD")))
            {
                string baseLocation = Assembly.GetEntryAssembly()?.Location ?? Assembly.GetExecutingAssembly().Location;
                string baseDir = Path.GetDirectoryName(baseLocation);
                string rid = "win-" + RuntimeInformation.ProcessArchitecture.ToString().ToLower();
                string path = Path.Combine(
                    baseDir,
                    "runtimes", 
                    rid, 
                    "native",
                    "DevolutionsCrypto.dll");

                if (LoadLibrary(path) == IntPtr.Zero)
                {
                    throw new DevolutionsCryptoException(ManagedError.NativeLibraryLoad, $"LoadLibrary failed for { path }");
                }
            }
#endif

#if !DEBUG
            Assembly assembly = Assembly.GetExecutingAssembly();

            Version assemblyVersion = assembly.GetName().Version;
            Version managedVersion = Version.Parse(ManagedVersion);
            
            if(managedVersion.Revision == -1)
            {
                managedVersion = Version.Parse(ManagedVersion + ".0");
            }

            string nativeVersion = Utils.Version();

            if (managedVersion != assemblyVersion || NativeVersion != nativeVersion)
            {
                throw new DevolutionsCryptoException(ManagedError.IncompatibleVersion, "Non-matching versions - Managed: " + assemblyVersion + " Native: " + nativeVersion + " Supported : managed(" + ManagedVersion + ") native (" + NativeVersion + ")");
            }
#endif
        }

        [Obsolete("This method has been deprecated. Use Managed.Decrypt instead.")]
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            return Managed.Decrypt(data, key);
        }

        [Obsolete("This method has been deprecated. Use Managed.DerivePassword instead.")]
        public static byte[] DerivePassword(string password, string salt, uint iterations = 10000)
        {
            return Managed.DerivePassword(password, salt, iterations);
        }

        [Obsolete("This method has been deprecated. Use Managed.DeriveKey instead.")]
        public static byte[] DeriveKey(byte[] key, byte[] salt, uint iterations = 10000, uint length = 32)
        {
            return Managed.DeriveKey(key, salt, iterations, length);
        }

        [Obsolete("This method has been deprecated. Use Managed.Encrypt instead.")]
        public static byte[] Encrypt(byte[] data, byte[] key, uint version = 0)
        {
            return Managed.Encrypt(data, key, null, (CipherTextVersion)version);
        }

        [Obsolete("This method has been deprecated. Use Managed.GenerateKey instead.")]
        public static byte[] GenerateKey(uint keySize)
        {
            return Managed.GenerateKey(keySize);
        }

        [Obsolete("This method has been deprecated. Use Managed.GenerateKeyPair instead.")]
        public static KeyPair GenerateKeyPair()
        {
            return Managed.GenerateKeyPair();
        }

        [Obsolete("This method has been deprecated. Use Managed.HashPassword instead.")]
        public static byte[] HashPassword(byte[] password, uint iterations = 10000)
        {
            return Managed.HashPassword(password, iterations);
        }

        [Obsolete("This method has been deprecated. Use Managed.HashPassword instead.")]
        public static bool VerifyPassword(byte[] password, byte[] hash)
        {
            return Managed.VerifyPassword(password, hash);
        }
    }
}
#pragma warning restore SA1600 // Elements should be documented