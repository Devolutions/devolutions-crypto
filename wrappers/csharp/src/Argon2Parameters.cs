namespace Devolutions.Cryptography.Argon2
{
    using System;
    using System.IO;

    /// <summary>
    /// Used to define the Argon2 parameters when deriving data.
    /// </summary>
    public class Argon2Parameters
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Argon2Parameters"/> class.
        /// </summary>
        public Argon2Parameters()
        {
            this.InitializeParameters();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Argon2Parameters"/> class.
        /// </summary>
        /// <param name="defaultParameters">Use the standard Argon2 parameters.</param>
        internal Argon2Parameters(bool defaultParameters = true)
        {
            if (defaultParameters)
            {
                this.InitializeParameters();
            }
        }

        /// <summary>
        /// Gets the size of the raw Argon2 data.
        /// </summary>
        public static long NativeSize => Native.GetDefaultArgon2ParametersSizeNative();

        /// <summary>
        /// Gets or sets the number of iterations over the memory.
        /// </summary>
        public uint Iterations { get; set; }

        /// <summary>
        /// Gets or sets the number of threads to use.
        /// </summary>
        public uint Lanes { get; set; }

        /// <summary>
        /// Gets or sets the hash length.
        /// </summary>
        public uint Length { get; set; }

        /// <summary>
        /// Gets or sets the memory used by the algorithm.
        /// </summary>
        public uint Memory { get; set; }

        /// <summary>
        /// Gets or sets the associated data.
        /// </summary>
        internal byte[]? AssociatedData { get; set; }

        /// <summary>
        /// Gets or sets the devolutions crypto version.
        /// </summary>
        internal uint DevolutionsCryptoVersion { get; set; }

        /// <summary>
        /// Gets or sets the salt used by the algorithm.
        /// </summary>
        internal byte[]? Salt { get; set; }

        /// <summary>
        /// Gets or sets the Argon2 variant used by the algorithm.
        /// </summary>
        internal Variant Variant { get; set; }

        /// <summary>
        /// Gets or sets the Argon2 version.
        /// </summary>
        internal Version Version { get; set; }

        /// <summary>
        /// Deserialize the Argon2Parameters class from a little endian byte array.
        /// </summary>
        /// <param name="data">The data to deserialize.</param>
        /// <returns>Returns the deserialized parameters.</returns>
        public static Argon2Parameters? FromByteArray(byte[]? data)
        {
            if (data == null)
            {
                return null;
            }

            try
            {
                MemoryStream stream = new MemoryStream(data);

                Argon2Parameters parameters = new Argon2Parameters(false);

                // ==== Devolutions Crypto Version ====
                byte[] buffer = new byte[4];

                stream.Read(buffer, 0, 4);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(buffer);
                }

                parameters.DevolutionsCryptoVersion = BitConverter.ToUInt32(buffer, 0);

                // ==== Length ====
                stream.Read(buffer, 0, 4);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(buffer);
                }

                parameters.Length = BitConverter.ToUInt32(buffer, 0);

                // ==== Lanes ====
                stream.Read(buffer, 0, 4);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(buffer);
                }

                parameters.Lanes = BitConverter.ToUInt32(buffer, 0);

                // ==== Memory ====
                stream.Read(buffer, 0, 4);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(buffer);
                }

                parameters.Memory = BitConverter.ToUInt32(buffer, 0);

                // ==== Iterations ====
                stream.Read(buffer, 0, 4);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(buffer);
                }

                parameters.Iterations = BitConverter.ToUInt32(buffer, 0);

                // ==== Variant ====
                stream.Read(buffer, 0, 1);

                parameters.Variant = (Variant)buffer[0];

                // ==== Version ====
                stream.Read(buffer, 0, 1);

                parameters.Version = (Version)buffer[0];

                // ==== Associated Data ====
                stream.Read(buffer, 0, 4);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(buffer);
                }

                uint associatedDataLength = BitConverter.ToUInt32(buffer, 0);

                byte[] associatedData = new byte[associatedDataLength];

                stream.Read(associatedData, 0, (int)associatedDataLength);

                parameters.AssociatedData = associatedData;

                // ==== Salt ====
                stream.Read(buffer, 0, 4);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(buffer);
                }

                uint saltLength = BitConverter.ToUInt32(buffer, 0);

                byte[] salt = new byte[saltLength];

                stream.Read(salt, 0, (int)saltLength);

                parameters.Salt = salt;

                stream.Close();

                return parameters;
            }
            catch (Exception ex)
            {
                DevolutionsCryptoException exception = new DevolutionsCryptoException(ManagedError.Error, exception: ex);
                throw exception;
            }
        }

        /// <summary>
        /// Serialize the Argon2Parameters class to a little endian byte array.
        /// </summary>
        /// <returns>Returns Argon2Parameters class to a little endian byte array.</returns>
        public byte[] ToByteArray()
        {
            try
            {
                // === Devolutions Crypto Version ===
                byte[] devolutionsCryptoVersion = BitConverter.GetBytes(this.DevolutionsCryptoVersion);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(devolutionsCryptoVersion);
                }

                // === Length ===
                byte[] length = BitConverter.GetBytes(this.Length);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(length);
                }

                // === Lanes ===
                byte[] lanes = BitConverter.GetBytes(this.Lanes);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(lanes);
                }

                // === Memory ===
                byte[] memory = BitConverter.GetBytes(this.Memory);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(memory);
                }

                // === Iterations ===
                byte[] iterations = BitConverter.GetBytes(this.Iterations);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(iterations);
                }

                // === Variant ===
                byte[] variant = new byte[1];

                variant[0] = (byte)this.Variant;

                // === Version ===
                byte[] version = new byte[1];

                version[0] = (byte)this.Version;

                // === Associated Data Length ===
                if (this.AssociatedData == null)
                {
                    this.AssociatedData = Array.Empty<byte>();
                }

                byte[] associatedDataLength = BitConverter.GetBytes(this.AssociatedData.Length);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(associatedDataLength);
                }

                // === Salt Length ===
                if (this.Salt == null)
                {
                    this.Salt = [];
                }

                byte[] saltLength = BitConverter.GetBytes(this.Salt.Length);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(saltLength);
                }

                return Utils.ConcatArrays(
                    devolutionsCryptoVersion,
                    length,
                    lanes,
                    memory,
                    iterations,
                    variant,
                    version,
                    associatedDataLength,
                    this.AssociatedData,
                    saltLength,
                    this.Salt);
            }
            catch (Exception ex)
            {
                DevolutionsCryptoException exception = new DevolutionsCryptoException(ManagedError.Error, exception: ex);
                throw exception;
            }
        }

        /// <summary>
        /// Initialise the default recommended parameters.
        /// </summary>
        private void InitializeParameters()
        {
            Argon2Parameters parameters = Managed.GetDefaultArgon2Parameters();

            this.Iterations = parameters.Iterations;
            this.Lanes = parameters.Lanes;
            this.Length = parameters.Length;
            this.Memory = parameters.Memory;
            this.AssociatedData = parameters.AssociatedData;
            this.DevolutionsCryptoVersion = parameters.DevolutionsCryptoVersion;
            this.Salt = parameters.Salt;
            this.Variant = parameters.Variant;
            this.Version = parameters.Version;
        }
    }
}