namespace Devolutions.Cryptography.Argon2
{
    using System;
    using System.IO;

    public class Argon2Parameters
    {
        public Argon2Parameters()
        {
            this.InitializeParameters();
        }

        internal Argon2Parameters(bool defaultParameters = true)
        {
            if (defaultParameters)
            {
                this.InitializeParameters();
            }
        }

        public static long NativeSize
        {
            get
            {
                return Native.GetDefaultArgon2ParametersSizeNative();
            }
        }

        public uint Iterations { get; set; }

        public uint Lanes { get; set; }

        public uint Length { get; set; }

        public uint Memory { get; set; }

        internal byte[] AssociatedData { get; set; }

        internal uint DevolutionsCryptoVersion { get; set; }

        internal byte[] Salt { get; set; }

        internal Variant Variant { get; set; }

        internal Version Version { get; set; }

        /// <summary>
        /// Deserialize the Argon2Parameters class from a little endian byte array.
        /// </summary>
        /// <param name="data">The data to deserialize.</param>
        /// <returns>Returns the deserialized parameters</returns>
        public static Argon2Parameters FromByteArray(byte[] data)
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
        /// <param name="argon2Parameters">The argon2Paramerters to serialize.</param>
        /// <returns>Returns Argon2Parameters class to a little endian byte array</returns>
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
                    this.AssociatedData = new byte[0];
                }

                byte[] associatedDataLength = BitConverter.GetBytes(this.AssociatedData.Length);

                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(associatedDataLength);
                }

                // === Salt Length ===
                if (this.Salt == null)
                {
                    this.Salt = new byte[0];
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