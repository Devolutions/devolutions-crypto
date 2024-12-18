using System;
using System.IO;

namespace Devolutions.Cryptography
{
    public class EncryptionStream
        : Stream, IDisposable
    {
        private UIntPtr native_ptr = UIntPtr.Zero;
        private readonly int _chunkLength;
        private readonly int _tagLength;
        private bool _finalBlockTransformed = false;
        private bool _leaveOpen;

        public int ChunkLength { get { return _chunkLength; } }

        public int TagLength { get { return _tagLength; } }

        public bool HasFlushedFinalBlock
        {
            get { return _finalBlockTransformed; }
        }

        private readonly byte[] inputBuffer;

        private int inputBufferOffset = 0;
        private bool disposed = false;

        private readonly Stream outputStream;

        public EncryptionStream(byte[] key, byte[] aad, int chunkLength, bool asymmetric, int version, Stream outputStream)
            : this(key, aad, chunkLength, asymmetric, version, outputStream, false) { }

        public EncryptionStream(byte[] key, byte[] aad, int chunkLength, bool asymmetric, int version, Stream outputStream, bool leaveOpen) {
            _chunkLength = chunkLength;
            this.outputStream = outputStream;
            this._leaveOpen = leaveOpen;

            long result = Native.NewOnlineEncryptor(key, (UIntPtr)key.Length, aad, (UIntPtr)aad.Length, (uint)chunkLength, asymmetric, (ushort)version, out native_ptr);

            if (result < 0)
            {
                Utils.HandleError(result);
            }

            long tagSize = Native.OnlineEncryptorGetTagSize(native_ptr);

            if (tagSize < 0)
            {
                Utils.HandleError(tagSize);
            }

            _tagLength = (int) tagSize;

            inputBuffer = new byte[chunkLength];
        }

        public byte[] GetHeader()
        {
            long headerSize = Native.OnlineEncryptorGetHeaderSize(native_ptr);

            if (headerSize < 0)
            {
                Utils.HandleError(headerSize);
            }

            byte[] header = new byte[headerSize];

            long result = Native.OnlineEncryptorGetHeader(native_ptr, header, (UIntPtr)headerSize);

            if (result < 0)
            {
                Utils.HandleError(result);
            }

            return header;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public void FlushFinalBlock()
        {
            if(HasFlushedFinalBlock)
            {
                throw new NotSupportedException();
            }

            if (inputBufferOffset > 0)
            {
                byte[] outputBuffer = EncryptLastChunk();

                outputStream.Write(outputBuffer, 0, outputBuffer.Length);
            }

            _finalBlockTransformed = true;
        }

        public override void Flush()
        {
            return;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if(HasFlushedFinalBlock)
            {
                // Cannot write as stream is already closed
                return;
            };

            while (count > ChunkLength - inputBufferOffset)
            {
                // Here we write every finished blocks
                int countToAdd = ChunkLength - inputBufferOffset;
                Buffer.BlockCopy(buffer, offset, inputBuffer, inputBufferOffset, countToAdd);

                // Encrypt the buffer
                byte[] outputBuffer = EncryptChunk();

                // Write the output to the stream
                outputStream.Write(outputBuffer, 0, outputBuffer.Length);

                count -= countToAdd;
                offset += countToAdd;
                inputBufferOffset = 0;
            }

            if (count > 0) {
                Buffer.BlockCopy(buffer, offset, inputBuffer, inputBufferOffset, count);

                inputBufferOffset += count;
            }
        }

        private byte[] EncryptChunk()
        {
            byte[] aad = new byte[0];
            byte[] outputBuffer = new byte[ChunkLength + TagLength];

            long result = Native.OnlineEncryptorNextChunk(native_ptr, inputBuffer, (UIntPtr) ChunkLength, aad, UIntPtr.Zero, outputBuffer, (UIntPtr) outputBuffer.Length);

            if (result < 0) {
                Utils.HandleError(result);
            }

            return outputBuffer;
        }

        private byte[] EncryptLastChunk()
        {
            byte[] aad = new byte[0];
            byte[] outputBuffer = new byte[inputBufferOffset + TagLength];

            long result = Native.OnlineEncryptorLastChunk(native_ptr, inputBuffer, (UIntPtr) inputBufferOffset, aad, UIntPtr.Zero, outputBuffer, (UIntPtr)outputBuffer.Length);

            if (result < 0)
            {
                Utils.HandleError(result);
            }

            // Here, the pointer is freed, so let's set it to 0
            native_ptr = UIntPtr.Zero;

            return outputBuffer;
        }

        public new void Dispose()
        {
            base.Dispose();

            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    if(!HasFlushedFinalBlock)
                    {
                        FlushFinalBlock();
                    };

                    if(!_leaveOpen)
                    {
                        outputStream.Close();
                    }
                }
                base.Dispose(disposing: disposing);

                // If the ptr has not been freed yet, do it now
                if (native_ptr != UIntPtr.Zero)
                {
                    Native.FreeOnlineEncryptor(native_ptr);
                    native_ptr = UIntPtr.Zero;
                }

                disposed = true;
            }
        }
    }
}