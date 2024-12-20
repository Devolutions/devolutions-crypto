using System;
using System.IO;

namespace Devolutions.Cryptography
{
    public class DecryptionStream
        : Stream, IDisposable
    {
        private UIntPtr _native_ptr = UIntPtr.Zero;
        private readonly int _chunkLength;
        private readonly int _tagLength;
        private bool _finalBlockTransformed = false;
        private readonly bool _leaveOpen;

        public int ChunkLength { get { return _chunkLength; } }

        public int TagLength { get { return _tagLength; } }

        public bool HasFlushedFinalBlock
        {
            get { return _finalBlockTransformed; }
        }

        private readonly byte[] _inputBuffer;

        private int _inputBufferOffset = 0;
        private bool _disposed = false;

        private readonly Stream _outputStream;

        public DecryptionStream(byte[] key, byte[] aad, byte[] header, bool asymmetric, Stream outputStream)
            : this(key, aad, header, asymmetric, outputStream, false) { }

        public DecryptionStream(byte[] key, byte[] aad, byte[] header, bool asymmetric, Stream outputStream, bool leaveOpen) {
            _outputStream = outputStream;
            _leaveOpen = leaveOpen;

            long result = Native.NewOnlineDecryptor(key, (UIntPtr)key.Length, aad, (UIntPtr)aad.Length, header, (UIntPtr)header.Length, asymmetric, ref _native_ptr);

            if (result < 0)
            {
                Utils.HandleError(result);
            }

            long tagSize = Native.OnlineDecryptorGetTagSize(_native_ptr);

            if (tagSize < 0)
            {
                Utils.HandleError(tagSize);
            }

            long chunkLength = Native.OnlineDecryptorGetChunkSize(_native_ptr);

            if (tagSize < 0)
            {
                Utils.HandleError(chunkLength);
            }

            _tagLength = (int) tagSize;
            _chunkLength = (int)chunkLength + _tagLength;

            _inputBuffer = new byte[_chunkLength];
        }

        public byte[] GetHeader()
        {
            long headerSize = Native.OnlineDecryptorGetHeaderSize(_native_ptr);

            if (headerSize < 0)
            {
                Utils.HandleError(headerSize);
            }

            byte[] header = new byte[headerSize];

            long result = Native.OnlineDecryptorGetHeader(_native_ptr, header, (UIntPtr)headerSize);

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

            if (_inputBufferOffset > 0)
            {
                byte[] outputBuffer = DecryptLastChunk();

                _outputStream.Write(outputBuffer, 0, outputBuffer.Length);
            }

            Array.Clear(_inputBuffer, 0, _inputBuffer.Length);

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

            while (count > ChunkLength - _inputBufferOffset)
            {
                // Here we write every finished blocks
                int countToAdd = ChunkLength - _inputBufferOffset;
                Buffer.BlockCopy(buffer, offset, _inputBuffer, _inputBufferOffset, countToAdd);

                // Encrypt the buffer
                byte[] outputBuffer = DecryptChunk();

                // Write the output to the stream
                _outputStream.Write(outputBuffer, 0, outputBuffer.Length);

                count -= countToAdd;
                offset += countToAdd;
                _inputBufferOffset = 0;
            }

            if (count > 0) {
                Buffer.BlockCopy(buffer, offset, _inputBuffer, _inputBufferOffset, count);

                _inputBufferOffset += count;
            }
        }

        private byte[] DecryptChunk()
        {
            byte[] aad = new byte[0];
            byte[] outputBuffer = new byte[ChunkLength - TagLength];

            long result = Native.OnlineDecryptorNextChunk(_native_ptr, _inputBuffer, (UIntPtr) ChunkLength, aad, UIntPtr.Zero, outputBuffer, (UIntPtr) outputBuffer.Length);

            if (result < 0) {
                Utils.HandleError(result);
            }

            return outputBuffer;
        }

        private byte[] DecryptLastChunk()
        {
            byte[] aad = new byte[0];
            byte[] outputBuffer = new byte[_inputBufferOffset - TagLength];

            long result = Native.OnlineDecryptorLastChunk(_native_ptr, _inputBuffer, (UIntPtr) _inputBufferOffset, aad, UIntPtr.Zero, outputBuffer, (UIntPtr)outputBuffer.Length);

            if (result < 0)
            {
                Utils.HandleError(result);
            }

            // Here, the pointer is freed, so let's set it to 0
            _native_ptr = UIntPtr.Zero;

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
            if (!_disposed)
            {
                if (disposing)
                {
                    if(!HasFlushedFinalBlock)
                    {
                        FlushFinalBlock();
                    };

                    if(!_leaveOpen)
                    {
                        _outputStream.Close();
                    }
                }
                base.Dispose(disposing: disposing);

                // If the ptr has not been freed yet, do it now
                FreeNativeObject();

                _disposed = true;
            }
        }

        private void FreeNativeObject()
        {
            if (_native_ptr != UIntPtr.Zero)
            {
                Native.FreeOnlineDecryptor(_native_ptr);
                _native_ptr = UIntPtr.Zero;
            }
        }
    }
}