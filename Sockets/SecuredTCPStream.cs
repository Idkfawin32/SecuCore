/*
 * Secucore
 * 
 * Copyright (C) 2023 Trevor Hall
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.
 * 
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecuCore.Sockets
{
    public class SecuredTCPStream : INetStream
    {
        private TlsStream _tls;

        public int recvBufferSize;
        private byte[] readBuffer;
        private int rbpos = 0;
        private int rbavail = 0;

        public SecuredTCPStream(TCPSocket _tcps)
        {
            _tls = new TlsStream(_tcps);
            readBuffer = new byte[_tcps.RecvBufferSize];
        }

        public void SetRecvBufferSize(int bufsz)
        {
            if (recvBufferSize != bufsz)
            {
                recvBufferSize = bufsz;
                byte[] recvbf = new byte[recvBufferSize];
                int copysz = readBuffer.Length;
                if (copysz > recvbf.Length) copysz = recvbf.Length;
                Buffer.BlockCopy(readBuffer, 0, recvbf, 0, copysz);
                readBuffer = recvbf;
            }
        }

        private int FindCRLF(byte[] inbuf, int offset, int count)
        {
            for (int i = offset; i < offset + count - 1; i++)
            {
                if (inbuf[i] == 0x0d)
                {
                    if (inbuf[i + 1] == 0x0a)
                    {
                        return i;
                    }
                }
            }
            return -1;
        }
        private int FindCRLFCRLF(byte[] inbuf, int offset, int count)
        {
            for (int i = offset; i < offset + count - 3; i++)
            {
                if (inbuf[i] == 0x0d)
                {
                    if (inbuf[i + 1] == 0x0a)
                    {
                        if (inbuf[i + 2] == 0x0d)
                        {
                            if (inbuf[i + 3] == 0x0a)
                            {
                                return i;
                            }
                        }
                    }
                }
            }
            return -1;
        }

        private async Task<bool> ReadAny()
        {
            rbavail = 0;
            rbpos = 0;
            int rlen = await _tls.ReadAsync(readBuffer, 0, readBuffer.Length).ConfigureAwait(false);
            if (rlen <= 0)
            {
                return false;
            }
            rbavail = rlen;
            return true;
        }
        private async Task<int> ReadAsyncInternal(byte[] dest, int offset, int count)
        {
            if (rbavail == 0)
            {
                if (!await ReadAny().ConfigureAwait(false))
                {
                    return 0;
                }
            }

            if (rbavail > 0)
            {
                if (rbavail > count)
                {
                    Buffer.BlockCopy(readBuffer, rbpos, dest, offset, count);
                    rbpos += count;
                    rbavail -= count;
                    if (rbavail == 0) rbpos = 0;
                    return count;
                }
                else
                {
                    Buffer.BlockCopy(readBuffer, rbpos, dest, offset, rbavail);
                    int read = rbavail;
                    rbpos = 0;
                    rbavail = 0;
                    return read;
                }
            }
            else
            {
                return 0;
            }
        }
        public async Task<bool> NegotiateTLSConnection(string targetDomain, TLS.TLSRecordLayer.ValidateServerCertificate validationCallback, TLS.TLSRecordLayer.ClientCertificateRequest clientRequestCallback)
        {
            return await _tls.AuthenticateAsClientAsync(targetDomain, validationCallback, clientRequestCallback).ConfigureAwait(false);
        }

        public Task<int> ReadAsync(byte[] dest)
        {
            return ReadAsyncInternal(dest, 0, dest.Length);
        }

        public Task<int> ReadAsync(byte[] dest, int offset, int length)
        {
            return ReadAsyncInternal(dest, offset, length);
        }

        public Task<int> ReadAsync(byte[] dest, CancellationToken token)
        {
            return ReadAsyncInternal(dest, 0, dest.Length);
        }
        public async Task<int> ReadAsync(Memory<byte> destmem, CancellationToken token)
        {
            byte[] localBuffer = new byte[destmem.Length];
            int len = await ReadAsyncInternal(localBuffer, 0, localBuffer.Length).ConfigureAwait(false);
            if (len > 0)
            {
                Memory<byte> lmem = new Memory<byte>(localBuffer, 0, len);
                lmem.CopyTo(destmem);
            }
            return len;
        }
        public async Task<byte[]> ReadUntilCRLF()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                int crlfi = -1;
                while (crlfi == -1)
                {
                    if (rbavail == 0)
                    {
                        if (!await ReadAny().ConfigureAwait(false)) break;
                    }
                    crlfi = FindCRLF(readBuffer, rbpos, rbavail);
                    //int resplen = ((crlfi + 2) - rbpos);

                    if (crlfi == -1)
                    {
                        await ms.WriteAsync(readBuffer, rbpos, rbavail).ConfigureAwait(false);
                        rbavail = 0;
                        rbpos = 0;
                    }
                    else
                    {
                        //we found crlf
                        int sublen = (crlfi + 2) - rbpos;
                        await ms.WriteAsync(readBuffer, rbpos, sublen).ConfigureAwait(false);
                        rbavail -= sublen;
                        rbpos += sublen;
                        if (rbavail <= 0)
                        {
                            rbpos = 0;
                            rbavail = 0;
                        }
                        return ms.ToArray();
                    }
                }

                if (ms.Position == 0) return null;

                return ms.ToArray();
            }
        }
        public async Task<byte[]> ReadUntilCRLFCRLF()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                int crlfi = -1;
                while (crlfi == -1)
                {
                    if (rbavail == 0)
                    {
                        if (!await ReadAny().ConfigureAwait(false)) break;
                    }
                    crlfi = FindCRLFCRLF(readBuffer, rbpos, rbavail);
                    int resplen = ((crlfi + 4) - rbpos);

                    if (crlfi == -1)
                    {
                        await ms.WriteAsync(readBuffer, rbpos, rbavail).ConfigureAwait(false);
                        rbavail = 0;
                        rbpos = 0;
                    }
                    else
                    {
                        //we found crlf
                        await ms.WriteAsync(readBuffer, rbpos, resplen).ConfigureAwait(false);
                        rbpos += resplen;
                        rbavail -= resplen;
                        if (rbavail <= 0)
                        {
                            rbpos = 0;
                            rbavail = 0;
                        }
                        return ms.ToArray();
                    }
                }

                if (ms.Position == 0) return null;

                return ms.ToArray();
            }
        }
        public async Task<bool> WriteAsync(byte[] dat)
        {
            await _tls.WriteAsync(dat).ConfigureAwait(false);
            return true;
        }

        public async Task<bool> WriteAsync(byte[] dat, int offset, int length)
        {
            await _tls.WriteAsync(dat, offset, length).ConfigureAwait(false);
            return true;
        }

        public async Task<bool> WriteAsync(ReadOnlyMemory<byte> datrom, CancellationToken token)
        {
            await _tls.WriteAsync(datrom.ToArray(), token).ConfigureAwait(false);
            return true;
        }

        public async Task DisposeAsync()
        {
            await _tls.DisposeAsync();
        }
    }
}
