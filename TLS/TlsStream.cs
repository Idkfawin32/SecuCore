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

using SecuCore.Shared;
using SecuCore.TLS;
using SecuCore.TLS.Exceptions;
using System.Threading;
using System.Threading.Tasks;
using System;

namespace SecuCore.Sockets
{
    public class TlsStream
    {
        ApplicationDataController applicationDataController;
        TLSNetworkController networkController;
        TLSRecordLayer recordLayer;

        private int availablebytes = 0;
        private byte[] availabledat = null;

        public TlsStream(TCPSocket tcps) 
        {
            networkController = new TLSNetworkController(tcps);
            recordLayer = new TLSRecordLayer(networkController);
            applicationDataController = new ApplicationDataController(recordLayer, 8192);
        }

        public TlsStream(TCPSocket tcps, TLSVersion version, int applicationReadBufferSize = 8192)
        {
            networkController = new TLSNetworkController(tcps);
            recordLayer = new TLSRecordLayer(networkController, version);
            applicationDataController = new ApplicationDataController(recordLayer, applicationReadBufferSize);
        }

        public Task<bool> AuthenticateAsClientAsync(string target, TLSRecordLayer.ValidateServerCertificate validateServerCertificateCallback, TLSRecordLayer.ClientCertificateRequest clientCertificateRequestCallback)
        {
            return recordLayer.EstablishTLSConnection(target, validateServerCertificateCallback, clientCertificateRequestCallback).AsTask();
        }

        private Task<byte[]> AskForDataAsync(int len)
        {
            TaskCompletionSource<byte[]> dtcs = new TaskCompletionSource<byte[]>();
            DataRequest dr = new DataRequest()
            {
                length = len,
                tcs = dtcs
            };
            applicationDataController.RequestData(dr);
            return dtcs.Task;
        }
        public static async Task<T> TimeoutAfter<T>(Task<T> task, int millisecondsTimeout)
        {
            using(CancellationTokenSource cts = new CancellationTokenSource())
            {
                if (task == await Task.WhenAny(task, Task.Delay(millisecondsTimeout, cts.Token)).ConfigureAwait(false))
                {
                    cts.Cancel();
                    return await task;
                }
                else
                {
                    cts.Cancel();
                    throw new TLSNetworkException("operation timed out");
                }
            }
        }

        private async ValueTask WriteInternalAsync(byte[] buffer)
        {
            TaskCompletionSource dtcs = null;
            dtcs = new TaskCompletionSource();

            DataDispatch datd = new DataDispatch()
            {
                data = buffer,
                tcs = dtcs
            };
            applicationDataController.QueueData(datd);
            applicationDataController.FlushData();
            await dtcs.Task.ConfigureAwait(false);
        }

        private async ValueTask<int> ReadInternal(byte[] buffer, int offset, int len)
        {
            try
            {
                int read = 0;
                if (availablebytes == 0)
                {
                    byte[] recieve = null;
                    try
                    {
                       recieve = await AskForDataAsync(-1).ConfigureAwait(false);
                    }
                    catch (Exception ex) { }
                    if (recieve != null)
                    {
                        if (recieve.Length > 0)
                        {
                            availabledat = recieve;
                            availablebytes = recieve.Length;
                        }
                        else
                        {
                            return -1;
                        }
                    }
                    else
                    {
                        return -1;
                    }
                }
                if (availablebytes > len)
                {
                    //we have more than needed
                    Buffer.BlockCopy(availabledat, 0, buffer, offset, len);
                    read += len;
                    byte[] remain = new byte[availablebytes - len];
                    Buffer.BlockCopy(availabledat, len, remain, 0, remain.Length);
                    availabledat = remain;
                    availablebytes -= len;
                    return read;
                }
                else
                {
                    //we can exhaust our buffer
                    int copylen = availablebytes;
                    Buffer.BlockCopy(availabledat, 0, buffer, offset, copylen);
                    read += copylen;
                    availabledat = null;
                    availablebytes = 0;
                    offset += copylen;
                    len -= copylen;
                }
                return read;
            }
            catch(Exception ex)
            {
                return -1;
            }            
        }

        public ValueTask<int> ReadAsync(byte[] buffer, int offset, int count)
        {
            return ReadInternal(buffer, offset, count);
        }

        public Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (offset == 0 && count == buffer.Length)
            {
                return WriteInternalAsync(buffer).AsTask();
            }
            byte[] localBuffer = new byte[count];
            Buffer.BlockCopy(buffer, offset, localBuffer, 0, count);
            return WriteInternalAsync(localBuffer).AsTask();
        }

        public Task WriteAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            return WriteInternalAsync(buffer).AsTask();
        }
        public Task WriteAsync(byte[] buffer)
        {
            return WriteInternalAsync(buffer).AsTask();
        }

        public async ValueTask DisposeAsync()
        {
            recordLayer.Dispose();
            networkController.Dispose();
            applicationDataController.Shutdown(false);
            recordLayer = null;
            networkController = null;
            applicationDataController = null;
        }
    }
}
