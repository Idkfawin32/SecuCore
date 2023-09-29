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

using Microsoft.VisualStudio.Threading;
using SecuCore.Shared;
using SecuCore.Sockets;
using SecuCore.TLS.Exceptions;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SecuCore.TLS
{
    class TLSNetworkController : IDataController
    {
        TCPSocket _socket;
        public bool isFaulted = false;
        public string lastError = "";

        public TLSNetworkController(TCPSocket tcps)
        {
            _socket = tcps;
            _ = Start();
        }

        private bool shutdownRequested = false;
        private AsyncAutoResetEvent requestReset = new AsyncAutoResetEvent();
        private AsyncAutoResetEvent flushReset = new AsyncAutoResetEvent();
        private AsyncAutoResetEvent nextEmpty = new AsyncAutoResetEvent();

        private async Task Start()
        {
            _ = WriteLoop();
            _ = ReadLoop();
        }

        private bool GetNextDataDispatch(out DataDispatch next)
        {
            if (outgoing == null || shutdownRequested)
            {
                next = null;
                return false;
            }
            return outgoing.TryDequeue(out next);
        }
        private bool GetNextDataRequest(out DataRequest next)
        {
            if (requests == null || shutdownRequested)
            {
                next = null;
                return false;
            }
            return requests.TryDequeue(out next);
        }

        private async Task WriteLoop()
        {
            while (!shutdownRequested)
            {
                await flushReset.WaitAsync().ConfigureAwait(false);
                while (GetNextDataDispatch(out DataDispatch next))
                {

                    if (!await DispatchAsync(next).ConfigureAwait(false))
                    {
                        Shutdown(true);
                        return;
                    }
                }
            }
        }

        private async Task ReadLoop()
        {
            while (!shutdownRequested)
            {
                await requestReset.WaitAsync().ConfigureAwait(false);
                try
                {
                    while (GetNextDataRequest(out DataRequest next))
                    {
                        if (!await HandleRequestAsync(next).ConfigureAwait(false))
                        {
                            Shutdown(true);
                            return;
                        }
                    }
                }catch (Exception) {}
            }
        }

        bool shutdownCalled = false;
        private void Shutdown(bool faulted)
        {
            if (shutdownCalled)
                return;
            shutdownCalled = true;

            shutdownRequested = true;
            if (faulted)
            {
                this.isFaulted = true;
                // clear buffers and inform failure
                while (outgoing.TryDequeue(out DataDispatch next))
                {
                    if (next.tcs != null)
                        next.tcs.TrySetException(new Exception("Network controller failure: " + this.lastError));
                }
                while (requests.TryDequeue(out DataRequest next))
                {
                    if (next.tcs != null)
                        next.tcs.TrySetException(new Exception("Network controller failure: " + this.lastError));
                }
            }
            else
            {
                while (outgoing.TryDequeue(out DataDispatch next))
                {
                    if (next.tcs != null)
                        next.tcs.TrySetCanceled();
                }
                while (requests.TryDequeue(out DataRequest next))
                {
                    if (next.tcs != null)
                        next.tcs.TrySetCanceled();
                }
            }
            flushReset.Set();
            nextEmpty.Set();
            requestReset.Set();
            _socket = null;
            outgoing = null;
            requests = null;
        }

        private async ValueTask<bool> DispatchAsync(DataDispatch data)
        {
            if (data == null)
                return false;
            bool sent = await WriteNSAsync(data.data).ConfigureAwait(false);
            if (data.tcs != null)
                data.tcs.TrySetResult();
            return sent;
        }

        private async ValueTask<bool> HandleRequestAsync(DataRequest request)
        {
            byte[] buffer = new byte[request.length];

            int pos = 0;
            int remain = request.length;
            while (remain > 0)
            {
                int len = await ReadNSAsync(buffer, pos, remain).ConfigureAwait(false);
                if (len > 0)
                {
                    pos += len;
                    remain -= len;
                }
                else
                {
                    request.tcs.TrySetException(new Exception("Network failure or timeout"));
                    return false;
                }
            }

            // success
            if (!request.tcs.TrySetResult(buffer))
            {
                lastError = "failed to set result to datarequest";
                return false;
            }

            return true;
        }

        private async ValueTask<int> ReadNSAsync(byte[] buf, int offset, int length)
        {
            try
            {
                int rlen = await _socket.RecieveAsync(buf, offset, length).ConfigureAwait(false);
                if (rlen > 0)
                {
                    return rlen;
                }
            }
            catch (Exception ex)
            {
                this.lastError = ex.Message;
            }
            return -1;
        }

        private async ValueTask<bool> WriteNSAsync(byte[] dat)
        {
            try
            {
                await _socket.SendAsync(dat).ConfigureAwait(false);
                return true;
            }
            catch (Exception ex)
            {
                this.lastError = ex.Message;
            }
            return false;
        }

        public Queue<DataDispatch> outgoing = new Queue<DataDispatch>();
        public Queue<DataRequest> requests = new Queue<DataRequest>();

        public void RequestData(DataRequest request)
        {
            if (shutdownRequested)
                throw new TLSNetworkException("Shutdown has been requested");
            requests.Enqueue(request);
            requestReset.Set();
        }

        public void QueueData(DataDispatch dispatch)
        {
            if (shutdownRequested)
                throw new TLSNetworkException("Shutdown has been requested");
            outgoing.Enqueue(dispatch);
        }
        public void FlushData()
        {
            if (shutdownRequested)
                throw new TLSNetworkException("Shutdown has been requested");

            flushReset.Set();
        }
        public async Task FlushDataFully()
        {
            if (shutdownRequested)
                throw new TLSNetworkException("Shutdown has been requested");
            flushReset.Set();
            await nextEmpty.WaitAsync().ConfigureAwait(false);
        }

        public void Dispose() { Shutdown(false); }
    }
}
