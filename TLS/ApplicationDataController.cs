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
using Microsoft.VisualStudio.Threading;
using SecuCore.Shared;
using SecuCore.TLS.Exceptions;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SecuCore.TLS
{
    class ApplicationDataController : IDataController
    {
        TLSRecordLayer _recordLayer;
        public bool isFaulted = false;
        public string lastError = "";

        public Queue<DataDispatch> outgoing = new Queue<DataDispatch>();
        public Queue<DataRequest> requests = new Queue<DataRequest>();
        byte[] localBuffer;

        public ApplicationDataController(TLSRecordLayer recordLayer, int recieveBufferSize)
        {
            localBuffer = new byte[recieveBufferSize];
            _recordLayer = recordLayer;
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
                while (GetNextDataRequest(out DataRequest next))
                {
                    if (!await HandleRequestAsync(next).ConfigureAwait(false))
                    {
                        if (next.tcs != null)
                            next.tcs.TrySetException(new Exception("Network failure"));
                        Shutdown(true);
                        return;
                    }
                }
            }
        }

        bool shutdownCalled = false;
        public void Shutdown(bool faulted)
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
                        next.tcs.TrySetException(new Exception("Application Layer failure: " + this.lastError));
                }
                while (requests.TryDequeue(out DataRequest next))
                {
                    if (next.tcs != null)
                        next.tcs.TrySetException(new Exception("Application Layer failure: " + this.lastError));
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
            _recordLayer = null;
            outgoing = null;
            requests = null;
            localBuffer = null;
        }

        private async ValueTask<bool> DispatchAsync(DataDispatch data)
        {
            if (shutdownRequested)
                return false;

            try
            {
                await _recordLayer.SendApplicationDataAsync(data.data).ConfigureAwait(false);
                if (data.tcs != null)
                    data.tcs.TrySetResult();
                return true;
            }
            catch (Exception e)
            {
                lastError = e.Message;
            }
            return false;
        }

        private async ValueTask<bool> HandleRequestAsync(DataRequest request)
        {
            if (shutdownRequested)
                return false;

            if (request.length == -1)
            {
                // any amount of data
                try
                {

                    int len = await _recordLayer.ReadApplicationDataAsync(localBuffer, 0, localBuffer.Length).ConfigureAwait(false);
                    if (len > 0)
                    {
                        byte[] recieved = new byte[len];
                        Buffer.BlockCopy(localBuffer, 0, recieved, 0, len);
                        if (!request.tcs.TrySetResult(recieved))
                        {
                            lastError = "failed to set result to datarequest";
                            return false;
                        }
                        return true;
                    }
                    else
                    {
                        lastError = "Failed to read application data";
                        if (!request.tcs.TrySetException(new Exception("no data")))
                        {
                        }
                        return false;
                    }
                }
                catch (Exception)
                {
                    if (!request.tcs.TrySetException(new Exception("no data")))
                    {
                    }
                    return false;
                }
            }
            else
            {
                byte[] buffer = new byte[request.length];

                int pos = 0;
                int remain = 0;
                while (remain > 0)
                {
                    int len = await _recordLayer.ReadApplicationDataAsync(buffer, pos, remain).ConfigureAwait(false);
                    if (len > 0)
                    {
                        pos += len;
                        remain -= len;
                    }
                    else
                    {
                        request.tcs.TrySetException(new Exception("no data"));
                        lastError = "Failed to read application data";
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
        }

        public void RequestData(DataRequest request)
        {
            if (shutdownRequested)
                throw new TLSDataException("Shutdown has been requested");

            requests.Enqueue(request);
            requestReset.Set();
        }

        public void QueueData(DataDispatch dispatch)
        {
            if (shutdownRequested)
                throw new TLSDataException("Shutdown has been requested");

            outgoing.Enqueue(dispatch);
        }
        public void FlushData()
        {
            if (shutdownRequested)
                throw new TLSDataException("Shutdown has been requested");

            flushReset.Set();
        }
    }
}
