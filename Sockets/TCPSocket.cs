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
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SecuCore.Proxies;
namespace SecuCore.Sockets
{
    public class TCPSocket
    {
        private Socket _socket;
        private Proxy _proxy;
        private TCPNetworkStream _tcpns;
        private string _remoteHost;
        private int _remotePort;
        public int connectionLevelReached = 0;
        public int ConnectTimeout { get; set; } = 10000;
        public int WriteTimeout { get; set; } = 10000;
        public int ReadTimeout { get; set; } = 10000;
        public bool NoDelay { get; set; } = false;
        private int _socketRBS = 0;
        private int _socketSBS = 0;
        private int _recvBufSz = 0;
        private int _sendBufSz = 0;
        public int SendBufferSize
        {
            get
            {
                return _sendBufSz;
            }
            set
            {
                if (value != _sendBufSz)
                {
                    _sendBufSz = value;
                }
            }
        }
        public int RecvBufferSize
        {
            get
            {
                return _recvBufSz;
            }
            set
            {
                if (value != _recvBufSz)
                {
                    _recvBufSz = value;
                    if (_tcpns != null)
                    {
                        _tcpns.SetRecvBufferSize(_recvBufSz);
                    }
                }
            }
        }
        public bool ResetOnClose { get; set; } = false;
        public TCPSocket(string remoteHost, int remotePort, Proxy proxy = null, int wsaSockRecieveBufferSize = 8192, int wsaSockSendBufferSize = 8192)
        {
            _remoteHost = remoteHost;
            _remotePort = remotePort;
            _proxy = proxy;
            _socketRBS = wsaSockRecieveBufferSize;
            _socketSBS = wsaSockSendBufferSize;
            _recvBufSz = wsaSockRecieveBufferSize;
            _sendBufSz = wsaSockSendBufferSize;
        }
        public void SetWSASockBufferSizes(int recieve, int send)
        {
            if (_socket != null)
            {
                _socket.ReceiveBufferSize = recieve;
                _socket.SendBufferSize = send;
            }
        }
        public void SetProxy(string proxyStr, ProxyProtocol protocol)
        {
            try
            {
                this._proxy = new Proxy(proxyStr, protocol);
            }
            catch (Exception e)
            {
                throw new ArgumentException(e.Message);
            }
        }
        public void SetTimeout(int milliseconds)
        {
            ConnectTimeout = milliseconds;
            WriteTimeout = milliseconds;
            ReadTimeout = milliseconds;
        }
        public TCPNetworkStream GetStream()
        {
            if (_tcpns == null) _tcpns = new TCPNetworkStream(this);
            return _tcpns;
        }
        public bool Connected() => _socket.Connected;
        public async Task<bool> ConnectAsync()
        {
            using (CancellationTokenSource cts = new CancellationTokenSource())
            {
                try
                {
                    bool usingProxy = (_proxy != null);
                    if (!IPAddress.TryParse(_remoteHost, out IPAddress rhip))
                    {
                        string remoteip = await DNS.AsyncDNSResolver.GetFirstArecord(_remoteHost);
                        if (!IPAddress.TryParse(remoteip, out rhip))
                        {
                            return false;
                        }
                        _remoteHost = rhip.ToString();
                    }
                    IPEndPoint ipep = (usingProxy ? _proxy.GetRemoteEndpoint() : new IPEndPoint(rhip, _remotePort));
                    _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    _socket.ReceiveTimeout = this.ReadTimeout;
                    _socket.SendTimeout = this.WriteTimeout;
                    _socket.NoDelay = this.NoDelay;
                    _socket.ReceiveBufferSize = _socketRBS;
                    _socket.SendBufferSize = _socketSBS;
                    if (ResetOnClose) _socket.LingerState = new LingerOption(true, 0);
                    Task delayTask = Task.Delay(ConnectTimeout, cts.Token);
                    Task conTask = _socket.ConnectAsync(ipep, cts.Token).AsTask();
                    Task ret = await Task.WhenAny(conTask, delayTask).ConfigureAwait(false);
                    cts.Cancel();
                    if (ret == delayTask) return false;
                    if (_socket.Connected)
                    {
                        _socket.NoDelay = this.NoDelay;
                        connectionLevelReached = 1;
                        if (usingProxy)
                        {
                            bool proxyconres = await _proxy.ConnectAsync(GetStream(), _remoteHost, _remotePort).ConfigureAwait(false);
                            if (proxyconres) connectionLevelReached = 2;
                            return proxyconres;
                        }
                        else
                        {
                            connectionLevelReached = 2;
                            return true;
                        }
                    }
                }
                catch (Exception)
                { }
            }
            return false;
        }
        public virtual async Task<bool> SendAsync(byte[] data)
        {
            using (CancellationTokenSource cts = new CancellationTokenSource(WriteTimeout))
            {
                ReadOnlyMemory<byte> rom = new ReadOnlyMemory<byte>(data, 0, data.Length);
                try
                {
                    int remain = data.Length;
                    while (remain > 0)
                    {
                        int sentdata = await _socket.SendAsync(rom, SocketFlags.None, cts.Token).ConfigureAwait(false);
                        if (sentdata <= 0) return false;
                        remain -= sentdata;
                        if (remain <= 0) return true;
                    }
                }
                catch (Exception)
                { }
            }
            return false;
        }
        public virtual async Task<int> RecieveAsync(byte[] dest, int offset, int count)
        {
            Memory<byte> mem = new Memory<byte>(dest, offset, count);
            try
            {
                using (CancellationTokenSource cts = new CancellationTokenSource(ReadTimeout))
                {
                    return await _socket.ReceiveAsync(mem, SocketFlags.None, cts.Token).ConfigureAwait(false);
                }
            }
            catch (Exception e)
            { }
            return 0;
        }
        public void Dispose()
        {
            if (ResetOnClose)
            {
                if (_socket != null) _socket.Close(0);
            }
            else
            {
                _socket.Close();
            }
        }
    }
}