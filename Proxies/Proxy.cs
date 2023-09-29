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
using System.Threading.Tasks;
using SecuCore.Sockets;

namespace SecuCore.Proxies
{
    public enum ProxyProtocol
    {
        HTTP,
        SOCKS4,
        SOCKS5
    }
    public class Proxy
    {
        private string proxyHost;
        private int proxyPort;
        private string proxyUsername;
        private string proxyPassword;
        public ProxyProtocol proxyProtocol;

        private IPAddress proxyAddress;

        public Proxy(string proxyString, ProxyProtocol protocol)
        {
            if (proxyString.Contains(':'))
            {
                string[] pspl = proxyString.Split(':');
                if (string.IsNullOrEmpty(pspl[0])) throw new Exception("Proxy host parse error");
                this.proxyHost = pspl[0];
                if(!int.TryParse(pspl[1], out this.proxyPort)) throw new Exception("Proxy port parse error");
                if (pspl.Length > 2) this.proxyUsername = pspl[2];
                if(pspl.Length > 3) this.proxyPassword = pspl[3];
                this.proxyProtocol = protocol;
            }
            else
            {
                throw new Exception("Proxy input parse error");
            }
        }

        public Task<bool> ConnectAsync(TCPNetworkStream tcpns, string remoteHost, int remotePort)
        {
            if (this.proxyProtocol == ProxyProtocol.HTTP)
            {
                return HTTPProxyProtocol.ConnectAsync(tcpns, remoteHost, remotePort, proxyUsername, proxyPassword, proxyHost + ":" + proxyPort);
            }else if(this.proxyProtocol == ProxyProtocol.SOCKS5)
            {
                return SOCKS5ProxyProtocol.ConnectAsync(tcpns, remoteHost, remotePort, proxyUsername, proxyPassword);
            }else if(this.proxyProtocol == ProxyProtocol.SOCKS4)
            {
                return SOCKS4ProxyProtocol.ConnectAsync(tcpns, remoteHost, remotePort, proxyUsername, proxyPassword);
            }
            return Task<bool>.FromResult(false);
        }
        public IPEndPoint GetRemoteEndpoint()
        {
            if(proxyAddress == null)
            {
                proxyAddress = IPAddress.Parse(proxyHost);
            }
            return new IPEndPoint(proxyAddress, proxyPort);
        }
    }
}
