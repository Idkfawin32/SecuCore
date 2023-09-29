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
using System.Text;
using System.Threading.Tasks;

namespace SecuCore.Proxies
{

    public class HTTPProxyProtocol : IProxyProtocol
    {
        private const string httpConnectHostPort = "CONNECT {0}:{1} HTTP/1.1\r\n\r\n";
        private const string httpConnectHostPortAuth = "CONNECT {0}:{1} HTTP/1.1\r\nProxy-Authorization: Basic {2}\r\n\r\n";
        private static string CreateHTTPConnectHeaders(string destHost, int destport, string proxyUsername, string proxyPassword)
        {
            if (!string.IsNullOrEmpty(proxyUsername) && !string.IsNullOrEmpty(proxyPassword))
            {
                //auth
                string b64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(proxyUsername + ":" + proxyPassword));
                return string.Format(httpConnectHostPortAuth, destHost, destport, b64);
            }
            else
            {
                return string.Format(httpConnectHostPort, destHost, destport);
            }
        }

        public static async Task<bool> ConnectAsync(Sockets.TCPNetworkStream tcpns, string remoteHost, int remotePort, string proxyUsername, string proxyPassword, string extra)
        {
            string http_connect_headers = CreateHTTPConnectHeaders(remoteHost, remotePort, proxyUsername, proxyPassword);
            byte[] header_data = Encoding.ASCII.GetBytes(http_connect_headers);
            await tcpns.WriteAsync(header_data, 0, header_data.Length).ConfigureAwait(false);
            byte[] received = await tcpns.ReadUntilCRLFCRLF().ConfigureAwait(false);
            if (received == null) return false;
            int rlen = received.Length;
            if (rlen <= 9) return false;
            string result = Encoding.ASCII.GetString(received, 0, rlen);
            string code = result.Substring(9, 3);
            if (code != "200") return false;
            return true;
        }
    }
}
