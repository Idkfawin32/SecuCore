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

using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using System;

namespace SecuCore.Proxies
{
    public class SOCKS4ProxyProtocol : IProxyProtocol
    {
        public static async Task<bool> ConnectAsync(Sockets.TCPNetworkStream tcpns, string remoteHost, int remotePort, string proxyUsername, string proxyPassword)
        {
            byte[] conp = Socks4ConnectPacket(remoteHost, remotePort);
            await tcpns.WriteAsync(conp, 0, conp.Length).ConfigureAwait(false);
            byte[] readb = new byte[64];
            int len = await tcpns.ReadAsync(readb, 0, readb.Length).ConfigureAwait(false);
            if (len <= 0) return false;

            if (readb[0] == 0x04)
            {
                if (readb[1] == 0x5A)
                {
                    return true;
                }
            }
            return false;
        }

        public static byte[] Socks4ConnectPacket(string host, int port)
        {
            List<byte> connectionPacket = new();
            {
                var withBlock = connectionPacket;
                // Write packet feader
                withBlock.Add(4); // socks version 4
                withBlock.Add(1); // TCP Stream Connection

                // Write port, network order
                withBlock.AddRange(PortToBytes(port));

                // Write address, network order
                IPAddress dest = IPAddress.Parse(host);
                byte[] ipb = dest.GetAddressBytes();
                Array.Reverse(ipb);
                withBlock.AddRange(ipb);
                withBlock.Add(0);
            }
            return connectionPacket.ToArray();
        }

        private static byte[] PortToBytes(int port)
        {
            ushort ps = (ushort)port;
            byte[] pb = BitConverter.GetBytes(ps);

            // network order bytes
            byte[] nb = new byte[2];

            if (BitConverter.IsLittleEndian)
            {
                nb[0] = pb[1];
                nb[1] = pb[0];
            }
            else
            {
                nb[0] = pb[0];
                nb[1] = pb[1];
            }
            return nb;
        }
    }
}