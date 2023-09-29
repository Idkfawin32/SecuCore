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
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System;

namespace SecuCore.Proxies
{
    public class SOCKS5ProxyProtocol : IProxyProtocol
    {
        public static readonly byte[] Socks5greeting = { 0x5, 0x2, 0x0, 0x2 };

        public static async Task<bool> ConnectAsync(Sockets.TCPNetworkStream tcpns, string remoteHost, int remotePort, string proxyUsername, string proxyPassword)
        {
            byte[] socksReadBuf = new byte[64];

            await tcpns.WriteAsync(Socks5greeting, 0, Socks5greeting.Length).ConfigureAwait(false);

            if (await tcpns.ReadAsync(socksReadBuf, 0, 2).ConfigureAwait(false) < 2) return false;

            int vers = socksReadBuf[0];
            int authmethod = socksReadBuf[1];
            if (vers != 5 || authmethod != 0) return false;

            byte[] conp = Socks5ConnectPacket(remoteHost, remotePort);

            await tcpns.WriteAsync(conp, 0, conp.Length).ConfigureAwait(false);

            int len = await tcpns.ReadAsync(socksReadBuf, 0, socksReadBuf.Length).ConfigureAwait(false);
            if (len <= 0) return false;

            vers = (int)socksReadBuf[0];
            if (vers == 0x05)
            {
                Socks5ConnectResult status = (Socks5ConnectResult)socksReadBuf[1];
                if (status == Socks5ConnectResult.Succcess)
                {
                    int boundType = socksReadBuf[3];
                    int totalResponseSize = 4;
                    if (boundType == 1)
                    {
                        totalResponseSize += 4;
                    }
                    else if (boundType == 3)
                    {
                        int strl = socksReadBuf[4];
                        totalResponseSize += strl + 1;
                    }
                    else if (boundType == 4)
                    {
                        totalResponseSize += 16;
                    }
                    totalResponseSize += 2;

                    int remainingSize = totalResponseSize - len;

                    if (remainingSize > 0)
                    {
                        byte[] remainb = new byte[remainingSize];

                        len = await tcpns.ReadAsync(remainb, 0, remainb.Length).ConfigureAwait(false);
                        if (len <= 0) return false;
                    }
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        public enum Socks5ConnectResult
        {
            Succcess,
            Failure,
            NotAllowedByRuleSet,
            NetworkUnreachable,
            HostUnreachable,
            ConnectionRefused,
            TTLExpired,
            NotSupportedProtocol
        }
        public static byte[] Socks5ConnectPacket(string host, int port)
        {
            int hostType;
            if (Regex.IsMatch(host, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                hostType = 1; // ipv4 address
            else if (Regex.IsMatch(host, @"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"))
                hostType = 4; // ipv6 address
            else
                hostType = 3; // domain name

            List<byte> connectionPacket = new();

            {
                var withBlock = connectionPacket;
                // Write packet feader
                withBlock.Add(5); // socks version 5
                withBlock.Add(1); // TCP Stream Connection
                withBlock.Add(0); // RFC Reserved 0 

                // Write address
                withBlock.Add((byte)hostType); // Address Type
                switch (hostType)
                {
                    case 1 // ipv4
                    :
                        {
                            IPAddress dest = IPAddress.Parse(host);
                            withBlock.AddRange(dest.GetAddressBytes());
                            break;
                        }

                    case 4 // ipv6
                    :
                        {
                            IPAddress dest = IPAddress.Parse(host);
                            withBlock.AddRange(dest.GetAddressBytes());
                            break;
                        }

                    case 3 // domain
                    :
                        {
                            withBlock.Add((byte)host.Length);
                            withBlock.AddRange(System.Text.Encoding.UTF8.GetBytes(host));
                            break;
                        }
                }

                // Write port
                withBlock.AddRange(PortToBytes(port));
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