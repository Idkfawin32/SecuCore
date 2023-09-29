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

using SecuCore.Sockets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecuCore.Proxies
{
    interface IProxyProtocol
    {
        public static async Task<bool> ConnectAsync(TCPSocket tcpns, string remoteHost, int remotePort, string proxyUsername, string proxyPassword, string extra) => false;
    }
}
