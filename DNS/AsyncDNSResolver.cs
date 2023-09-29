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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecuCore.DNS
{
    public static class Extensions
    {
        public static void WriteBigEndian16(this BinaryWriter bw, ushort littleEndian)
        {
            ushort swapped = (ushort)((littleEndian >> 8) | ((littleEndian & 255) << 8));
            bw.Write(swapped);
        }
    }
    public static class AsyncDNSResolver
    {
        //Uses Google Public DNS by Default
        private static readonly IPAddress[] DNSServers = new IPAddress[]
        {
            IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4")
        };

        public static int Timeout { get; set; } = 120000;
        private const int minPayloadSize = 17;
        private const int maxPayloadSize = 2048;

        //Connects utilizing DNS through TCP, Port 53
        private async static Task<bool> ConnectDNS(this Socket socket, IPAddress ip)
        {
            try
            {
                await socket.ConnectAsync(ip, 53).ConfigureAwait(false);
            }
            catch (Exception ex)
            { }
            return socket.Connected;
        }


        //The Primary Sending/Recieving Functions for this class
        private async static Task<int> Send(Socket socket, byte[] buf)
        {
            return await Task<int>.Factory.FromAsync(socket.BeginSend(buf, 0, buf.Length, SocketFlags.None, null, null), socket.EndSend).ConfigureAwait(false);
        }
        private async static Task<int> Recieve(Socket socket, byte[] buf)
        {
            int result = 0;
            try
            {
                result = await socket.ReceiveAsync(buf, SocketFlags.None).WithTimeout(TimeSpan.FromMilliseconds(Timeout)).ConfigureAwait(false);
            }
            catch (Exception ex)
            { }
            return result;
        }

        public async static Task<string> GetFirstMXrecord(string domain)
        {
            string[] mxr = await GetMXrecords(domain).ConfigureAwait(false);
            if (mxr.Length > 0)
                return mxr[0];
            return "";
        }
        public async static Task<string> GetFirstArecord(string domain)
        {
            string[] mxr = await GetArecords(domain).ConfigureAwait(false);
            if (mxr.Length > 0)
                return mxr[0];
            return "";
        }

        public static Task<string[]> GetMXrecords(string domain)
        {
            return GetByHost(domain, QueryType.MX);
        }
        public static Task<string[]> GetArecords(string domain)
        {
            return GetByHost(domain, QueryType.A);
        }
        public static Task<string[]> GetAAAArecords(string domain)
        {
            return GetByHost(domain, QueryType.AAAA);
        }
        public static Task<string[]> GetTXTrecords(string domain)
        {
            return GetByHost(domain, QueryType.TXT);
        }
        private static readonly List<ushort> transactionids = new();
        private static SemaphoreSlim tsem = new SemaphoreSlim(1);
        private static async Task<ushort> GetTransactionID()
        {
            await tsem.WaitAsync().ConfigureAwait(false);
            try
            {
                ushort result = 0;
                while (true)
                {
                    ushort tID = RandomNumbers.GetNext16();
                    if (!transactionids.Contains(tID))
                    {
                        transactionids.Add(tID);
                        if (transactionids.Count > 10000) transactionids.RemoveAt(0);
                        result = tID;
                        break;
                    }
                }
                return result;
            }
            catch (Exception)
            {
                return RandomNumbers.GetNext16();
            }
            finally
            {
                tsem.Release();
            }
        }
        private async static Task ReturnTransactionID(ushort utid)
        {
            await tsem.WaitAsync().ConfigureAwait(false);
            try
            {
                if (transactionids.Contains(utid))
                {
                    transactionids.Remove(utid);
                }
            }
            catch (Exception e)
            { }
            tsem.Release();
        }
        public static bool ResultWasWithin(int value, ref int destination, int min, int max)
        {
            if (value >= min & value <= max)
            {
                destination = value;
                return true;
            }
            return false;
        }
        private async static Task<string[]> GetByHost(string domain, QueryType qt)
        {
            using Socket dnsSock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (!await dnsSock.ConnectDNS(DNSServers[RandomNumbers.GetNext(0, DNSServers.Length - 1)]).ConfigureAwait(false)) return null; // could not establish connection
            
            ushort transactionID = await GetTransactionID().ConfigureAwait(false);
            byte[] payload = null;
            if (!DNSPacket.CreateRecursiveQuestionPayload(transactionID, domain, qt, ref payload))
            {
                await ReturnTransactionID(transactionID).ConfigureAwait(false);
                return null; // internal error attempting to create query
            }
            if (await Send(dnsSock, payload).ConfigureAwait(false) == 0)
            {
                await ReturnTransactionID(transactionID).ConfigureAwait(false);
                return null; // error sending query
            }
            byte[] rBuf = new byte[maxPayloadSize];
            int len = 0;
            if (!ResultWasWithin(await Recieve(dnsSock, rBuf).ConfigureAwait(false), ref len, minPayloadSize, maxPayloadSize))
            {
                await ReturnTransactionID(transactionID).ConfigureAwait(false);
                return null; // result was malformed
            }
            Array.Resize<byte>(ref rBuf, len); // prune the buffer
            await ReturnTransactionID(transactionID).ConfigureAwait(false);
            DNSPacket dnsResponse = null;
            if (!DNSPacket.ParseResponse(rBuf, ref dnsResponse)) return null; // failed to parse response, or no answers were contained
            return dnsResponse.GetAnswers(qt);
        }
    }
    public enum QueryType
    {
        A = 1,
        AAAA = 28,
        CNAME = 5,
        MX = 15,
        NS = 2,
        PTR = 12,
        TXT = 16
    }
    public class DNSPacket
    {
        public ushort transactionID;
        public ushort flags;
        public ushort questions;
        public ushort answerRRs;
        public ushort authorityRRs;
        public ushort additionalRRs;
        public List<DNSQuestion> queries = new();
        public List<DNSAnswer> answers = new();
        public DNSPacket(byte[] buf)
        {
            this.ParseBuffer(buf);
        }
        public DNSPacket(ushort transactionID)
        {
            this.transactionID = transactionID;
        }
        private DNSPacket()
        { }
        public static bool ParseResponse(byte[] buf, ref DNSPacket rPack)
        {
            try
            {
                rPack = new DNSPacket(buf);
                if (rPack.answers.Count > 0) return true;
            }
            catch (Exception e)
            { }
            return false;
        }
        public static bool CreateRecursiveQuestionPayload(ushort transactionID, string question, QueryType qt, ref byte[] buf)
        {
            try
            {
                DNSPacket dnsQ = new(transactionID);
                dnsQ.SetRecursive();
                dnsQ.AddQuestion(question, qt);
                buf = dnsQ.GetBytes();
                return true;
            }
            catch (Exception)
            { }
            return false;
        }
        public void SetRecursive()
        {
            flags = (ushort)(flags | System.Convert.ToUInt16(Math.Pow(2, 8)));
        }
        public void AddQuestion(string name, QueryType type)
        {
            queries.Add(new DNSQuestion(name, (ushort)type));
            questions = (ushort)queries.Count;
        }
        public byte[] GetBytes()
        {
            using System.IO.MemoryStream packetms = new();
            using BinaryWriter bw = new(packetms);
            additionalRRs = 1;
            bw.WriteBigEndian16(transactionID);
            bw.WriteBigEndian16(flags);
            bw.WriteBigEndian16(questions);
            bw.WriteBigEndian16(answerRRs);
            bw.WriteBigEndian16(authorityRRs);
            bw.WriteBigEndian16(additionalRRs);
            foreach (DNSQuestion q in queries)
                q.WriteTo(bw);
            byte[] optpacket = new byte[11];
            optpacket[2] = (byte)41;
            optpacket[3] = (byte)5;
            bw.Write(optpacket, 0, optpacket.Length);
            return packetms.ToArray();
        }
        private static uint ReadInt(ref uint index, byte[] buffer)
        {
            uint value = (uint)((buffer[index] << 24) | ((int)(buffer[index + 1]) << 16) | ((int)(buffer[index + 2]) << 8) | (int)(buffer[index + 3]));
            index += 4;
            return value;
        }
        private static ushort ReadShort(ref uint index, byte[] buffer)
        {
            ushort value = (ushort)(((int)(buffer[index]) << 8) | ((int)(buffer[(index + 1)])));
            index += 2;
            return value;
        }
        private string ReadName(ref uint idx, byte[] buf)
        {
            string @out = "";
            while (idx < buf.Length)
            {
                int lbl = buf[idx];
                idx += 1;
                if (lbl == 0) return @out;
                else if (lbl > 63)
                {
                    uint namePosition = (ushort)(((lbl << 8) | buf[idx]) & 0x3FFF);
                    idx += 1;
                    return (@out != "" ? @out + "." : "") + ReadName(ref namePosition, buf);
                }
                else
                {
                    @out += (@out != "" ? "." : "") + Encoding.ASCII.GetString(buf, (int)idx, lbl);
                    idx += (uint)lbl;
                }
            }
            return @out;
        }
        public static int ByteAt(int input, int position)
        {
            if (position > 3) throw new Exception("You can only use positions 0 through 3");
            return (input >> ((3 - position) * 8)) & 255;
        }
        public void ParseBuffer(byte[] buf)
        {
            uint idx = 0;
            transactionID = ReadShort(ref idx, buf);
            flags = ReadShort(ref idx, buf);
            questions = ReadShort(ref idx, buf);
            answerRRs = ReadShort(ref idx, buf);
            authorityRRs = ReadShort(ref idx, buf);
            additionalRRs = ReadShort(ref idx, buf);
            Int16 rescode = ((short)(flags & 63));
            if (rescode > 0)
            {
                switch (rescode)
                {
                    case 1:
                        throw new Exception("Format Error");
                    case 2:
                        throw new Exception("Server Failure");
                    case 3:
                        throw new Exception("Name Error");
                    case 4:
                        throw new Exception("Not Implemented");
                    case 5:
                        throw new Exception("Refused");
                }
                throw new Exception("Unknown Error");
            }
            for (int i = 0; i <= questions - 1; i++)
            {
                string nm = ReadName(ref idx, buf);
                ushort qtype = ReadShort(ref idx, buf);
                ushort qclass = ReadShort(ref idx, buf);
                DNSQuestion q = new(nm, qtype);
                queries.Add(q);
            }
            for (int i = 0; i <= answerRRs - 1; i++)
            {
                DNSAnswer ans = new()
                {
                    name = ReadName(ref idx, buf),
                    type = ReadShort(ref idx, buf),
                    @class = ReadShort(ref idx, buf),
                    TTL = ReadInt(ref idx, buf),
                    dataLength = ReadShort(ref idx, buf)
                };
                QueryType anstype = (QueryType)ans.type;
                if (anstype == QueryType.MX)
                {
                    ans.preference = ReadShort(ref idx, buf);
                    ans.rdata = ReadName(ref idx, buf);
                }
                else if (anstype == QueryType.CNAME)
                {
                    ans.rdata = ReadName(ref idx, buf);
                }
                else if (anstype == QueryType.TXT)
                {
                    string txtDat = "";
                    int bytesRead = 0;
                    while (ans.dataLength > bytesRead)
                    {
                        byte nLen = buf[idx];
                        idx++;
                        bytesRead++;
                        string txtStr = System.Text.Encoding.ASCII.GetString(buf, (int)idx, nLen);
                        txtDat += txtStr;
                        idx += nLen;
                        bytesRead += nLen;
                    }
                    ans.rdata = txtDat;
                }
                else if (anstype == QueryType.A && ans.dataLength == 4)
                {
                    int ip32 = (int)ReadInt(ref idx, buf);
                    ans.rdata = ByteAt(ip32, 0) + "." + ByteAt(ip32, 1) + "." + ByteAt(ip32, 2) + "." + ByteAt(ip32, 3);
                }
                else if (anstype == QueryType.AAAA)
                {
                    byte[] ipv6 = new byte[16];
                    Array.Copy(buf, idx, ipv6, 0, 16);
                    IPAddress ipv6Addr = new(ipv6);
                    ans.rdata = ipv6Addr.ToString();
                }
                if (ans.rdata != "") answers.Add(ans);
            }
        }
        public string[] GetAnswers(QueryType qt)
        {
            List<DNSAnswer> qualified = new List<DNSAnswer>();
            foreach(DNSAnswer answer in answers)
            {
                if (answer.type == (ushort)qt) qualified.Add(answer);
            }
            if(qt == QueryType.MX)
            {
                qualified = qualified.OrderBy(x =>
                {
                    return x.preference;
                }).ToList();
            }
            return Array.ConvertAll<DNSAnswer, string>(qualified.ToArray(), new Converter<DNSAnswer, string>(d =>
            {
                return d.rdata;
            }));
        }
    }
    public class DNSQuestion
    {
        public string name;
        public ushort type;
        private readonly ushort @class = 1;
        public DNSQuestion(string name, ushort type)
        {
            this.name = name;
            this.type = type;
        }
        public void WriteTo(BinaryWriter bw)
        {
            string[] labels = name.Split('.');
            foreach (string lbl in labels)
            {
                bw.Write(System.Convert.ToByte(lbl.Length));
                bw.Write(Encoding.ASCII.GetBytes(lbl));
            }
            bw.Write(System.Convert.ToByte(0));
            bw.WriteBigEndian16(type);
            bw.WriteBigEndian16(@class);
        }
        public byte[] GetBytes()
        {
            using MemoryStream ms = new();
            using BinaryWriter bw = new(ms);
            WriteTo(bw);
            return ms.ToArray();
        }
    }
    public class DNSAnswer
    {
        public string name;
        public ushort type;
        public ushort @class;
        public UInt32 TTL;
        public ushort dataLength;
        public ushort preference;
        public string rdata;
    }
}