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

using SecuCore.TLS.Exceptions;
using System;
using System.Buffers;
using System.Text;
using static SecuCore.TLS.CipherSuites;

namespace SecuCore.TLS
{
    public static class TLSData
    {
        public static ushort[] preferredCipherSuites = new ushort[] { (ushort)CipherSuiteValue.TLS_RSA_WITH_AES_128_CBC_SHA, (ushort)CipherSuiteValue.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, (ushort)CipherSuiteValue.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA };

        public static byte[] label_extmastersecret = Encoding.ASCII.GetBytes("extended master secret");
        public static byte[] label_mastersecret = Encoding.ASCII.GetBytes("master secret");
        public static byte[] label_keyexpansion = Encoding.ASCII.GetBytes("key expansion");
        public static byte[] label_clientfinished = Encoding.ASCII.GetBytes("client finished");
        public static byte[] label_serverfinished = Encoding.ASCII.GetBytes("server finished");

        public const int RecordLengthLimit = 16383;
        public const int HandshakeLengthLimit = RecordLengthLimit - 4;
        public const int CertificateLengthLimit = RecordLengthLimit - 3 - 4;

        private static byte[] TLS_1_0 = new byte[] { 0x03, 0x01 };
        private static byte[] TLS_1_1 = new byte[] { 0x03, 0x02 };
        private static byte[] TLS_1_2 = new byte[] { 0x03, 0x03 };

        public static byte[] GetVersionBytes(TLSVersion v)
        {
            byte[] versionbytes = null;
            if (v == TLSVersion.TLS10)
                versionbytes = TLS_1_0;
            else if (v == TLSVersion.TLS11)
                versionbytes = TLS_1_1;
            else if (v == TLSVersion.TLS12)
                versionbytes = TLS_1_2;
            return versionbytes;
        }

        public static byte[] GetUnixTime()
        {
            DateTime now = DateTime.Now.ToUniversalTime();
            TimeSpan time = now.Subtract(new DateTime(1970, 1, 1));
            byte[] ret = BitConverter.GetBytes((uint)time.TotalSeconds);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(ret);
            return ret;
        }

        public static byte[] GetCipherSuite(ushort[] ciphers)
        {
            Array.Sort(ciphers);
            byte[] header = new byte[2];
            uint cl2 = (uint)(ciphers.Length * 2);
            byte[] b = new byte[2 + cl2];
            b[0] = (byte)((cl2 >> 8) & 0xff);
            b[1] = (byte)(cl2 & 0xff);
            int idx = 2;
            for (int i = 0; i < ciphers.Length; i++)
            {
                uint cipher = ciphers[i];
                b[idx++] = (byte)((cipher >> 8) & 0xff);
                b[idx++] = (byte)((cipher) & 0xff);
            }
            return b;
        }

        public static byte[] GetExtensions(string externalServerName, bool useExtendedMasterSecret, string curvename)
        {
            byte[] bServerName = GetExtensionsServerName(externalServerName);
            byte[] bSupportedGroups = GetExtensionsSupportedGroups(curvename);
            byte[] bECPointFormats = GetExtensionsECPointFormats();
            byte[] bKeySignatureAlgorithms = new byte[] { 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x02, 0x01 };
            byte[] bECSessionTicket = new byte[] { 0x00, 0x23, 0x00, 0x00 };
            byte[] bECExtendedMasterSec = new byte[] { 0x00, 0x17, 0x00, 0x00 };
            byte[] bRenegotiationInfo = GetExtensionsRenegotiationInfo();
            byte[] last = bRenegotiationInfo;

            if (useExtendedMasterSecret) last = Tools.JoinAll(bECExtendedMasterSec, last);
            int totalLen = bServerName.Length + bSupportedGroups.Length + bECPointFormats.Length + bECSessionTicket.Length + bKeySignatureAlgorithms.Length + last.Length;

            byte[] header = new byte[2];
            header[0] = (byte)((totalLen >> 8) & 0xff);
            header[1] = (byte)(totalLen & 0xff);
            byte[] output = Tools.JoinAll(header, bServerName, bSupportedGroups, bECPointFormats, bKeySignatureAlgorithms, bECSessionTicket, last);
            return output;
        }

        private static byte[] GetExtensionsServerName(string externalServerName)
        {
            int hnlen = externalServerName.Length;
            int lelen = hnlen + 3;
            int flelen = lelen + 2;
            byte[] header = new byte[] { 0x00, 0x00, (byte)((flelen >> 8) & 0xff), (byte)((flelen) & 0xff), (byte)((lelen >> 8) & 0xff), (byte)((lelen) & 0xff), 0x00, (byte)((hnlen >> 8) & 0xff), (byte)((hnlen) & 0xff) };
            byte[] esnb = Encoding.ASCII.GetBytes(externalServerName);
            return Tools.JoinAll(header, esnb);
        }

        public static byte[] GetExtensionsSupportedGroups(string curvename)
        {
            if (curvename == "x25519")
            {
                return new byte[] {
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d // x25519
      };
            }
            return new byte[] {
      0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17 // secp256r1
    };
        }
        public static byte[] GetExtensionsECPointFormats() { return new byte[] { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 }; }
        public static byte[] GetExtensionsRenegotiationInfo() { return new byte[] { 0xff, 0x01, 0x00, 0x01, 0x00 }; }
    }

    public enum TLSVersion { TLS10, TLS11, TLS12 }
    public struct ServerHello
    {
        public TLSVersion tlsVersion;
        public byte[] serverRandom;
        public ushort selectedCipher;
        public static ServerHello Parse(HandshakeRecord hsr)
        {
            ServerHello svh = new ServerHello();

            if (hsr.Data[0] != 0x03)
                throw new TLSProtocolException("Unknown server TLS version");
            if (hsr.Data[1] > 0x03 || hsr.Data[1] == 0x00)
                throw new TLSProtocolException("Unknown server TLS version");

            byte[] srand = new byte[32];
            Buffer.BlockCopy(hsr.Data, 2, srand, 0, 32);
            svh.serverRandom = srand;

            int serversessionidlen = hsr.Data[34];
            int hpos = 35;
            if (serversessionidlen > 0)
                hpos += serversessionidlen;

            int selcuite = 0;
            selcuite |= hsr.Data[hpos++] << 8;
            selcuite |= hsr.Data[hpos++];
            svh.selectedCipher = (ushort)selcuite;

            // ignore everything else
            return svh;
        }
    }

    public struct KeyExchangeInfo
    {
        public ushort namedCurve;
        public ushort keySize;

        public byte[] keyExchangeData;
        public byte[] edchParams;
        public byte[] curveInfo;
        public byte[] publicKey;
        public byte[] signedMessage;
        public byte[] signature;
        public byte[] signatureAlgorithm;

        public static KeyExchangeInfo Parse(byte[] keyExchangeDat, TLSVersion version)
        {
            KeyExchangeInfo kei = new KeyExchangeInfo();
            if (keyExchangeDat[0] != 0x03)
                throw new TLSProtocolException("Curve is not 'named_curve'");

            int namedCurveIdent = 0;
            namedCurveIdent |= keyExchangeDat[1] << 8;
            namedCurveIdent |= keyExchangeDat[2];
            kei.namedCurve = (ushort)namedCurveIdent;
            kei.curveInfo = new byte[] { keyExchangeDat[0], keyExchangeDat[1], keyExchangeDat[2] };

            byte pubkeylen = keyExchangeDat[3];
            kei.keySize = pubkeylen;

            byte[] pubkey = new byte[pubkeylen];
            Buffer.BlockCopy(keyExchangeDat, 4, pubkey, 0, pubkeylen);

            int ecdhParamsLen = 4 + pubkeylen;
            byte[] ecdhParams = new byte[ecdhParamsLen];
            Buffer.BlockCopy(keyExchangeDat, 0, ecdhParams, 0, ecdhParamsLen);
            kei.edchParams = ecdhParams;
            kei.publicKey = pubkey;

            int idx = 4 + pubkeylen;

            if (version == TLSVersion.TLS12)
            {
                kei.signatureAlgorithm = new byte[2];
                kei.signatureAlgorithm[0] = keyExchangeDat[idx++];
                kei.signatureAlgorithm[1] = keyExchangeDat[idx++];
            }

            // sig starts here
            byte[] message = new byte[idx];
            Buffer.BlockCopy(keyExchangeDat, 0, message, 0, idx);
            kei.signedMessage = message;

            int sigLen = 0;
            sigLen |= keyExchangeDat[idx++] << 8;
            sigLen |= keyExchangeDat[idx++];

            if (sigLen > 8192)
                throw new TLSProtocolException("Signature exceeded size limit");

            byte[] sigdat = new byte[sigLen];
            Buffer.BlockCopy(keyExchangeDat, idx, sigdat, 0, sigLen);
            kei.signature = sigdat;
            return kei;
        }
    }

    public struct HandshakeRecord
    {
        public const byte HS_Client_Hello = 0x01;
        public const byte HS_Server_Hello = 0x02;
        public const byte HS_NewSessionTicket = 0x04;
        public const byte HS_Client_KeyExchange = 0x10;
        public const byte HS_Server_KeyExchange = 0x0c;
        public const byte HS_Finished = 0x14;
        public const byte HS_Server_HelloDone = 0x0e;
        public const byte HS_Certificate = 0x0b;

        public byte Type;
        public UInt32 Length;
        public byte[] Data;

        public byte[] Serialize()
        {
            int outlen = 4 + (int)Length;
            byte[] output = new byte[outlen];
            output[0] = Type;
            output[1] = (byte)((Length >> 16) & 0xff);
            output[2] = (byte)((Length >> 8) & 0xff);
            output[3] = (byte)((Length) & 0xff);
            if (Length > 0)
                Buffer.BlockCopy(Data, 0, output, 4, Data.Length);
            return output;
        }

        public static HandshakeRecord Parse(byte[] header, byte[] fragment)
        {
            HandshakeRecord hsr = new HandshakeRecord();
            hsr.Type = header[0];
            uint len = 0;
            len |= (uint)(header[1] << 16);
            len |= (uint)(header[2] << 8);
            len |= (uint)(header[3]);
            hsr.Length = len;
            if (len > 0)
            {
                hsr.Data = fragment;
            }
            return hsr;
        }
        public static HandshakeRecord Parse(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new TLSHandshakeException("No data to parse");
            if (data.Length < 4)
                throw new TLSHandshakeException("No Header");

            HandshakeRecord hsr = new HandshakeRecord();
            hsr.Type = data[0];
            uint len = 0;
            len |= (uint)(data[1] << 16);
            len |= (uint)(data[2] << 8);
            len |= (uint)(data[3]);
            hsr.Length = len;
            if (len > 0)
            {
                if (len > TLSData.HandshakeLengthLimit)
                    throw new TLSProtocolException("Handshake size exceeds limits");
                byte[] hdat = new byte[len];
                Buffer.BlockCopy(data, 4, hdat, 0, (int)len);
                hsr.Data = hdat;
            }
            return hsr;
        }
    }

    public struct TLSRecord
    {
        public const byte TLSR_ChangeSipherSpec = 0x14;
        public const byte TLSR_Alert = 0x15;
        public const byte TLSR_Handshake = 0x16;
        public const byte TLSR_ApplicationData = 0x17;

        public byte Type;
        public ushort Version;
        public ushort Length;
        public byte[] Data;

        public TLSRecord(byte[] ApplicationData, TLSVersion v)
        {
            Type = TLSR_ApplicationData;
            byte major = 0x03;
            byte minor = 0x01;
            if (v == TLSVersion.TLS10)
                minor = 0x01;
            else if (v == TLSVersion.TLS11)
                minor = 0x02;
            else if (v == TLSVersion.TLS12)
                minor = 0x03;
            Version = (ushort)((major << 8) | minor);
            Length = (ushort)ApplicationData.Length;
            Data = ApplicationData;
        }

        public TLSRecord(HandshakeRecord hsr, TLSVersion v)
        {
            byte major = 0x03;
            byte minor = 0x01;
            if (v == TLSVersion.TLS10)
                minor = 0x01;
            else if (v == TLSVersion.TLS11)
                minor = 0x02;
            else if (v == TLSVersion.TLS12)
                minor = 0x03;
            byte[] hsd = hsr.Serialize();
            Type = 0x16;
            Version = (ushort)((major << 8) | minor);
            Length = (ushort)(hsd.Length);
            Data = hsd;
        }

        public byte[] Serialize()
        {
            if (Data == null || Data.Length == 0)
            {
                byte[] header = new byte[5];
                header[0] = Type;
                header[1] = (byte)((Version >> 8) & 0xff);
                header[2] = (byte)((Version & 0xff));
                header[3] = (byte)((Length >> 8) & 0xff);
                header[4] = (byte)((Length & 0xff));
                return header;
            }
            byte[] outbuf = new byte[Data.Length + 5];
            outbuf[0] = Type;
            outbuf[1] = (byte)((Version >> 8) & 0xff);
            outbuf[2] = (byte)((Version & 0xff));
            outbuf[3] = (byte)((Length >> 8) & 0xff);
            outbuf[4] = (byte)((Length & 0xff));
            Buffer.BlockCopy(Data, 0, outbuf, 5, Data.Length);
            return outbuf;
        }
    }
}
