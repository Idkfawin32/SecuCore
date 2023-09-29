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
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Threading;
using SecuCore.Curves;
using SecuCore.Security;
using SecuCore.Shared;
using SecuCore.TLS.Exceptions;
using static SecuCore.KeyDerivation;
using static SecuCore.TLS.CipherSuites;
using static SecuCore.TLS.TLSData;

namespace SecuCore.TLS
{
    public class TLSRecordLayer
    {
        public static TLSVersion preferredVersion = TLSVersion.TLS12;
        public static string preferredNamedCurve = "x25519";
        public static int preferredFragmentSize = 8192;
        public static bool verifyServerSignature = true;
        public static ushort[] AllImplementedCipherSuites = CipherSuites.GetSupportedCipherSuites();

        //for handshake process
        X509Cert remoteServerCertificate;
        X509CertChain serverCertChain;
        KeyExchangeInfo serverKeyExchangeInfo;
        TLSCipherSuite cipherSuite;
        ulong sessionTicketLifetime = 0;
        byte[] sessionTicket = null;

        byte[] tlsEncryptedPremaster;
        byte[] tlsPremasterSecret;
        byte[] tlsMasterSecret;
        byte[] clientRandom;
        byte[] serverRandom;

        //for the key exchange
        byte[] clientPrivateKey;
        byte[] clientPublicKey;

        //for encryption and decryption
        KeyExpansionResult keyRing;

        IDataController dataController;
        TLSVersion vers;
        private string lastErrorString;
        private byte[] versionb;
        private SecRNG srng = new SecRNG();

        public delegate bool ValidateServerCertificate(X509CertChain serverCertificates, bool handshakeSignatureValid);
        public delegate X509Cert ClientCertificateRequest();

        private ValidateServerCertificate certificateValidationCallback = null;
        private ClientCertificateRequest clientCertificateRequestCallback = null;
        private TLSEncryptionProvider tlsCrypt = null;
        private AsyncAutoResetEvent negotiationCompleted = new AsyncAutoResetEvent();

        public bool isConnected = false;
        public bool isFaulted = false;
        private bool trackHandshakes = true;
        private byte[] hsbuf;
        private int hsbufpos = 0;
        private bool sendEncrypted = false;
        private bool recieveEncrypted = false;
        ulong seq_local = 0;
        ulong seq_server = 0;
        private int AvailableApplicationDataBytes = 0;
        private byte[] AvailableApplicationData = null;
        private bool serverHelloDoneRecieved = false;
        private bool serverFinishedRecieved = false;

        private const bool use_extended_master_secret = false;
        private bool verify_server_signature = true;
        private bool shutdownRequested = false;

        public void Dispose()
        {
            shutdownRequested = true;
            negotiationCompleted.Set();
            if (tlsCrypt != null) tlsCrypt.Dispose();
            if (remoteServerCertificate != null) remoteServerCertificate.Dispose();
            if (serverCertChain != null) serverCertChain.Dispose();
            sessionTicket = null;
            tlsMasterSecret = null;
            clientRandom = null;
            serverRandom = null;
            clientPrivateKey = null;
            clientPublicKey = null;
            versionb = null;
            hsbuf = null;
            AvailableApplicationData = null;
            AvailableApplicationDataBytes = 0;
            dataController = null;
        }

        public TLSRecordLayer(IDataController _dataController)
        {
            vers = preferredVersion;
            this.dataController = _dataController;
            this.versionb = GetVersionBytes(vers);
        }

        public TLSRecordLayer(IDataController _dataController, TLSVersion version = TLSVersion.TLS12)
        {
            vers = version;
            this.dataController = _dataController;
            this.versionb = GetVersionBytes(version);
        }

        public async ValueTask<bool> EstablishTLSConnection(string hostname, ValidateServerCertificate ValidateServerCertificateCallback, ClientCertificateRequest CertificateRequestCallback)
        {
            this.certificateValidationCallback = ValidateServerCertificateCallback;
            this.clientCertificateRequestCallback = CertificateRequestCallback;
            try
            {
                _ = HandshakeProcess(hostname);
                await negotiationCompleted.WaitAsync().ConfigureAwait(false);
                return isConnected;
            }
            catch (Exception e)
            {
                lastErrorString = e.Message;
                isFaulted = true;
            }
            return false;
        }

        private async Task HandshakeProcess(string hostname)
        {
            try
            {
                StartLoggingHandshakes();
                HandshakeRecord clienthello = CreateClientHello(hostname);
                SendHandshakeRecord(clienthello);
                FlushOutput();

                while (!serverHelloDoneRecieved)
                {
                    if (shutdownRequested) return;
                    if (!await ReadOne().ConfigureAwait(false)) return;
                }

                HandshakeRecord clientkex;
                if(tlsEncryptedPremaster != null) clientkex = CreateClientPremasterExchange();
                else clientkex = CreateClientKeyExchange();
                
                SendHandshakeRecord(clientkex);
                FlushOutput();

                TLSRecord changeCipherSpec = GetClientChangeCipherSpec();
                ScheduleSend(changeCipherSpec);
                FlushOutput();

                HandshakeRecord clientfinished = CreateClientFinishedRecord();
                SendHandshakeRecord(clientfinished);
                FlushOutput();

                while (!serverFinishedRecieved)
                {
                    if (shutdownRequested) return;
                    if (!await ReadOne().ConfigureAwait(false)) return;
                }

                isConnected = true;
                negotiationCompleted.Set();
            }
            catch (Exception e)
            {
                isFaulted = true;
                lastErrorString = e.Message;
                negotiationCompleted.Set();
            }
        }

        private HandshakeRecord CreateClientKeyExchange()
        {
            int pubkeylen = this.clientPublicKey.Length;
            byte[] publicKeyData = new byte[pubkeylen + 1];
            publicKeyData[0] = (byte)pubkeylen;

            Buffer.BlockCopy(this.clientPublicKey, 0, publicKeyData, 1, pubkeylen);

            return new HandshakeRecord()
            {
                Type = HandshakeRecord.HS_Client_KeyExchange,
                Length = (uint)publicKeyData.Length,
                Data = publicKeyData
            };
        }

        private HandshakeRecord CreateClientPremasterExchange()
        {
            byte[] encryptedPremasterPlusLength = new byte[tlsEncryptedPremaster.Length + 2];
            encryptedPremasterPlusLength[0] = (byte)((tlsEncryptedPremaster.Length >> 8) & 0xff);
            encryptedPremasterPlusLength[1] = (byte)(tlsEncryptedPremaster.Length & 0xff);
            Buffer.BlockCopy(tlsEncryptedPremaster, 0, encryptedPremasterPlusLength, 2, tlsEncryptedPremaster.Length);
            return new HandshakeRecord() { 
                Type = HandshakeRecord.HS_Client_KeyExchange,
                Length = (uint)encryptedPremasterPlusLength.Length,
                Data = encryptedPremasterPlusLength
            };
        }

        private HandshakeRecord CreateClientHello(string externalHost)
        {
            byte[] cliRandom = new byte[32];
            byte[] cliTime = GetUnixTime();
            Buffer.BlockCopy(cliTime, 0, cliRandom, 0, 4);
            srng.GetRandomBytes(cliRandom, 4, 28);
            this.clientRandom = cliRandom;

            byte[] cipherSuite = GetCipherSuite(AllImplementedCipherSuites);
            byte[] compressionMethods = new byte[] { 0x01, 0x00 };
            byte[] extensions = GetExtensions(externalHost, use_extended_master_secret, preferredNamedCurve);
            byte[] hellodata = Tools.JoinAll(versionb, cliRandom, new byte[1] {0}, cipherSuite, compressionMethods, extensions);

            HandshakeRecord hsr = new HandshakeRecord()
            {
                Type = HandshakeRecord.HS_Client_Hello,
                Length = (uint)hellodata.Length,
                Data = hellodata
            };
            return hsr;
        }

        private HandshakeRecord CreateClientFinishedRecord()
        {
            //create verification data
            byte[] allshakeshash = GetFinishedHash();
            using(HMAC hm = cipherSuite.CreateHMAC(tlsMasterSecret))
            {
                byte[] verifyDat = null;
                
                if(vers == TLSVersion.TLS12)
                {
                    verifyDat = GenerateVerifyData(TLSData.label_clientfinished, allshakeshash, hm);
                }
                else
                {
                    verifyDat = GenerateVerifyData11(TLSData.label_clientfinished, allshakeshash, tlsMasterSecret);
                }
                return new HandshakeRecord()
                {
                    Type = HandshakeRecord.HS_Finished,
                    Length = (uint)verifyDat.Length,
                    Data = verifyDat
                };
            }
        }

        private void SendHandshakeRecord(HandshakeRecord hsr)
        {
            UpdateHandshakes(hsr);
            TLSRecord tlsr = new TLSRecord(hsr, vers);
            ScheduleSend(tlsr);
        }

        public Queue<HandshakeRecord> handshakeRecords = new Queue<HandshakeRecord>();
        private async ValueTask<bool> ReadOne()
        {
            if (shutdownRequested) return false;
            try
            {
                if(handshakeRecords.Count == 0)
                {
                    TLSRecord tlsr = await ReadNextRecord().ConfigureAwait(false);

                    if(tlsr.Type == TLSRecord.TLSR_Handshake)
                    {
                        //Parse them here
                        byte[] hsdat = tlsr.Data;

                        int idx = 0;
                        int remain = hsdat.Length;
                        while(remain > 0)
                        {
                            byte[] header = new byte[4];
                            Buffer.BlockCopy(hsdat, idx, header, 0, 4); idx += 4;

                            int hskl = (header[1] << 16 | header[2] << 8 | header[3]);
                            if (hskl > remain) throw new TLSHandshakeException("Error parsing handshake messages");

                            byte[] fragment = new byte[hskl];
                            Buffer.BlockCopy(hsdat, idx, fragment, 0, hskl); idx += hskl;
                            remain -= hskl + 4;
                            HandshakeRecord shk = HandshakeRecord.Parse(header, fragment);
                            handshakeRecords.Enqueue(shk);
                        }
                    }
                    else if (tlsr.Type == TLSRecord.TLSR_ChangeSipherSpec)
                    {
                        recieveEncrypted = true;
                    }
                }
                
                if(handshakeRecords.TryDequeue(out HandshakeRecord hsr))
                {
                    if (hsr.Type == HandshakeRecord.HS_Server_Hello)
                    {
                        ProcessServerHello(hsr);
                    }
                    else if (hsr.Type == HandshakeRecord.HS_Server_KeyExchange)
                    {
                        ProcessServerKeyExchange(hsr);
                    }
                    else if (hsr.Type == HandshakeRecord.HS_Certificate)
                    {
                        ProcessServerCertificate(hsr);
                    }
                    else if (hsr.Type == HandshakeRecord.HS_Server_HelloDone)
                    {
                        ProcessServerHelloDone(hsr);
                    }
                    else if (hsr.Type == HandshakeRecord.HS_NewSessionTicket)
                    {
                        ProcessServerNewSessionTicket(hsr);
                    }
                    else if (hsr.Type == HandshakeRecord.HS_Finished)
                    {
                        ProcessServerFinished(hsr);
                    }
                    UpdateHandshakes(hsr);
                }
                return true;
            }
            catch (Exception ex)
            {
                lastErrorString = ex.Message;
                negotiationCompleted.Set();
            }
            return false;
        }
        private void ProcessServerHello(HandshakeRecord hsr)
        {
            ServerHello svh = ServerHello.Parse(hsr);
            serverRandom = svh.serverRandom;
            if (!preferredCipherSuites.Contains(svh.selectedCipher)) throw new TLSHandshakeException("Server attempting to use unsupported Ciphersuite");
            cipherSuite = InitializeCipherSuite(svh.selectedCipher);
        }
        private void ProcessServerKeyExchange(HandshakeRecord hsr)
        {
            serverKeyExchangeInfo = KeyExchangeInfo.Parse(hsr.Data, vers);
        }

        private void ProcessServerCertificate(HandshakeRecord hsr)
        {
            if (!ParseServerCertificates(hsr)) throw new TLSHandshakeException("Unable to acquire server certificate");
        }
        private void ProcessServerHelloDone(HandshakeRecord hsr)
        {
            bool sigVerified = true;
            if (verify_server_signature)
            {
                if (cipherSuite.tlsparams.keyExchangeAlgorithm != KeyExchangeAlgorithm.RSA) sigVerified = VerifyServerSignature();

                if (certificateValidationCallback != null)
                {
                    if (!certificateValidationCallback.Invoke(serverCertChain, sigVerified)) throw new TLSValidationException("Parent client rejected server certificate");
                }
            }

            if (!CreateKeys()) throw new TLSEncryptionException("Failed to create encryption keys");

            serverHelloDoneRecieved = true;
        }

        private void ProcessServerNewSessionTicket(HandshakeRecord hsr)
        {
            uint lifetime = 0;
            lifetime |= (uint)(hsr.Data[0] << 24);
            lifetime |= (uint)(hsr.Data[1] << 16);
            lifetime |= (uint)(hsr.Data[2] << 8);
            lifetime |= (uint)(hsr.Data[3]);

            ushort ticketlen = 0;
            ticketlen |= (ushort)(hsr.Data[4] << 8);
            ticketlen |= (ushort)(hsr.Data[5]);

            if (ticketlen > 8192) throw new TLSProtocolException("Session Ticket exceeds internal limit");

            byte[] sessticket = new byte[ticketlen];
            Buffer.BlockCopy(hsr.Data, 6, sessticket, 0, ticketlen);

            this.sessionTicket = sessticket;
            this.sessionTicketLifetime = lifetime;
        }

        private void ProcessServerFinished(HandshakeRecord hsr)
        {
            byte[] verifyData = hsr.Data;

            //create verification data
            byte[] allshakeshash = GetFinishedHash();
            using(HMAC hm = cipherSuite.CreateHMAC(tlsMasterSecret))
            {
                byte[] expectedverifyDat = null;
                if(vers == TLSVersion.TLS12)
                {
                    expectedverifyDat = GenerateVerifyData(TLSData.label_serverfinished, allshakeshash, hm);
                }
                else
                {
                    expectedverifyDat = GenerateVerifyData11(TLSData.label_serverfinished, allshakeshash, tlsMasterSecret);
                }
               

                if (!Tools.ArraysEqual(verifyData, expectedverifyDat)) throw new TLSHandshakeException("Failed to verify server finished message");

                FinishLoggingHandshakes();
                serverFinishedRecieved = true;
            }
        }

        private bool CreateKeys()
        {
            try
            {
                byte[] premaster = null;

                KeyExchangeAlgorithm exch = cipherSuite.tlsparams.keyExchangeAlgorithm;
                if (exch == KeyExchangeAlgorithm.RSA)
                {
                    //generate random premaster secret
                    premaster = new byte[48];
                    premaster[0] = versionb[0];
                    premaster[1] = versionb[1];
                    srng.GetRandomBytes(premaster, 2, 46);
                    RSAPublicKey rpk = remoteServerCertificate.GetRSAPublicKey();
                    tlsEncryptedPremaster = rpk.EncryptData(premaster);

                }
                else if (exch == KeyExchangeAlgorithm.ECDHE_RSA || exch == KeyExchangeAlgorithm.ECDHE_ECDSA || exch == KeyExchangeAlgorithm.ECDHE_PSK)
                {
                    //first generate our keys for the key exchange, the public key will be sent on 'client key exchange'
                    GenerateClientKeys(preferredNamedCurve);
                    premaster = CalculateSharedSecret(clientPrivateKey, serverKeyExchangeInfo.publicKey, preferredNamedCurve);
                }
                else
                {
                    //unsupported
                    throw new TLSProtocolException("Unsupported key exchange algorithm");
                }
               
                byte[] master = null;
                tlsPremasterSecret = premaster;
                
                //generate master secret
                if(vers == TLSVersion.TLS12)
                {
                    using (HMAC hm = cipherSuite.CreateHMAC(premaster))
                    {
                        master = GenerateMasterSecret(use_extended_master_secret, clientRandom, serverRandom, hm);
                    }
                    tlsMasterSecret = master;
                    using (HMAC hm = cipherSuite.CreateHMAC(tlsMasterSecret))
                    {
                        this.keyRing = PerformKeyExpansion(master, clientRandom, serverRandom, cipherSuite.tlsparams.HashSize, cipherSuite.tlsparams.BulkKeySize, cipherSuite.tlsparams.BulkIVSize, hm);
                    }
                  
                  
                    return true;
                }
                else if (vers == TLSVersion.TLS11)
                {
                    master = GenerateMasterSecret11(premaster, clientRandom, serverRandom);
                    tlsMasterSecret = master;

                    this.keyRing = PerformKeyExpansionTLS11(master, clientRandom, serverRandom, cipherSuite.tlsparams.HashSize, cipherSuite.tlsparams.BulkKeySize, cipherSuite.tlsparams.BulkIVSize);
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private void GenerateClientKeys(string curvename)
        {
            if(curvename == "x25519")
            {
                byte[] prirnd = new byte[32];
                srng.GetRandomBytes(prirnd, 0, 32);
                byte[] clipri = Curve25519.ClampPrivateKey(prirnd);
                byte[] clipub = Curve25519.GetPublicKey(clipri);

                clientPrivateKey = prirnd;
                clientPublicKey = clipub;
                return;
            }

            //define curve
            ECCurve curve = ECCurve.CreateFromFriendlyName(curvename);

            //generate master secret
            using (ECDiffieHellman clientECDH = ECDiffieHellman.Create(curve))
            {
                ECParameters ecp = clientECDH.ExportParameters(true);
                byte[] privateKey = ecp.D;
                byte[] Qx = ecp.Q.X;
                byte[] Qy = ecp.Q.Y;

                byte[] cprivatekey = new byte[1 + privateKey.Length];
                cprivatekey[0] = 0x04;
                Buffer.BlockCopy(privateKey, 0, cprivatekey, 1, privateKey.Length);

                byte[] cpublicKey = new byte[1 + Qx.Length + Qy.Length];
                cpublicKey[0] = 0x04;
                Buffer.BlockCopy(Qx, 0, cpublicKey, 1, Qx.Length);
                Buffer.BlockCopy(Qy, 0, cpublicKey, 1 + Qx.Length, Qy.Length);
                clientPrivateKey = cprivatekey;
                clientPublicKey = cpublicKey;

            }
        }

        private bool ParseServerCertificates(HandshakeRecord hsr)
        {
            int certificatesLen = 0;
            certificatesLen |= hsr.Data[0] << 16;
            certificatesLen |= hsr.Data[1] << 8;
            certificatesLen |= hsr.Data[2];

            byte[] certificatesData = new byte[certificatesLen];
            Buffer.BlockCopy(hsr.Data, 3, certificatesData, 0, certificatesLen);
            X509CertChain certchn = new X509CertChain();

            int bufp = 0;
            int idx = 0;
            while (bufp < certificatesLen)
            {
                int nextCertLen = 0;
                nextCertLen |= certificatesData[bufp++] << 16;
                nextCertLen |= certificatesData[bufp++] << 8;
                nextCertLen |= certificatesData[bufp++];

                if (nextCertLen > TLSData.CertificateLengthLimit) throw new TLSProtocolException("Certificate[" + idx + "] exceeds bounds");

                byte[] certDat = new byte[nextCertLen];

                Buffer.BlockCopy(certificatesData, bufp, certDat, 0, nextCertLen);
                bufp += nextCertLen;

                X509Cert cert = Security.X509Cert.FromASN(certDat, 0);
                certchn.AddLink(cert);
                if (idx == 0)
                {
                    remoteServerCertificate = cert;
                }
                idx++;
            }
            if (remoteServerCertificate != null)
            {
                this.serverCertChain = certchn;
                return true;
            }
            return false;
        }

        private bool VerifyServerSignature()
        {
            try
            {
                byte[] pms = clientRandom.Concat(serverRandom).Concat(serverKeyExchangeInfo.edchParams).ToArray();
                byte[] sig = serverKeyExchangeInfo.signature;
                if(vers == TLSVersion.TLS12)
                {
                    using (HashAlgorithm ha = cipherSuite.GetHasher())
                    {
                        byte[] dataHash = ha.ComputeHash(pms);
                        return cipherSuite.VerifyHash(dataHash, sig, remoteServerCertificate);
                    }
                }
                else
                {
                    using (MD5 md5 = new MD5CryptoServiceProvider())
                    {
                        using(SHA1 sha1 = new SHA1CryptoServiceProvider())
                        {
                            byte[] md5Hash = md5.ComputeHash(pms);
                            byte[] sha1Hash = sha1.ComputeHash(pms);
                            byte[] hash = new byte[md5Hash.Length + sha1Hash.Length];
                            Buffer.BlockCopy(md5Hash, 0, hash, 0, md5Hash.Length);
                            Buffer.BlockCopy(sha1Hash, 0, hash, md5Hash.Length, sha1Hash.Length);
                            return cipherSuite.VerifyHash(hash, sig, remoteServerCertificate);
                        }
                    }
                }

            }
            catch (Exception)
            {
                return false;
            }           
        }

        private TLSRecord GetClientChangeCipherSpec()
        {
            TLSRecord tlsr = new TLSRecord()
            {
                Type = 0x14,
                Version = (ushort)(versionb[0] << 8 | versionb[1]),
                Length = (ushort)0x01,
                Data = new byte[] { 0x01 }
            };
            return tlsr;
        }

        private void StartLoggingHandshakes()
        {
            hsbuf = new byte[8192];
            hsbufpos = 0;
            trackHandshakes = true;
        }
        private void FinishLoggingHandshakes()
        {
            hsbuf = null;
            hsbufpos = 0;
            trackHandshakes = false;
        }
        private void UpdateHandshakes(HandshakeRecord hsr)
        {
            if (!trackHandshakes) return;
            byte[] hshk = hsr.Serialize();
            if (hsbufpos + hshk.Length > hsbuf.Length)
            {
                //this almost never happen
                byte[] rsz = new byte[hsbuf.Length + 4096];
                Buffer.BlockCopy(hsbuf, 0, rsz, 0, hsbufpos);
                hsbuf = rsz;
            }

            Buffer.BlockCopy(hshk, 0, hsbuf, hsbufpos, hshk.Length);
            hsbufpos += hshk.Length;
        }

        private byte[] GetFinishedHash()
        {
            byte[] hshdat = Tools.SubArray(hsbuf, 0, hsbufpos);
            if(vers == TLSVersion.TLS12)
            {
                using (HashAlgorithm ha = SHA256.Create())
                {
                    byte[] hshhash = ha.ComputeHash(hshdat);
                    return hshhash;
                }
            }
            else
            {
                byte[] hash = new byte[36];
                using (MD5 md5 = MD5.Create())
                {
                    byte[] hshmd5 = md5.ComputeHash(hshdat);
                    Buffer.BlockCopy(hshmd5, 0, hash, 0, 16);
                }
                using (SHA1 sha1 = SHA1.Create())
                {
                    byte[] hshsha1 = sha1.ComputeHash(hshdat);
                    Buffer.BlockCopy(hshsha1, 0, hash, 16, 20);
                }
                return hash;
            }        
        }

        private void InitializeEncryption()
        {
            tlsCrypt = cipherSuite.InitializeEncryption(this.keyRing);
        }


        private void ScheduleSend(TLSRecord tlso, TaskCompletionSource _tcs = null)
        {
            if (shutdownRequested) return;

            if (sendEncrypted)
            {
                tlso = Encryption.EncryptRecord(tlso, tlsCrypt, seq_local);
                seq_local++;
            }
            if (tlso.Type == TLSRecord.TLSR_ChangeSipherSpec)
            {
                //we are changing to an encrypted state
                InitializeEncryption();
                sendEncrypted = true;
                seq_local = 0;
            }
            dataController.QueueData(new DataDispatch()
            {
                data = tlso.Serialize(),
                tcs = _tcs
            });
        }

        private void FlushOutput()
        {
            dataController.FlushData();
        }

        private ValueTask<byte[]> AskForData(int len)
        {
            TaskCompletionSource<byte[]> dtcs = new TaskCompletionSource<byte[]>();
            DataRequest dr = new DataRequest()
            {
                length = len,
                tcs = dtcs
            };
            dataController.RequestData(dr);
            return new ValueTask<byte[]>(dtcs.Task);
        }

        private async ValueTask<TLSRecord> ReadNextRecord()
        {
            byte[] header = await AskForData(5).ConfigureAwait(false);
            if (header.Length != 5) throw new TLSNetworkException("Failed while reading TLS record");

            byte _type = header[0];
            ushort _version = (ushort)(header[2] | (header[1] << 8));
            ushort _recordLength = (ushort)(header[4] | (header[3] << 8));

            if (_recordLength > TLSData.RecordLengthLimit)
            {
                //throw new TLSProtocolException("Record exceeds length limits");
            }
            byte[] _data = await AskForData(_recordLength).ConfigureAwait(false);

            if (_type == 0x15)
            {
                ushort _alertLen = (ushort)(header[4] | (header[3] << 8));
                bool fatal = (_data[0] == 2);
                if (fatal)
                {
                    throw new TLSRecordException("TLS Alert fatal: " + _data[1].ToString("X2"));
                }
            }

            TLSRecord tlsr = new TLSRecord()
            {
                Type = _type,
                Version = _version,
                Length = _recordLength,
                Data = _data
            };

            if (recieveEncrypted) tlsr = Encryption.DecryptRecord(tlsr, tlsCrypt, seq_server);

            seq_server++;
            if(tlsr.Type == TLSRecord.TLSR_ChangeSipherSpec)
            {
                seq_server = 0;
            }
            
            return tlsr;
        }

        public async ValueTask<int> ReadApplicationDataAsync(byte[] dest, int offset, int length)
        {
            if (shutdownRequested) return -1;
            try
            {
                int read = 0;
                if (AvailableApplicationDataBytes > 0)
                {
                    if (AvailableApplicationDataBytes > length)
                    {
                        //we have more than needed
                        Buffer.BlockCopy(AvailableApplicationData, 0, dest, offset, length);
                        read += length;

                        byte[] remain = new byte[AvailableApplicationDataBytes - length];
                        Buffer.BlockCopy(AvailableApplicationData, length, remain, 0, remain.Length);
                        AvailableApplicationData = remain;
                        AvailableApplicationDataBytes -= length;
                        return read;
                    }
                    else
                    {
                        //we can exhaust our buffer, but we require more
                        int copylen = AvailableApplicationDataBytes;
                        Buffer.BlockCopy(AvailableApplicationData, 0, dest, offset, copylen);
                        read += copylen;
                        AvailableApplicationData = null;
                        AvailableApplicationDataBytes = 0;
                        offset += copylen;
                        length -= copylen;

                        if (length <= 0) return read;
                    }
                }
                TLSRecord next = await ReadNextRecord().ConfigureAwait(false);

                if (next.Type == TLSRecord.TLSR_Alert)
                {
                    if(next.Data.Length >= 2)
                    {
                        if (next.Data[1] == 0)
                        {
                            //close notify
                            return read;
                        }
                    }
                }
                if (next.Type == TLSRecord.TLSR_ApplicationData)
                {

                    byte[] newApplicationData = next.Data;
                    if (newApplicationData.Length > length)
                    {
                        Buffer.BlockCopy(newApplicationData, 0, dest, offset, length);
                        byte[] remain = new byte[newApplicationData.Length - length];
                        Buffer.BlockCopy(newApplicationData, length, remain, 0, remain.Length);
                        AvailableApplicationData = remain;
                        AvailableApplicationDataBytes = remain.Length;
                        read += length;
                    }
                    else
                    {
                        //give them what we can, no need to save any available data
                        Buffer.BlockCopy(newApplicationData, 0, dest, offset, newApplicationData.Length);
                        read += newApplicationData.Length;
                    }
                    return read;
                }
                else
                {
                    return -1;
                }
            }
            catch (Exception ex) { }
            return -1;
        }

        public ValueTask SendApplicationDataAsync(byte[] data)
        {
            if (shutdownRequested) return new ValueTask();
            int datlen = data.Length;
            int limit = 16384 - 5 - 20 - 100;
            limit = preferredFragmentSize;
            if (datlen > limit)
            {
                int bpos = 0;
                int remain = datlen;

                while (remain > 0)
                {
                    int copysize = preferredFragmentSize;
                    if (copysize > remain) copysize = remain;

                    byte[] recdat = new byte[copysize];
                    Buffer.BlockCopy(data, bpos, recdat, 0, copysize);
                    bpos += copysize;
                    remain -= copysize;

                    TLSRecord fragrec = new TLSRecord(recdat, vers);

                    if (remain <= 0)
                    {
                        //if this is the last in the sequence
                        TaskCompletionSource tcs = new TaskCompletionSource();
                        ScheduleSend(fragrec, tcs);
                        FlushOutput();
                        return new ValueTask(tcs.Task);
                    }
                    else
                    {
                        ScheduleSend(fragrec);
                    }
                }
            }
            else
            {
                TaskCompletionSource tcs = new TaskCompletionSource();
                TLSRecord apld = new TLSRecord(data, vers);
                ScheduleSend(apld, tcs);
                FlushOutput();
                return new ValueTask(tcs.Task);
            }
            return new ValueTask(Task.FromException(new Exception("Failure during dispatch")));
        }
    }
}
