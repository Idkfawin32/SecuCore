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
using System.Security.Cryptography.X509Certificates;
using SecuCore.Security;

namespace SecuCore.TLS
{
    public static class CipherSuites
    {
        public enum ConnectionEnd
        {
            SERVER,
            CLIENT
        }
        public enum PRFAlgorithm
        {
            LEGACY,
            TLS_PRF_SHA256,
            TLS_PRF_SHA384
        }
        public enum KeyExchangeAlgorithm
        {
            NULL,
            RSA,
            RSA_EXPORT,
            DHE_DSS,
            DHE_DSS_EXPORT,
            DHE_RSA,
            DHE_RSA_EXPORT,
            DH_DSS,
            DH_DSS_EXPORT,
            DH_RSA,
            DH_RSA_EXPORT,
            DH_anon,
            DH_anon_EXPORT,
            //RFC 4279
            PSK,
            DHE_PSK,
            RSA_PSK,
            //RFC 4429
            ECDH_ECDSA,
            ECDHE_ECDSA,
            ECDH_RSA,
            ECDHE_RSA,
            ECDH_anon,
            //RFC 5054
            SRP,
            SRP_DSS,
            SRP_RSA,
            //RFC 5489
            ECDHE_PSK
        }
        public enum BulkCipherAlgorithm
        {
            NULL,
            RC4,
            RC2,
            DES,
            _3DES,
            DES40,
            AES,
            IDEA
        }
        public enum CipherType
        {
            STREAM,
            BLOCK,
            AEAD
        }
        public enum MACAlgorithm
        {
            NULL,
            MD5,
            SHA,
            HMAC_MD5 = MD5,
            HMAC_SHA1 = SHA,
            HMAC_SHA256,
            HMAC_SHA384,
            HMAC_SHA512
        }
        public enum CompressionMethod
        {
            NULL,
            DEFLATE
        }

        public class SecurityParameters
        {
            public ConnectionEnd entity;
            public BulkCipherAlgorithm bulk_cipher_algorithm;
            public CipherType cipher_type;
            public byte key_size;
            public CompressionMethod compression_algorithm;
            public byte[] master_secret;
            public byte[] client_random;
            public byte[] server_random;
        }

        public enum BulkAlgorithmType
        {
            Stream,
            Block,
            AEAD
        }

        public class TLSEncryptionProvider
        {
            public TLSCipherSuite tcs;
            public BulkAlgorithmType bulkAlgorithmType;
            public int AuthenticationTagSize;
            public int HashSize;
            public int IVSize;
            public int BlockSize;
            public KeyedHashAlgorithm LocalHasher;
            public KeyedHashAlgorithm RemoteHasher;
            public ICryptoTransform Encryptor;
            public ICryptoTransform Decryptor;

            private void DisposeIfExists(IDisposable d)
            {
                if (d != null) d.Dispose();
            }
            public void Dispose()
            {
                DisposeIfExists(Decryptor);
                DisposeIfExists(Encryptor);
                DisposeIfExists(LocalHasher);
                DisposeIfExists(RemoteHasher);
            }
        }

        public class TLSCipherImplementation
        {
            public Func<SymmetricAlgorithm> getBulkFunc;
            public Func<HashAlgorithm> getHashFunc;
            public Func<byte[], HMAC> createHMACFunc;
            public Func<byte[], byte[], X509Cert, bool> verifyHashFunc;
            public TLSCipherImplementation(Func<SymmetricAlgorithm> _getBulkFunction, Func<HashAlgorithm> _getHashFunction, Func<byte[], HMAC> _createHMACFunc, Func<byte[], byte[], X509Cert, bool> _verifyHashFunc)
            {
                this.getBulkFunc = _getBulkFunction;
                this.getHashFunc = _getHashFunction;
                this.createHMACFunc = _createHMACFunc;
                this.verifyHashFunc = _verifyHashFunc;
            }
            public SymmetricAlgorithm GetBulker() => getBulkFunc.Invoke();
            public HashAlgorithm GetHasher() => getHashFunc.Invoke();
            public HMAC CreateHMAC(byte[] key) => createHMACFunc.Invoke(key);
            public bool VerifyHash(byte[] hash, byte[] sig, X509Cert cert) => verifyHashFunc.Invoke(hash, sig, cert);
        }

        public struct TLSCipherParameters
        {
            public int CipherSuite;
            public string BulkCipherAlgorithmName;
            public int BlockSize;
            public int HashSize;
            public int BulkKeySize;
            public int BulkIVSize;
            public CipherMode cipherMode;
            public KeyExchangeAlgorithm keyExchangeAlgorithm;
        }

        public class TLSCipherSuite
        {
            public TLSCipherParameters tlsparams;
            TLSCipherImplementation implementation;
            public byte[] clWriteKey;
            public byte[] clWriteMAC;

            public TLSCipherSuite(TLSCipherImplementation impl, TLSCipherParameters _tlsparams)
            {
                this.implementation = impl;
                this.tlsparams = _tlsparams;
            }

            public SymmetricAlgorithm GetBulker()
            {
                SymmetricAlgorithm bulker = implementation.GetBulker();
                bulker.Mode = tlsparams.cipherMode;
                bulker.Padding = PaddingMode.None;
                return bulker;
            }

            public HashAlgorithm GetHasher() => implementation.GetHasher();
            public HMAC CreateHMAC(byte[] key) => implementation.CreateHMAC(key);
            public bool VerifyHash(byte[] hash, byte[] sig, X509Cert cert) => implementation.VerifyHash(hash, sig, cert);
            public TLSEncryptionProvider InitializeEncryption(KeyDerivation.KeyExpansionResult keyring)
            {
                clWriteKey = keyring.clientWriteKey;
                clWriteMAC = keyring.clientWriteMac;

                SymmetricAlgorithm localBulker = GetBulker();
                localBulker.Key = keyring.clientWriteKey;

                SymmetricAlgorithm remoteBulker = GetBulker();
                remoteBulker.Key = keyring.serverWriteKey;
                KeyedHashAlgorithm localHasher = new HMACSHA1(keyring.clientWriteMac);
                KeyedHashAlgorithm remoteHasher = new HMACSHA1(keyring.serverWriteMac);
                return new TLSEncryptionProvider
                {
                    tcs = this,
                    AuthenticationTagSize = 0,
                    bulkAlgorithmType = BulkAlgorithmType.Block,
                    BlockSize = tlsparams.BlockSize,
                    IVSize = tlsparams.BulkIVSize,
                    HashSize = tlsparams.HashSize,
                    Encryptor = localBulker.CreateEncryptor(),
                    Decryptor = remoteBulker.CreateDecryptor(),
                    LocalHasher = localHasher,
                    RemoteHasher = remoteHasher
                };
            }
        }



        private static bool VerifyHashEDCSA(byte[] hash, byte[] sig, X509Cert publicCert)
        {
            using (ECDsa ecd = ECDsaCertificateExtensions.GetECDsaPublicKey(new X509Certificate2(publicCert.sourceData)))
            {
                bool valid = ecd.VerifyHash(hash, sig, DSASignatureFormat.Rfc3279DerSequence);
                return valid;
            }
        }

        private static bool VerifyHashRSA(byte[] hash, byte[] sig, X509Cert publicCert)
        {
            RSAPublicKey rpk = publicCert.GetRSAPublicKey();
            byte[] decrypted = rpk.DecryptSignature(sig);
            byte[] actualhash;

            if (decrypted.Length == 36)
            {
                actualhash = decrypted;
            }
            else
            {
                actualhash = Asn1Tools.ParseHash(decrypted);
            }
            if (Asn1Tools.HashesEqual(hash, actualhash))
            {
                return true;
            }
            return false;
        }
        private static HashAlgorithm CreateSha1()
        {
            return SHA1.Create();
        }
        private static HashAlgorithm CreateSha256()
        {
            return SHA256.Create();
        }
        private static SymmetricAlgorithm CreateAes()
        {
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider
            {
                BlockSize = 128,
                KeySize = 128,
                Padding = PaddingMode.None,
                Mode = CipherMode.CBC,

            };
            return aesProvider;
        }
        private static HMAC CreateSha1Hmac(byte[] key)
        {
            return new HMACSHA1(key);
        }
        private static HMAC CreateSha256Hmac(byte[] key)
        {
            return new HMACSHA256(key);
        }

        public static ushort[] GetSupportedCipherSuites()
        {
            CipherSuiteValue[] cipherSuiteValues = SupportedSuites.Keys.ToList().ToArray();
            List<ushort> usv = new List<ushort>();
            foreach (var cipherSuiteValue in cipherSuiteValues) usv.Add((ushort)cipherSuiteValue);
            return usv.ToArray();
        }

        public static TLSCipherSuite InitializeCipherSuite(ushort ciphersuitevalue)
        {
            CipherSuiteValue key = (CipherSuiteValue)ciphersuitevalue;
            return SupportedSuites[key].Invoke();
        }

        public static Dictionary<CipherSuiteValue, Func<TLSCipherSuite>> SupportedSuites = new Dictionary<CipherSuiteValue, Func<TLSCipherSuite>>
        {
            //TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            {
                CipherSuiteValue.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                ()=>{
                    return
                    new TLSCipherSuite(
                        new TLSCipherImplementation(CreateAes,CreateSha1,CreateSha256Hmac,VerifyHashRSA),
                        new TLSCipherParameters()
                        {
                            BlockSize = 16,
                            BulkCipherAlgorithmName = "AES",
                            BulkIVSize = 16,
                            BulkKeySize = 16,
                            HashSize = 20,
                            cipherMode = CipherMode.CBC,
                            CipherSuite = (int)CipherSuiteValue.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                            keyExchangeAlgorithm = KeyExchangeAlgorithm.ECDHE_RSA
                        }
                    );
                }
            },
            //TLS_RSA_WITH_AES_128_CBC_SHA
            {
                CipherSuiteValue.TLS_RSA_WITH_AES_128_CBC_SHA,
                ()=>{
                    return
                    new TLSCipherSuite(
                        new TLSCipherImplementation(CreateAes,CreateSha1,CreateSha256Hmac,VerifyHashRSA),
                        new TLSCipherParameters()
                        {
                            BlockSize = 16,
                            BulkCipherAlgorithmName = "AES",
                            BulkIVSize = 16,
                            BulkKeySize = 16,
                            HashSize = 20,
                            cipherMode = CipherMode.CBC,
                            CipherSuite = (int)CipherSuiteValue.TLS_RSA_WITH_AES_128_CBC_SHA,
                            keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA
                        }
                    );
                }
            },
            {
                CipherSuiteValue.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                ()=>{
                    return
                    new TLSCipherSuite(
                        new TLSCipherImplementation(CreateAes,CreateSha1,CreateSha256Hmac,VerifyHashEDCSA),
                        new TLSCipherParameters()
                        {
                            BlockSize = 16,
                            BulkCipherAlgorithmName = "AES",
                            BulkIVSize = 16,
                            BulkKeySize = 16,
                            HashSize = 20,
                            cipherMode = CipherMode.CBC,
                            CipherSuite = (int)CipherSuiteValue.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                            keyExchangeAlgorithm = KeyExchangeAlgorithm.ECDHE_ECDSA
                        }
                    );
                }
            }

        };

        public enum CipherSuiteValue
        {
            TLS_RSA_WITH_AES_128_CBC_SHA = 47,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 49171,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 49161
        }
    }
}
