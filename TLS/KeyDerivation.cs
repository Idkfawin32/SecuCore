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

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;
using SecuCore.Curves;
using SecuCore.TLS;
using System;
using System.Linq;

namespace SecuCore
{
    public class KeyDerivation
    {
        public struct KeyExpansionResult
        {
            public byte[] clientWriteMac;
            public byte[] serverWriteMac;
            public byte[] clientWriteKey;
            public byte[] serverWriteKey;
            public byte[] clientWriteIV;
            public byte[] serverWriteIV;
        }

        private static byte[] Kexpand11(int minbytes, byte[] seed, HMACMD5 hmacmd5, HMACSHA1 hmacsha1)
        {
            byte[] md5bytes = Kexp11(minbytes, seed, hmacmd5);
            byte[] sha1bytes = Kexp11(minbytes, seed, hmacsha1);
            byte[] output = new byte[minbytes];
            for (int i = 0; i < output.Length; i++)
            {
                output[i] = (byte)(md5bytes[i] ^ sha1bytes[i]);
            }
            return output;
        }
        private static byte[] Kexp11(int minbytes, byte[] seed, HMAC hm)
        {

            byte[] output = new byte[minbytes];
            byte[] a = seed;
            int hs = hm.HashSize / 8;

            byte[] b1 = new byte[hs];
            byte[] b2 = new byte[hs];

            int pos = 0;
            while (pos < output.Length)
            {
                b1 = hm.ComputeHash(a, 0, a.Length);
                a = b1;
                hm.Initialize();
                hm.TransformBlock(b1, 0, b1.Length, b1, 0);
                hm.TransformFinalBlock(seed, 0, seed.Length);
                b2 = hm.Hash;
                int copysize = hs;
                if (copysize > (output.Length - pos))
                    copysize = (output.Length - pos);
                Buffer.BlockCopy(b2, 0, output, pos, copysize);
                pos += hs;
            }
            return output;
        }

        public static byte[] GenerateVerifyData11(byte[] label, byte[] hash, byte[] master)
        {
            int secretLength = (master.Length + 1) / 2;
            byte[] md5Secret = new byte[secretLength];
            Buffer.BlockCopy(master, 0, md5Secret, 0, secretLength);
            byte[] sha1Secret = new byte[secretLength];
            Buffer.BlockCopy(master, master.Length - secretLength, sha1Secret, 0, secretLength);

            using (HMACMD5 hmacmd5 = new HMACMD5(md5Secret))
            {
                using (HMACSHA1 hmacsha1 = new HMACSHA1(sha1Secret))
                {
                    byte[] seed = label.Concat(hash).ToArray();

                    byte[] verifyMaterial = Kexpand11(12, seed, hmacmd5, hmacsha1);

                    return Tools.SubArray(verifyMaterial, 0, 12);
                }
            }
        }

        public static byte[] GenerateMasterSecret11(byte[] sharedsecret, byte[] clientRandom, byte[] serverRandom)
        {
            byte[] label = TLSData.label_mastersecret;
            byte[] seed = clientRandom.Concat(serverRandom).ToArray();
            seed = label.Concat(seed).ToArray();

            // split in half and give each half to a hasher
            int secretLength = (sharedsecret.Length + 1) / 2;
            byte[] md5Secret = new byte[secretLength];
            Buffer.BlockCopy(sharedsecret, 0, md5Secret, 0, secretLength);

            byte[] sha1Secret = new byte[secretLength];
            Buffer.BlockCopy(sharedsecret, sharedsecret.Length - secretLength, sha1Secret, 0, secretLength);

            using (HMACMD5 hmacmd5 = new HMACMD5(md5Secret))
            {
                using (HMACSHA1 hmacsha1 = new HMACSHA1(sha1Secret))
                {
                    byte[] master = Kexpand11(48, seed, hmacmd5, hmacsha1);
                    return master;
                }
            }
        }

        public static KeyExpansionResult PerformKeyExpansionTLS11(byte[] master, byte[] clientRandom, byte[] serverRandom, int MacSize, int KeySize, int IVSize)
        {
            byte[] label = TLSData.label_keyexpansion;
            byte[] seed = label.Concat(serverRandom).Concat(clientRandom).ToArray();

            // split in half and give each half to a hasher
            int secretLength = (master.Length + 1) / 2;
            byte[] md5Secret = new byte[secretLength];
            Buffer.BlockCopy(master, 0, md5Secret, 0, secretLength);
            byte[] sha1Secret = new byte[secretLength];
            Buffer.BlockCopy(master, secretLength, sha1Secret, 0, secretLength);

            int requiredMaterial = (MacSize * 2) + (KeySize * 2) + (IVSize * 2);
            byte[] keyMaterial = null;
            using (HMACMD5 hmacmd5 = new HMACMD5(md5Secret))
            {
                using (HMACSHA1 hmacsha1 = new HMACSHA1(sha1Secret))
                {
                    keyMaterial = Kexpand11(requiredMaterial, seed, hmacmd5, hmacsha1);

                    int pos = 0;
                    byte[] cliwritemackey = new byte[MacSize];
                    byte[] serwritemackey = new byte[MacSize];
                    byte[] cliwritekey = new byte[KeySize];
                    byte[] serwritekey = new byte[KeySize];
                    byte[] cliwriteiv = new byte[IVSize];
                    byte[] serwriteiv = new byte[IVSize];
                    Buffer.BlockCopy(keyMaterial, pos, cliwritemackey, 0, MacSize);
                    pos += MacSize;
                    Buffer.BlockCopy(keyMaterial, pos, serwritemackey, 0, MacSize);
                    pos += MacSize;
                    Buffer.BlockCopy(keyMaterial, pos, cliwritekey, 0, KeySize);
                    pos += KeySize;
                    Buffer.BlockCopy(keyMaterial, pos, serwritekey, 0, KeySize);
                    pos += KeySize;
                    Buffer.BlockCopy(keyMaterial, pos, cliwriteiv, 0, IVSize);
                    pos += IVSize;
                    Buffer.BlockCopy(keyMaterial, pos, serwriteiv, 0, IVSize);
                    pos += IVSize;
                    return new KeyExpansionResult() { clientWriteMac = cliwritemackey, serverWriteMac = serwritemackey, clientWriteKey = cliwritekey, serverWriteKey = serwritekey, clientWriteIV = cliwriteiv, serverWriteIV = serwriteiv };
                }
            }
        }
        public static KeyExpansionResult PerformKeyExpansion(byte[] master, byte[] clientRandom, byte[] serverRandom, int MacSize, int KeySize, int IVSize, HMAC hm)
        {
            byte[] label = TLSData.label_keyexpansion;
            byte[] seed = label.Concat(serverRandom).Concat(clientRandom).ToArray();
            int requiredMaterial = (MacSize * 2) + (KeySize * 2) + (IVSize * 2);
            byte[] keyMaterial = Kexpand(requiredMaterial, seed, hm);
            byte[] cliwritemackey = new byte[MacSize];
            byte[] serwritemackey = new byte[MacSize];
            byte[] cliwritekey = new byte[KeySize];
            byte[] serwritekey = new byte[KeySize];
            byte[] cliwriteiv = new byte[IVSize];
            byte[] serwriteiv = new byte[IVSize];

            int pos = 0;
            Buffer.BlockCopy(keyMaterial, pos, cliwritemackey, 0, MacSize);
            pos += MacSize;
            Buffer.BlockCopy(keyMaterial, pos, serwritemackey, 0, MacSize);
            pos += MacSize;
            Buffer.BlockCopy(keyMaterial, pos, cliwritekey, 0, KeySize);
            pos += KeySize;
            Buffer.BlockCopy(keyMaterial, pos, serwritekey, 0, KeySize);
            pos += KeySize;
            Buffer.BlockCopy(keyMaterial, pos, cliwriteiv, 0, IVSize);
            pos += IVSize;
            Buffer.BlockCopy(keyMaterial, pos, serwriteiv, 0, IVSize);
            pos += IVSize;
            return new KeyExpansionResult() { clientWriteMac = cliwritemackey, serverWriteMac = serwritemackey, clientWriteKey = cliwritekey, serverWriteKey = serwritekey, clientWriteIV = cliwriteiv, serverWriteIV = serwriteiv };
        }

        public static byte[] GenerateVerifyData(byte[] label, byte[] hash, HMAC hm)
        {
            byte[] seed = label.Concat(hash).ToArray();
            byte[] verifyMaterial = Kexpand(12, seed, hm);
            return Tools.SubArray(verifyMaterial, 0, 12);
        }

        public static byte[] GenerateMasterSecret(bool extended, byte[] clientRandom, byte[] serverRandom, HMAC hm)
        {
            byte[] label = (extended ? TLSData.label_extmastersecret : TLSData.label_mastersecret);
            byte[] seed = clientRandom.Concat(serverRandom).ToArray();
            seed = label.Concat(seed).ToArray();
            byte[] master = Kexpand(48, seed, hm);
            return master;
        }

        private static byte[] Kexpand(int minbytes, byte[] seed, HMAC hm)
        {
            byte[] outputbytes = new byte[minbytes];
            int pos = 0;
            byte[] k = (byte[])seed.Clone();
            while (pos < minbytes)
            {
                k = hm.ComputeHash(k);
                byte[] p = hm.ComputeHash(k.Concat(seed).ToArray());
                int copysize = p.Length;
                if (pos + copysize >= (minbytes))
                    copysize = minbytes - pos;
                Buffer.BlockCopy(p, 0, outputbytes, pos, copysize);
                pos += copysize;
            }
            return outputbytes;
        }

        private static byte[] BigIntegerToByteArray(BigInteger input, int length)
        {
            byte[] result = new byte[length];
            byte[] inputBytes = input.ToByteArray();
            Array.Reverse(inputBytes);
            Buffer.BlockCopy(inputBytes, 0, result, 0, System.Math.Min(inputBytes.Length, result.Length));
            Array.Reverse(result);
            return result;
        }

        public static byte[] CalculateSharedSecretx25519(byte[] clientPrivate, byte[] serverPublic)
        {
            byte[] clipri = Curve25519.ClampPrivateKey(clientPrivate);
            byte[] serpub;
            if (serverPublic.Length == 32)
            {
                serpub = serverPublic;
            }
            else
            {
                serpub = new byte[serverPublic.Length - 1];
                Buffer.BlockCopy(serverPublic, 1, serpub, 0, serverPublic.Length - 1);
            }
            byte[] shared = Curve25519.GetSharedSecret(clipri, serpub);
            return shared;
        }
        public static byte[] CalculateSharedSecret(byte[] clientPrivate, byte[] serverPublic, string curveName)
        {
            if (curveName == "x25519")
                return CalculateSharedSecretx25519(clientPrivate, serverPublic);

            byte[] sqx = new byte[serverPublic.Length / 2];
            byte[] sqy = new byte[sqx.Length];
            Buffer.BlockCopy(serverPublic, 1, sqx, 0, sqx.Length);
            Buffer.BlockCopy(serverPublic, 1 + sqx.Length, sqy, 0, sqy.Length);

            X9ECParameters ecParams = SecNamedCurves.GetByName(curveName);
            ECDomainParameters domainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());

            Org.BouncyCastle.Math.EC.ECPoint serverPoint = ecParams.Curve.DecodePoint(serverPublic);

            BigInteger privateBI = new BigInteger(1, clientPrivate, 1, 32);

            ECPublicKeyParameters theirPublicKey = new ECPublicKeyParameters(serverPoint, domainParams);
            ECPrivateKeyParameters myPrivateKey = new ECPrivateKeyParameters(privateBI, domainParams);

            // Calculate the actual agreement
            ECDHBasicAgreement agreement = new ECDHBasicAgreement();
            agreement.Init(myPrivateKey);

            BigInteger agreementBI = agreement.CalculateAgreement(theirPublicKey);
            byte[] sharedSecret = BigIntegerToByteArray(agreementBI, 32);
            return sharedSecret;
        }
    }
}
