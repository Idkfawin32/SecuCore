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
using System.Numerics;

namespace SecuCore.Security
{
    public class RSAPublicKey
    {
        public int keysize;
        public byte[] keydat;
        public byte[] modulusbytes;
        public byte[] exponentbytes;

        public RSAPublicKey(byte[] dat, int offset = 0)
        {
            keydat = dat;
            int dp = offset;
            Asn1Info ai = DerDecoder.GetAsn1Data(dat, ref dp);
            if (ai.type != Asn1Type.SEQUENCE) throw new AsnException("Malformed RSA key");
            ai = DerDecoder.GetAsn1Data(dat, ref dp);
            if (ai.type != Asn1Type.INTEGER) throw new AsnException("Malformed RSA key");
            modulusbytes = new byte[ai.length - 1];
            Buffer.BlockCopy(dat, ai.contentOffset + 1, modulusbytes, 0, ai.length - 1);
          
            keysize = modulusbytes.Length;
            dp += ai.length;
            ai = DerDecoder.GetAsn1Data(dat, ref dp);
            if (ai.type != Asn1Type.INTEGER) throw new AsnException("Malformed RSA key");
            exponentbytes = new byte[ai.length];
            Buffer.BlockCopy(dat, ai.contentOffset, exponentbytes, 0, ai.length);
        }

        public byte[] EncryptData(byte[] data)
        {
            SecRNG sr = new SecRNG();
            BigInteger modulus = new BigInteger(modulusbytes, true, true);
            BigInteger exponent = new BigInteger(exponentbytes, true, true);
            byte[] block = new byte[keysize];
            byte[] brng = new byte[keysize];
            int bp = 0;
            while (bp < keysize)
            {
                sr.GetRandomBytes(brng, 0, brng.Length);
                for(int i = 0; i < brng.Length; i++)
                {
                    if (brng[i] > 2) block[bp++] = brng[i];
                    if (bp >= keysize) break;
                }
            }
            block[0] = 0x00;
            block[1] = 0x02;
            block[block.Length - data.Length - 1] = 0x00;
            Buffer.BlockCopy(data, 0, block, block.Length - data.Length, data.Length);
            BigInteger B = new BigInteger(block, true, true);
            BigInteger D = ModPow(B, exponent, modulus);
            byte[] bigendian = D.ToByteArray(true, true);
            return bigendian;
        }

        public byte[] DecryptSignature(byte[] signature)
        {
            BigInteger modulus = new BigInteger(modulusbytes, true, true);
            BigInteger exponent = new BigInteger(exponentbytes, true, true);
            BigInteger B = new BigInteger(signature, true, true);
            BigInteger D =  ModPow(B, exponent, modulus);
            byte[] bigendian = D.ToByteArray(false, true);
            int start = 0;
            for(int i = 0; i < bigendian.Length; i++)
            {
                if(bigendian[i] == 0)
                {
                    start = i + 1;
                    break;
                }
            }
            byte[] cropped = new byte[bigendian.Length - start];
            Buffer.BlockCopy(bigendian, start, cropped, 0, bigendian.Length - start);
            return cropped;
        }


        private static BigInteger ModPow(BigInteger basenum, BigInteger exponent, BigInteger modulus)
        {
            if (modulus == 1) return 0;
            BigInteger curPow = basenum % modulus;
            BigInteger res = 1;


            while (exponent > 0)
            {
                if ((exponent & 0x01) == 1) res = (res * curPow) % modulus;
                exponent >>= 1;
                curPow = (curPow * curPow) % modulus;
            }
            return res;       
        }
    }
}