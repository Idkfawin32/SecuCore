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
using System.Security.Cryptography;
using SecuCore.TLS.Exceptions;
using static SecuCore.TLS.CipherSuites;

namespace SecuCore.TLS
{
    class Encryption
    {
        private static byte[] MacHeader(ulong seqNum, byte type, ushort version, int fregmentlen)
        {
            // 8 bytes(sequence) + 5 bytes(header)
            byte[] result = new byte[13];
            result[0] = ((byte)(seqNum >> 56 & 0xff));
            result[1] = ((byte)(seqNum >> 48 & 0xff));
            result[2] = ((byte)(seqNum >> 40 & 0xff));
            result[3] = ((byte)(seqNum >> 32 & 0xff));
            result[4] = ((byte)(seqNum >> 24 & 0xff));
            result[5] = ((byte)(seqNum >> 16 & 0xff));
            result[6] = ((byte)(seqNum >> 8 & 0xff));
            result[7] = ((byte)(seqNum & 0xff));
            result[8] = type;
            result[9] = (byte)((version >> 8) & 0xff);
            result[10] = (byte)(version & 0xff);
            result[11] = (byte)((fregmentlen >> 8) & 0xff);
            result[12] = (byte)(fregmentlen & 0xff);
            return result;
        }

        private const int IVSize = 16;
        public static TLSRecord EncryptRecord(TLSRecord tlso, TLSEncryptionProvider provider, ulong sequence)
        {
            // generate mac
            byte[] fragment = tlso.Data;
            byte[] macheader = MacHeader(sequence, tlso.Type, tlso.Version, fragment.Length);
            provider.LocalHasher.TransformBlock(macheader, 0, macheader.Length, macheader, 0);
            provider.LocalHasher.TransformFinalBlock(fragment, 0, fragment.Length);
            byte[] mac = provider.LocalHasher.Hash;
            ICryptoTransform tfm = provider.Encryptor;
            int blockSize = provider.BlockSize;
            int paddingLength = blockSize - ((fragment.Length + mac.Length) % blockSize);
            byte padb = (byte)(paddingLength - 1);

            byte[] inputbytes = new byte[IVSize + fragment.Length + mac.Length + paddingLength];
            byte[] ivguid = Guid.NewGuid().ToByteArray();
            int inpofs = 0;
            Buffer.BlockCopy(ivguid, 0, inputbytes, 0, ivguid.Length);
            inpofs += ivguid.Length;
            Buffer.BlockCopy(fragment, 0, inputbytes, inpofs, fragment.Length);
            inpofs += fragment.Length;
            Buffer.BlockCopy(mac, 0, inputbytes, inpofs, mac.Length);
            inpofs += mac.Length;
            Array.Fill(inputbytes, padb, inpofs, inputbytes.Length - inpofs);
            int inputblocks = (inputbytes.Length / tfm.InputBlockSize);
            byte[] outputbytes = new byte[inputblocks * tfm.OutputBlockSize];
            if (tfm.CanTransformMultipleBlocks)
            {
                tfm.TransformBlock(inputbytes, 0, inputbytes.Length, outputbytes, 0);
            }
            else
            {
                int outofs = 0;
                for (int i = 0; i < inputblocks; i++)
                    outofs += tfm.TransformBlock(inputbytes, i * tfm.InputBlockSize, tfm.InputBlockSize, outputbytes, outofs);
            }

            fragment = outputbytes;
            tlso.Data = fragment;
            tlso.Length = (ushort)fragment.Length;

            return tlso;
        }

        public static TLSRecord DecryptRecord(TLSRecord tlso, TLSEncryptionProvider provider, ulong sequence)
        {
            byte[] fragment = tlso.Data;

            ICryptoTransform tfm = provider.Decryptor;
            byte[] dec = tfm.TransformFinalBlock(fragment, 0, fragment.Length);
            fragment = dec;

            int startidx = 0;
            int fraglen = fragment.Length;

            // discard iv
            startidx += provider.IVSize;
            fraglen -= provider.IVSize;

            // remove padding if necessary
            if (provider.bulkAlgorithmType == BulkAlgorithmType.Block)
            {
                int padding = fragment[fragment.Length - 1] + 1;
                // Verify the correctness of padding
                if (padding > fragment.Length)
                    throw new TLSEncryptionException("padding removal failed");
                else
                    fraglen -= padding;
            }

            // remove mac
            int macidx = (startidx + fraglen) - provider.HashSize;
            byte[] remotemac = Tools.SubArray(fragment, macidx, provider.HashSize);
            fraglen -= provider.HashSize;
            byte[] macinputheader = MacHeader(sequence, tlso.Type, tlso.Version, fraglen);
            provider.RemoteHasher.Initialize();
            provider.RemoteHasher.TransformBlock(macinputheader, 0, macinputheader.Length, macinputheader, 0);
            provider.RemoteHasher.TransformFinalBlock(fragment, startidx, fraglen);

            byte[] mac = provider.RemoteHasher.Hash;

            if (!Tools.ArraysEqual(mac, remotemac))
                throw new TLSEncryptionException("Mac verification failed on decrypt");
            fragment = Tools.SubArray(fragment, startidx, fraglen);
            tlso.Data = fragment;
            tlso.Length = (ushort)fragment.Length;
            return tlso;
        }
    }
}