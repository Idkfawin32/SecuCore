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

namespace SecuCore
{
    public static class Tools
    {
        public static byte[] JoinAll(params byte[][] arrs)
        {
            int totallen = 0;
            for(int i = 0; i < arrs.Length; i++)
            {
                totallen += arrs[i].Length;
            }
            byte[] outputbuf = new byte[totallen];
            int bufp = 0;
            for(int i = 0; i < arrs.Length; i++)
            {
                int len = arrs[i].Length;
                Buffer.BlockCopy(arrs[i], 0, outputbuf, bufp, len);
                bufp += len;
            }
            return outputbuf;
        }

        public static bool ArraysEqual(byte[] a, byte[] b)
        {
            if (a == null && b != null) return false;
            if (a != null && b == null) return false;
            if (a.Length != b.Length) return false;
            for(int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }
        public static byte[] SubArray(byte[] input, int offset, int length)
        {
            byte[] output = new byte[length];
            Buffer.BlockCopy(input, offset, output, 0, length);
            return output;
        }
        public static byte[] Append(byte[] a, byte[] b)
        {
            byte[] output = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, output, 0, a.Length);
            Buffer.BlockCopy(b, 0, output, a.Length, b.Length);
            return output;
        }
            
        public static void PushTo(byte[] outputb, byte[] inputb, ref int offsetint)
        {
            Buffer.BlockCopy(inputb, 0, outputb, offsetint, inputb.Length);
            offsetint += inputb.Length;
        }

    }
}
