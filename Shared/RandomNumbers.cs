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

using System.Security.Cryptography;
using System;

namespace SecuCore.Shared
{
    class RandomNumbers
    {
        public static ushort GetNext16()
        {
            byte[] ib = RandomNumberGenerator.GetBytes(2);
            return BitConverter.ToUInt16(ib);
        }
        public static int GetNext(int min, int max)
        {
            byte[] ib = RandomNumberGenerator.GetBytes(4);
            int ival = BitConverter.ToInt32(ib, 0);
            ival = (ival >= 0 ? ival : -ival);
            int ceil = max + 1;
            int diff = ceil - min;
            int rn = ival % diff;
            return min + rn;
        }
    }
}
