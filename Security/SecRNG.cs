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

namespace SecuCore.Security
{
    class SecRNG
    {
        private RStep stepper;
        public SecRNG()
        {
            uint seed = BitConverter.ToUInt32(Guid.NewGuid().ToByteArray());
            stepper = new RStep(seed);
        }

        public void GetRandomBytes(byte[] target, int offset, int length)
        {
            int ceil = offset + length - 1;
            int i = offset;
            while(i <= ceil)
            {
                uint nu = stepper.Next32();
                if (i > ceil) break;
                target[i++] = (byte)((nu >> 24) & 0xff);
                if (i > ceil) break;
                target[i++] = (byte)((nu >> 16) & 0xff);
                if (i > ceil) break;
                target[i++] = (byte)((nu >> 8) & 0xff);
                if (i > ceil) break;
                target[i++] = (byte)((nu) & 0xff);
            }
        }
    }

    public struct RStep
    {
        const uint iY = 842502087, iZ = 3579807591, iW = 273326509;
        uint x;
        uint y;
        uint z;
        uint w;
        uint next;

        public RStep(uint seed)
        {
            x = seed;
            y = iY;
            z = iZ;
            w = iW;
            next = 0;
            Step();
        }

        public void Step()
        {
            uint t = (x ^ (x << 11));
            x = y;
            y = z;
            z = w;
            next = (w = (w ^ (w >> 19)) ^ (t ^ (t >> 8)));
        }
        public uint Next32()
        {
            Step();
            return next;
        }
    }
}
