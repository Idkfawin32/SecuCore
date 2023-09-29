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

using System.Threading.Tasks;

namespace SecuCore.Sockets
{
    public interface INetStream
    {
        public Task<bool> WriteAsync(byte[] dat, int offset, int length);
        public Task<int> ReadAsync(byte[] dst, int offset, int length);
        public Task<byte[]> ReadUntilCRLF();
        public Task<byte[]> ReadUntilCRLFCRLF();
    }
}
