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

namespace SecuCore.Shared
{
    public class DataDispatch
    {
        public TaskCompletionSource tcs;
        public byte[] data;
    }
    public class DataRequest 
    {
        public TaskCompletionSource<byte[]> tcs;
        public int length;
    }
    public interface IDataController
    {        
        public void RequestData(DataRequest request);
        public void QueueData(DataDispatch dispatch);
        public void FlushData();
    }
}
