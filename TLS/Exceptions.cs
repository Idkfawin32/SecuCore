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

namespace SecuCore.TLS.Exceptions
{
    public class TLSHandshakeException : Exception
    {
        public TLSHandshakeException(string s = "") : base("Error during tls handshake: " + s)
        {
        }
    }
    public class TLSEncryptionException : Exception
    {
        public TLSEncryptionException(string s = "") : base("Error during tls encryption: " + s)
        {
        }
    }
    public class TLSValidationException : Exception
    {
        public TLSValidationException(string s = "") : base("Error during tls validation: " + s)
        {
        }
    }
    public class TLSProtocolException : Exception
    {
        public TLSProtocolException(string s = "") : base("TLS Protocol was broken: " + s)
        {
        }
    }
    public class TLSRecordException : Exception
    {
        public TLSRecordException(string s = "") : base("TLS Record threw an exception: " + s)
        {
        }
    }
    public class TLSDataException : Exception
    {
        public TLSDataException(string s = "") : base("Error with TLS application data: " + s)
        {
        }
    }
    public class TLSNetworkException : Exception
    {
        public TLSNetworkException(string s = "") : base("Error during network communication: " + s)
        {
        }
    }
}
