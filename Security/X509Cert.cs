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

namespace SecuCore.Security
{
    public class CertificateException : Exception
    {
        public CertificateException(string s = "") : base("Error parsing Certificate: " + s)
        {
        }
    }
    public class X509Cert
    {
        public int version;
        public byte[] sourceData;
        public byte[] serialNumber;
        public string sigOid;
        public string encOid;
        public RDNSequence issuer;
        public RDNSequence subject;
        public DateTime notBefore;
        public DateTime notAfter;
        public byte[] publicKey;
        public string altNames;

        public string subjectKeyIdentifier;
        public string authorityKeyIdentifier;

        public string algorithmIdentifier;
        public byte[] certificateHash;
        public byte[] signature;

        private RSAPublicKey rpk;

        public void Dispose()
        {
            serialNumber = null;
            publicKey = null;
            certificateHash = null;
            signature = null;
            issuer = null;
            subject = null;
            rpk = null;
        }

        public RSAPublicKey GetRSAPublicKey()
        {
            if(rpk == null) rpk = new RSAPublicKey(publicKey, 0);
            return rpk;
        }

        public static X509Cert FromASN(byte[] asnData, int offset)
        {
            X509Cert cert = new X509Cert();
            cert.sourceData = asnData;
            IndexedASNData iad = new IndexedASNData(asnData, offset);
            if (!iad.Lookup(out Asn1Value av, 0, 0, 0)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.INTEGER) throw new AsnException("Malformed asn data");
            cert.version = Asn1Tools.Btoi(asnData, av.offset, av.length);

            if (!iad.Lookup(out av, 0, 0, 1)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.INTEGER) throw new AsnException("Malformed asn data");
            cert.serialNumber = Asn1Tools.Cpy(asnData, av.offset, av.length);

            if (!iad.Lookup(out av, 0, 0, 2, 0)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.OBJECT_IDENTIFIER) throw new AsnException("Malformed asn data");
            cert.sigOid = Asn1Tools.Poid(asnData, av.offset, av.length);

            if (!iad.Lookup(out av, 0, 0, 3)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.SEQUENCE) throw new AsnException("Malformed asn data");
            cert.issuer = new RDNSequence(asnData, av.offset, av.length);

            if (!iad.Lookup(out av, 0, 0, 4, 0)) throw new AsnException("Malformed asn data");
            if(av.asnType == Asn1Type.GeneralizedTime)
            {
                cert.notBefore = Asn1Tools.Generalized(asnData, av.offset);
            }
            else if (av.asnType == Asn1Type.UTCTime)
            {
                cert.notBefore = Asn1Tools.Utc(asnData, av.offset);
            }
            else
            {
                throw new AsnException("Malformed asn data");
            }

            if (!iad.Lookup(out av, 0, 0, 4, 1)) throw new AsnException("Malformed asn data");
            if (av.asnType == Asn1Type.GeneralizedTime)
            {
                cert.notAfter = Asn1Tools.Generalized(asnData, av.offset);
            }
            else if (av.asnType == Asn1Type.UTCTime)
            {
                cert.notAfter = Asn1Tools.Utc(asnData, av.offset);
            }
            else
            {
                throw new AsnException("Malformed asn data");
            }
            if (!iad.Lookup(out av, 0, 0, 5)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.SEQUENCE) throw new AsnException("Malformed asn data");
            cert.subject = new RDNSequence(asnData, av.offset, av.length);

            if (!iad.Lookup(out av, 0, 0, 6, 0, 0)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.OBJECT_IDENTIFIER) throw new AsnException("Malformed asn data");
            cert.encOid = Asn1Tools.Poid(asnData, av.offset, av.length);

            if (!iad.Lookup(out av, 0, 0, 6, 1)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.BIT_STRING) throw new AsnException("Malformed asn data");
            cert.publicKey = Asn1Tools.Cpy(asnData, av.offset + 1, av.length - 1);

            if (!iad.Lookup(out av, 0, 1, 0)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.OBJECT_IDENTIFIER) throw new AsnException("Malformed asn data");
            cert.algorithmIdentifier = Asn1Tools.Poid(asnData, av.offset, av.length);

            if(cert.algorithmIdentifier == "1.2.840.113549.1.1.11")
            {
                if (!iad.Lookup(out Asn1Value certOnly, 0, 0)) throw new AsnException("Malformed asn data");
                ReadOnlySpan<byte> certspan = new ReadOnlySpan<byte>(asnData, certOnly.offset - 4, certOnly.length + 4);
                cert.certificateHash = System.Security.Cryptography.SHA256.HashData(certspan);
            }
            if(cert.algorithmIdentifier == "1.2.840.113549.1.1.12")
            {
                if (!iad.Lookup(out Asn1Value certOnly, 0, 0)) throw new AsnException("Malformed asn data");
                ReadOnlySpan<byte> certspan = new ReadOnlySpan<byte>(asnData, certOnly.offset - 4, certOnly.length + 4);
                cert.certificateHash = System.Security.Cryptography.SHA384.HashData(certspan);
            }
            if(cert.algorithmIdentifier == "1.2.840.113549.1.1.5")
            {
                if (!iad.Lookup(out Asn1Value certOnly, 0, 0)) throw new AsnException("Malformed asn data");
                ReadOnlySpan<byte> certspan = new ReadOnlySpan<byte>(asnData, certOnly.offset - 4, certOnly.length + 4);
                cert.certificateHash = System.Security.Cryptography.SHA1.HashData(certspan);
            }
            if (!iad.Lookup(out av, 0, 2)) throw new AsnException("Malformed asn data");
            if (av.asnType != Asn1Type.BIT_STRING) throw new AsnException("Malformed asn data");
            cert.signature = Asn1Tools.Cpy(asnData, av.offset, av.length);

            //find optional data
            for (int i = 0; i < iad.AsnDataPairs.Count; i++)
            {
                KeyValuePair<Asn1Index, Asn1Value> pair = iad.AsnDataPairs[i];
                if(pair.Value.asnType == Asn1Type.OBJECT_IDENTIFIER)
                {
                    string oidstr = Asn1Tools.Poid(asnData, pair.Value.offset, pair.Value.length);
                    if (oidstr == "2.5.29.17") // subjectaltname
                    {
                        i++;
                        Asn1Value altnamesoct = iad.AsnDataPairs[i].Value;
                        cert.altNames = Asn1Tools.OctStr(asnData, altnamesoct.offset, altnamesoct.length);
                    }
                    else if (oidstr == "2.5.29.14") //subjectKeyIdentifier
                    {
                        i++;
                        Asn1Value subkeyid = iad.AsnDataPairs[i].Value;
                        cert.subjectKeyIdentifier = Asn1Tools.OctStr(asnData, subkeyid.offset, subkeyid.length);
                    }
                    else if (oidstr == "2.5.29.35") //authorityKeyIdentifier
                    {
                        i++;
                        Asn1Value authkeyid = iad.AsnDataPairs[i].Value;
                        cert.authorityKeyIdentifier = Asn1Tools.OctStr(asnData, authkeyid.offset, authkeyid.length);
                    }
                }
            }

            return cert;
        }

    }

}
