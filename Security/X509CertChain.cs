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
    public class X509CertChain
    {
        public List<X509Cert> certs;

        public X509CertChain()
        {
            certs = new List<X509Cert>();
        }

        public void AddLink(X509Cert cert)
        {
            certs.Add(cert);
        }

        public bool Verify()
        {
            if (certs.Count <= 1) return true;

            for(int i = 0; i < certs.Count; i++)
            {
                X509Cert certa = certs[i];
                X509Cert certb = null;
                
                if(i == certs.Count - 1)
                {
                    if (HasTrustedRoot(certa, out certb)) {
                        if(certb == null)
                        {
                            //self signed root was already trusted
                            return true;
                        }
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    certb = certs[i + 1];
                }
                RSAPublicKey rpkb = certb.GetRSAPublicKey();
                byte[] decrypted = rpkb.DecryptSignature(certa.signature);
                byte[] actualhash = Asn1Tools.ParseHash(decrypted);
                if(Asn1Tools.HashesEqual(certa.certificateHash, actualhash))
                {
                    //passed
                }
                else
                {
                    return false;
                }
            }

            return true;
        }


        private bool HasTrustedRoot(X509Cert cert, out X509Cert root)
        {
            root = null;
            string certificateIssuer = cert.issuer.ToString();
            string certificateSubject = cert.subject.ToString();

            if (certificateIssuer != certificateSubject)
            {
                if (!string.IsNullOrEmpty(cert.authorityKeyIdentifier))
                {
                    X509Cert trusted = TrustedCA.GetTrustedCertificate(cert.authorityKeyIdentifier);
                    if (trusted != null)
                    {
                        root = trusted;
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(cert.subjectKeyIdentifier))
                {
                    X509Cert trusted = TrustedCA.GetTrustedCertificate(cert.subjectKeyIdentifier);
                    if (trusted != null)
                    {
                        //we trust this
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
        }
        public static string ToHexString(byte[] input)
        {
            char[] outchars = new char[input.Length * 2];
            int outp = 0;
            for (int i = 0; i < input.Length; i++)
            {
                outchars[outp++] = ToHexChar(input[i] / 16);
                outchars[outp++] = ToHexChar(input[i] % 16);
            }
            return new string(outchars);
        }
        private static char ToHexChar(int input)
        {
            if (input < 0 || input > 15) throw new Exception("Hex conversion error");

            if (input < 10)
            {
                return (char)(48 + input);
            }
            else
            {
                return (char)(65 + (input - 10));
            }
        }

        public void Dispose()
        {

            if(certs is null)
            {
                //do nothing
            }
            else
            {
                certs.Clear();
                certs = null;
            }
        }
    }
}
