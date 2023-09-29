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
using System.Text;

namespace SecuCore.Security
{
    public class AsnException : Exception
    {
        public AsnException(string s = "") : base( "Error parsing ASN: " + s){}
    }

    public enum Asn1Type
    {
        EndOfContent,
        BOOLEAN,
        INTEGER,
        BIT_STRING,
        OCTET_STRING,
        NULL,
        OBJECT_IDENTIFIER,
        ObjectDescriptor,
        EXTERNAL,
        REAL,
        ENUMERATED,
        EMBEDDED_PDV,
        UTF8String,
        RELATIVE_OID,
        TIME,
        RESERVED,
        SEQUENCE,
        SET,
        NumericString,
        PrintableString,
        T61String,
        VideotexString,
        IA5String,
        UTCTime,
        GeneralizedTime,
        GraphicString,
        VisibleString,
        GeneralString,
        UniversalString,
        CHARACTER_STRING,
        BMPString,
        DATE,
        TIME_OF_DAY,
        DATE_TIME,
        DURATION,
        OID_URI,
        RELATIVE_OID_URI
    }

    public enum AsnTagClass
    {
        Universal,
        Application,
        ContextSpecific,
        Private
    }

    public struct Asn1Tag
    {
        public AsnTagClass tagClass;
        public bool constructed;
        public uint tagNumber;
        public Asn1Tag(AsnTagClass atc, bool pc, uint tn)
        {
            tagClass = atc;
            constructed = pc;
            tagNumber = tn;
        }
    }

    public struct Asn1Info
    {
        public Asn1Tag tag;
        public Asn1Type type;
        public int contentOffset;
        public bool lengthIsDefinite;
        public int length;
        public Asn1Info(Asn1Tag atag, int coffset, bool lendefinite, int alen)
        {
            tag = atag;
            type = (Asn1Type)(atag.tagNumber);
            contentOffset = coffset;
            lengthIsDefinite = lendefinite;
            length = alen;
        }
        public byte[] GetData(byte[] parent, ref int pos)
        {
            pos += length;
            byte[] dat = new byte[length];
            Buffer.BlockCopy(parent, (int)contentOffset, dat, 0, (int)length);
            return dat;
        }
    }

    public static class DerDecoder {

        public static Asn1Info GetAsn1Data(byte[] data, ref int offset)
        {
            byte first = data[offset++];
            AsnTagClass atc = (AsnTagClass)((first >> 6) & 0x3);
            bool constructed = (((first >> 5) & 0x1) == 1);
            byte tagbits = ((byte)(first & 0x1f));
            int tagnumber = 0;

            //if constructed is true and tag is 17 (10001) DER doesnt encode the type in additional bytes
            if (tagbits == 17 && constructed == false)
            {
                // long form
                while (true)
                {
                    byte tnb = data[offset++];
                    bool moreBytes = ((tnb >> 7) == 1);
                    int bval = (int)(tnb & 127);
                    tagnumber <<= 7;
                    tagnumber |= bval;
                }
            }
            else
            {
                tagnumber = (int)tagbits;
            }
            Asn1Tag asn1Tag = new Asn1Tag(atc, constructed, (uint)tagnumber);

            //read length octets
            byte lfirst = data[offset++];
            if (lfirst == 0xff) throw new AsnException("First length octet of 0xff is reserved");

            bool definite = true;
            int length = 0;
            bool bit8 = ((lfirst >> 7) == 1);
            int lenbits = (lfirst & 127);
            if (bit8)
            {
                if (lenbits == 0)
                {
                    //indefinite, parser will have to read until 2 EndOfContents octets are found
                    definite = false;
                }
                else
                {
                    //definite, long
                    for (int i = 0; i < lenbits; i++)
                    {
                        byte next = data[offset++];
                        length <<= 8;
                        length |= next;
                    }
                }
            }
            else
            {
                //definite short
                length = lenbits;
            }

            return new Asn1Info(asn1Tag, offset, definite, length);
        }

        public static string ParseOid(byte[] data, int length, ref int offset)
        {
            List<int> idelements = new List<int>();
            int endindex = offset + length;

            byte first = data[offset++];
            idelements.Add(first / 40);
            idelements.Add(first % 40);

            int currentvalue = 0;
            while (offset < endindex)
            {
                byte oide = data[offset++];
                currentvalue <<= 7;
                currentvalue |= (oide & 127);

                if (oide >> 7 == 0)
                {
                    idelements.Add(currentvalue);
                    currentvalue = 0;
                }
            }

            return string.Join('.', idelements);
        }
    }


    public class Asn1Index : IComparable<int[]>, IEquatable<int[]>
    {
        private int[] data;
        public Asn1Index(params int[] columns)
        {
            data = columns;
        }
        public int CompareTo(int[] other)
        {
            int cmp = -1;
            for (int i = 0; i < data.Length; i++)
            {
                if (other.Length <= i) return cmp;

                cmp = data[i].CompareTo(other[i]);
                if (cmp != 0) return cmp;
            }
            return cmp;
        }

        public bool Equals(int[] other)
        {
            if (other.Length != this.data.Length) return false;
            for (int i = 0; i < data.Length; i++)
            {
                if (!data[i].Equals(other[i])) return false;
            }
            return true;
        }
        public override string ToString()
        {
            return string.Join('.', data);
        }
    }

    public class Asn1Value
    {
        public Asn1Type asnType;
        public int offset;
        public int length;
    }

    public class IndexedASNData
    {
        public List<KeyValuePair<Asn1Index, Asn1Value>> AsnDataPairs = new List<KeyValuePair<Asn1Index, Asn1Value>>();

        public IndexedASNData(byte[] input, int offset)
        {
            X509Cert cert = new X509Cert();
            int ofs = offset;
            List<int> indexes = new List<int>();
            Stack<int> endstack = new Stack<int>();

            int curridx = 0;
            int datend = input.Length;
            int currdatend = datend;
            while (ofs < datend)
            {
                Asn1Info ai = DerDecoder.GetAsn1Data(input, ref ofs);
                if (ai.tag.tagClass == AsnTagClass.ContextSpecific)
                {

                    ai = DerDecoder.GetAsn1Data(input, ref ofs);
                }

                if (ai.type == Asn1Type.SEQUENCE || ai.type == Asn1Type.SET)
                {
                    int[] indints = new int[indexes.Count + 1];
                    indexes.CopyTo(indints);
                    indints[indints.Length - 1] = curridx;
                    Asn1Index aind = new Asn1Index(indints);
                    Asn1Value av = new Asn1Value()
                    {
                        asnType = ai.type,
                        length = ai.length,
                        offset = ofs
                    };
                    AsnDataPairs.Add(new KeyValuePair<Asn1Index, Asn1Value>(aind, av));

                    indexes.Add(curridx);
                    endstack.Push(currdatend);
                    curridx = 0;
                    currdatend = ofs + ai.length;
                }
                else
                {
                    int[] indints = new int[indexes.Count + 1];
                    indexes.CopyTo(indints);
                    indints[indints.Length - 1] = curridx;
                    Asn1Index aind = new Asn1Index(indints);
                    Asn1Value av = new Asn1Value()
                    {
                        asnType = ai.type,
                        length = ai.length,
                        offset = ofs
                    };
                    ofs += ai.length;
                    AsnDataPairs.Add(new KeyValuePair<Asn1Index, Asn1Value>(aind, av));   
                    while (ofs >= currdatend && endstack.Count > 0)
                    {
                        currdatend = endstack.Pop();
                        curridx = indexes[indexes.Count - 1];
                        indexes.RemoveAt(indexes.Count - 1);
                    }
                    curridx++;
                }
            }
        }
        public bool Lookup(out Asn1Value av, params int[] Index)
        {
            for(int i = 0; i < AsnDataPairs.Count; i++)
            {
                if(AsnDataPairs[i].Key.Equals(Index))
                {
                    av = AsnDataPairs[i].Value;
                    return true;
                }
            }
            av = null;
            return false;
        }
    }

    public class RDNSequence
    {
        public string country = "";
        public string organization = "";
        public string commonname = "";
        public RDNSequence(byte[] data, int offset, int length)
        {
            Asn1Info ai;
            while (true)
            {
                ai = DerDecoder.GetAsn1Data(data, ref offset);
                if (ai.type != Asn1Type.SET) break;
                ai = DerDecoder.GetAsn1Data(data, ref offset);
                if (ai.type != Asn1Type.SEQUENCE) break;
                ai = DerDecoder.GetAsn1Data(data, ref offset);
                if (ai.type != Asn1Type.OBJECT_IDENTIFIER) break;
                string oid = Asn1Tools.Poid(data, ai.contentOffset, ai.length);
                offset += ai.length;
                ai = DerDecoder.GetAsn1Data(data, ref offset);
                if (ai.type != Asn1Type.PrintableString && ai.type != Asn1Type.UTF8String) break;
                string strval = Asn1Tools.Strc(data, ai.contentOffset, ai.length);
                offset += ai.length;
                if (oid == "2.5.4.6") country = strval;
                else if (oid == "2.5.4.10") organization = strval;
                else if (oid == "2.5.4.3") commonname = strval;
            }
        }
        public override string ToString()
        {
            return organization + " " + commonname + " " + country;
        }
    }

    public class Asn1Tools
    {
        public static int Btoi(byte[] dat, int offset, int length)
        {
            int val = 0;
            for (int i = offset; i < (offset + length); i++)
            {
                val <<= 8;
                val |= dat[i];
            }
            return val;
        }

        public static byte[] Cpy(byte[] dat, int offset, int length)
        {
            byte[] copy = new byte[length];
            Buffer.BlockCopy(dat, offset, copy, 0, length);
            return copy;
        }

        public static string Poid(byte[] data, int offset, int length)
        {
            List<int> idelements = new List<int>();
            int endindex = offset + length;

            byte first = data[offset++];
            idelements.Add(first / 40);
            idelements.Add(first % 40);

            int currentvalue = 0;
            while (offset < endindex)
            {
                byte oide = data[offset++];
                currentvalue <<= 7;
                currentvalue |= (oide & 127);

                if (oide >> 7 == 0)
                {
                    idelements.Add(currentvalue);
                    currentvalue = 0;
                }
            }

            return string.Join('.', idelements);
        }

        public static string Strc(byte[] data, int offset, int length)
        {
            return Encoding.ASCII.GetString(data, offset, length);
        }

        public static DateTime Utc(byte[] data, int offset)
        {
            DateTime dt = new DateTime();
            int dp = offset;
            int yy = ((data[dp + 0] - 48) * 10) + (data[dp + 1] - 48);
            int mm = ((data[dp + 2] - 48) * 10) + (data[dp + 3] - 48);
            int dd = ((data[dp + 4] - 48) * 10) + (data[dp + 5] - 48);
            int thh = ((data[dp + 6] - 48) * 10) + (data[dp + 7] - 48);
            int tmm = ((data[dp + 8] - 48) * 10) + (data[dp + 9] - 48);
            int tss = ((data[dp + 10] - 48) * 10) + (data[dp + 11] - 48);
            int year = 2000 + yy;
            return new DateTime(year, mm, dd, thh, tmm, tss);
        }

        public static DateTime Generalized(byte[] data, int offset)
        {
            return DateTime.Now;
        }

        public static string OctStr(byte[] data, int offset, int length)
        {
            int dp = offset;
            int de = offset + length;

            StringBuilder sb = new StringBuilder();
            while (dp < de)
            {
                Asn1Info ai = DerDecoder.GetAsn1Data(data, ref dp);

                if (ai.type == Asn1Type.SEQUENCE)
                {
                    continue;
                }
                else if(ai.type == Asn1Type.OCTET_STRING || (ai.type == Asn1Type.EndOfContent && ai.tag.tagClass == AsnTagClass.ContextSpecific))
                {
                    byte[] hexdat = new byte[ai.length];
                    Buffer.BlockCopy(data, ai.contentOffset, hexdat, 0, ai.length);

                    sb.Append(ToHexString(hexdat));
                    dp += ai.length;
                }
                else if (ai.type == Asn1Type.INTEGER)
                {
                    string strdat = Encoding.ASCII.GetString(data, ai.contentOffset, ai.length);
                    dp += ai.length;
                    sb.AppendLine(strdat);
                }
                else
                {
                    break;
                }

            }
            return sb.ToString();
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
                return (char)(97 + (input - 10));
            }
        }

        public static bool HashesEqual(byte[] hasha, byte[] hashb)
        {
            if (hasha == null && hashb != null) return false;
            if (hasha != null && hashb == null) return false;
            if (hasha.Length != hashb.Length) return false;
            for (int i = 0; i < hasha.Length; i++)
            {
                if (hasha[i] != hashb[i]) return false;
            }
            return true;
        }

        public static byte[] ParseHash(byte[] decrypted)
        {
            int idx = 0;
            Asn1Info ai = DerDecoder.GetAsn1Data(decrypted, ref idx);
            if (ai.type != Asn1Type.SEQUENCE) return null;
            ai = DerDecoder.GetAsn1Data(decrypted, ref idx);
            if (ai.type != Asn1Type.SEQUENCE) return null;
            ai = DerDecoder.GetAsn1Data(decrypted, ref idx);
            if (ai.type != Asn1Type.OBJECT_IDENTIFIER) return null;
            string oid = Asn1Tools.Poid(decrypted, ai.contentOffset, ai.length);
            idx += ai.length;
            ai = DerDecoder.GetAsn1Data(decrypted, ref idx);
            if (ai.type != Asn1Type.NULL) return null;
            ai = DerDecoder.GetAsn1Data(decrypted, ref idx);
            if (ai.type != Asn1Type.OCTET_STRING) return null;
            byte[] hash = Asn1Tools.Cpy(decrypted, ai.contentOffset, ai.length);
            return hash;
        }
    }
}
