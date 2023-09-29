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

using SecuCore.Proxies;
using System.Text;
using SecuCore.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO.Compression;
using System.IO;

namespace SecuCore.Clients
{
    class HTTPCookie
    {
        public string Name;
        public string Value;
        public string Domain;
        public string Path;
        public DateTime Expires;
    }
    public class HTTPClient
    {
        public string UA = "SecuCore/1.0 HTTPClient";
        public string LastHeaders { get { return _lastHeaders; } }
        public string LastRedirect { get { return _lastHeaders; } }

        private Proxy _proxy;
        private TCPSocket _tcpSocket;
        private TCPNetworkStream _tcpns;
        private SecuredTCPStream _stcps;
        private string _lastErrorText = "";
        private string _lastHeaders = "";
        private string _lastRedirect = "";
        private List<HTTPCookie> _cookies;
        private bool _connectedWithTLS = false;
        public string LastError { get { return _lastErrorText; } }

        public int ConnectTimeout
        {
            get;
            set;
        } = 10000;
        public int WriteTimeout
        {
            get;
            set;
        } = 10000;
        public int ReadTimeout
        {
            get;
            set;
        } = 10000;

        private int _wsrbs = 8192;
        private int _wssbs = 8192;
        public int WsaSockRecieveBufSize
        {
            get
            {
                return _wsrbs;
            }
            set
            {
                if (_wsrbs != value)
                {
                    _wsrbs = value;
                    if (_tcpSocket != null)
                    {
                        _tcpSocket.SetWSASockBufferSizes(_wsrbs, _wssbs);
                    }
                }
            }
        }
        public int WsaSockSendBufSize
        {
            get
            {
                return _wssbs;
            }
            set
            {
                if (_wssbs != value)
                {
                    _wssbs = value;
                    _tcpSocket?.SetWSASockBufferSizes(_wsrbs, _wssbs);
                }
            }
        }

        public TLS.TLSRecordLayer.ValidateServerCertificate validationCallback;
        public TLS.TLSRecordLayer.ClientCertificateRequest certificateRequestCallback;

        public HTTPClient(string proxy = "", ProxyProtocol proxyProtocol = ProxyProtocol.HTTP)
        {
            _cookies = new List<HTTPCookie>();
            if (!string.IsNullOrEmpty(proxy)) this._proxy = new Proxy(proxy, proxyProtocol);
        }
        public void SetCallbacks(TLS.TLSRecordLayer.ValidateServerCertificate valCallback, TLS.TLSRecordLayer.ClientCertificateRequest certReqCallback)
        {
            this.validationCallback = valCallback;
            this.certificateRequestCallback = certReqCallback;
        }

        public static string UrlEncode(string value)
        {
            StringBuilder result = new StringBuilder();
            foreach (char symbol in value)
            {
                if ((symbol >= '0' && symbol <= '9') ||
                    (symbol >= 'a' && symbol <= 'z') ||
                    (symbol >= 'A' && symbol <= 'Z') ||
                    symbol == '-' || symbol == '_')
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + string.Format("{0:X2}", (int)symbol));
                }
            }
            return result.ToString();
        }

        public string BuildGETRequest(string host, string path)
        {
            List<(string Name, string Value)> headers = new List<(string Name, string Value)>
            {
                ("Host", host),
                ("Connection", "keep-alive"),
                ("User-Agent", UA),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Encoding", "gzip")
            };

            StringBuilder sb = new StringBuilder();
            sb.Append(string.Format("GET {0} HTTP/1.1\r\n", path));

            StringBuilder csb = new StringBuilder();
            foreach (HTTPCookie hc in _cookies)
            {
                if (hc.Domain.EndsWith(host))
                {
                    if (path.StartsWith(hc.Path))
                    {
                        csb.Append(String.Format("{0}={1}", hc.Name, hc.Value));
                        if (hc != _cookies.Last()) csb.Append("; ");
                    }
                }
            }
            if (csb.Length > 0) headers.Add(("Cookie", csb.ToString()));
            foreach ((string Name, string Value) in headers)
            {
                sb.Append(string.Format("{0}: {1}\r\n", Name, Value));
            }
            sb.Append("\r\n");
            return sb.ToString();
        }

        public string BuildPOSTRequest(string host, string path, List<(string,string)> postvals)
        {

            StringBuilder psb = new StringBuilder();
            foreach((string,string) nv in postvals)
            {
                psb.Append(String.Format("{0}={1}", UrlEncode(nv.Item1), UrlEncode(nv.Item2)));
                if (nv != postvals.Last()) psb.Append("&");
            }
            string urlencoded_postdata = psb.ToString();

            List<(string, string)> headers = new List<(string, string)>
            {
                ("Host", host),
                ("Connection", "keep-alive"),
                ("User-Agent", UA),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Length", urlencoded_postdata.Length.ToString()),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Encoding", "gzip")
            };

            StringBuilder sb = new StringBuilder();
            sb.Append(string.Format("POST {0} HTTP/1.1\r\n", path));

            StringBuilder csb = new StringBuilder();
            foreach (HTTPCookie hc in _cookies)
            {
                if (hc.Domain.EndsWith(host))
                {
                    if (path.StartsWith(hc.Path))
                    {
                        csb.Append(String.Format("{0}={1}", hc.Name, hc.Value));
                        if (hc != _cookies.Last()) csb.Append("; ");
                    }
                }
            }
            if (csb.Length > 0) headers.Add(("Cookie", csb.ToString()));
            foreach ((string,string) hv in headers)
            {
                sb.Append(string.Format("{0}: {1}\r\n", hv.Item1, hv.Item2));
            }
            sb.Append("\r\n");
            sb.Append(urlencoded_postdata);
            return sb.ToString();
        }

        private void ParseCookies()
        {
            //parse cookies
            MatchCollection cookmc = Regex.Matches(_lastHeaders, @"[Ss]et\-[Cc]ookie:\ ?([^\r\n]+)");
            if (cookmc.Count > 0)
            {
                foreach (Match cm in cookmc)
                {
                    string cookievalues = cm.Groups[1].Value;
                    string[] cookiepairs = cookievalues.Split(';');
                    HTTPCookie httpc = new HTTPCookie();
                    httpc.Expires = DateTime.Now.AddYears(1);
                    bool cookievalid = true;
                    foreach (string cookpair in cookiepairs)
                    {
                        string trimmed = cookpair.Trim();
                        if (trimmed.Length > 0)
                        {
                            if (cookpair == cookiepairs.First())
                            {
                                //name and value
                                if (trimmed.Contains("="))
                                {
                                    httpc.Name = trimmed.Substring(0, trimmed.IndexOf("="));
                                    httpc.Value = trimmed.Substring(trimmed.IndexOf("=") + 1);
                                }
                                else
                                {
                                    cookievalid = false;
                                    break;
                                }
                            }
                            else
                            {
                                string trimmedtl = trimmed.ToLower();
                                if (trimmed.Contains("="))
                                {
                                    if (trimmedtl.StartsWith("domain="))
                                    {
                                        httpc.Domain = trimmed.Substring(trimmed.IndexOf("=") + 1);
                                    }
                                    else if (trimmedtl.StartsWith("expires="))
                                    {
                                        DateTime.TryParse(trimmed.Substring(trimmed.IndexOf("=") + 1), out httpc.Expires);
                                    }
                                    else if (trimmedtl.StartsWith("path="))
                                    {
                                        httpc.Path = trimmed.Substring(trimmed.IndexOf("=") + 1);
                                    }
                                }
                            }
                        }
                    }
                    if (cookievalid)
                    {
                        bool found = false;
                        foreach (HTTPCookie cookie in _cookies)
                        {
                            if (cookie.Name == httpc.Name && cookie.Domain == httpc.Domain)
                            {
                                //replace the value
                                cookie.Value = httpc.Value;
                                cookie.Path = httpc.Path;
                                cookie.Expires = httpc.Expires;
                                found = true;
                                break;
                            }
                        }
                        if (!found) _cookies.Add(httpc);
                    }
                }
            }
        }

        public Task<string> GetAsync(string url, string referer)
        {
            return RequestAsync(url, referer, false, null);
        }
        public Task<string> PostAsync(string url, string referer, List<(string, string)> postvals)
        {
            return RequestAsync(url, referer, true, postvals);
        }
        public async Task<string> RequestAsync(string url, string referer, bool post, List<(string, string)> postvals)
        {
            _lastRedirect = "";
            //parse destination url
            try
            {
                Match m = Regex.Match(url, @"(https?)\:\/\/([^\:\/\r\n]+)(\/[^\r\n\ ]+)?");
                if(m.Success)
                {
                    string protocol = m.Groups[1].Value;
                    string host = m.Groups[2].Value;
                    string path = m.Groups[3].Value;
                    if(string.IsNullOrEmpty(path)) path = "/";

                    int destprt = (protocol == "https" ? 443 : 80);
                    if(!await ConnectAsync(host, destprt).ConfigureAwait(false))
                    {
                        _lastErrorText = "Failed to connect"; 
                        return "";
                    }
                    string request;
                    if(post)
                    {
                        request = BuildPOSTRequest(host, path, postvals);
                    }
                    else
                    {
                        request = BuildGETRequest(host, path);
                    }
                    

                    INetStream ins = (_connectedWithTLS ? _stcps : _tcpns);
                    byte[] requestdata = System.Text.Encoding.UTF8.GetBytes(request);
                    await ins.WriteAsync(requestdata, 0, requestdata.Length).ConfigureAwait(false);

                    _lastHeaders = System.Text.Encoding.UTF8.GetString(await ins.ReadUntilCRLFCRLF().ConfigureAwait(false));
                    int contentLength = 0;
                    Match clm = Regex.Match(_lastHeaders, @"[Cc]ontent-[Ll]ength\: (\d+)");
                    if(clm.Success)
                    {
                        string clenStr = clm.Groups[1].Value;
                        int.TryParse(clenStr, out contentLength);
                    }

                    //check for redirect
                    Match rlm = Regex.Match(_lastHeaders, @"[Ll]ocation:\ ?([^\r\n]+)");
                    if(rlm.Success) _lastRedirect = rlm.Groups[1].Value;
                    if (_lastRedirect == url) _lastRedirect = null;

                    //parse cookies
                    ParseCookies();
                    bool chunked = _lastHeaders.ToLower().Contains("transfer-encoding: chunked");
                    bool gzip = _lastHeaders.ToLower().Contains("content-encoding: gzip");

                    //get response body if any
                    string content = null;
                    if (contentLength >= 0)
                    {
                        byte[] rbuf = new byte[contentLength];
                        int rlen = await ins.ReadAsync(rbuf, 0, contentLength).ConfigureAwait(false);
                        if (rlen > 0)
                        {
                            byte[] responseData = new byte[rlen];
                            Buffer.BlockCopy(rbuf, 0, responseData, 0, rlen);
                            if (gzip)
                            {
                                byte[] decompressed = Decompress(responseData);
                                content = Encoding.UTF8.GetString(decompressed, 0, decompressed.Length);
                            }
                            else
                            {
                                content = Encoding.UTF8.GetString(responseData, 0, responseData.Length);
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(_lastRedirect))
                    {
                        if (!_lastRedirect.ToLower().StartsWith("http")) _lastRedirect = protocol + "://" + host + _lastRedirect;
                        return await GetAsync(_lastRedirect, url).ConfigureAwait(false);
                    }
                    else
                    {
                        if (chunked)
                        {
                            using (MemoryStream chunk_ms = new MemoryStream())
                            {
                                string nextchunkhex = System.Text.Encoding.UTF8.GetString(await ins.ReadUntilCRLF().ConfigureAwait(false));
                                if (nextchunkhex.Length < 0) return "";
                                int nextchunki = Convert.ToInt32("0x" + nextchunkhex.Substring(0, nextchunkhex.Length - 2), 16);
                                nextchunki += 2;
                                while (nextchunki > 0)
                                {
                                    byte[] rbuf = new byte[nextchunki];
                                    int cpos = 0;
                                    int remaining = nextchunki;
                                    while (remaining > 0)
                                    {
                                        int bytesread = await ins.ReadAsync(rbuf, cpos, remaining);
                                        if (bytesread <= 0) break;
                                        remaining -= bytesread;
                                        cpos += bytesread;
                                    }
                                    if (cpos <= 0) break;
                                    byte[] chunkdata = new byte[nextchunki - 2];
                                    Buffer.BlockCopy(rbuf, 0, chunkdata, 0, nextchunki - 2);
                                    chunk_ms.Write(chunkdata, 0, chunkdata.Length);
                                    nextchunki = 0;

                                    byte[] nextchunkb = await ins.ReadUntilCRLF().ConfigureAwait(false);
                                    if (nextchunkb != null)
                                    {
                                        nextchunkhex = System.Text.Encoding.UTF8.GetString(nextchunkb, 0, nextchunkb.Length);

                                        string nexthvstr = nextchunkhex.Substring(0, nextchunkhex.Length);
                                        nextchunki = Convert.ToInt32("0x" + nexthvstr.Substring(0, nexthvstr.Length - 2), 16);
                                        if (nextchunki == 0) break;
                                        if (nextchunki > 0) nextchunki += 2;
                                    }
                                }
                                byte[] responseData = chunk_ms.ToArray();
                                if (gzip)
                                {
                                    byte[] decompressed = Decompress(responseData);
                                    return Encoding.UTF8.GetString(decompressed, 0, decompressed.Length);
                                }
                                else
                                {
                                    return Encoding.UTF8.GetString(responseData, 0, responseData.Length);
                                }
                            }
                        }
                        else
                        {
                            return content;
                        }
                    }
                }
            }catch (Exception ex) {
                _lastErrorText = ex.Message;
            }
            finally
            {
                try
                {
                    if(_tcpSocket != null) _tcpSocket.Dispose();
                }
                catch (Exception ex) { }
                _tcpSocket = null;
            }
            return "";
        }

      
        static byte[] Decompress(byte[] gzip)
        {
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memory.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memory.ToArray();
                }
            }
        }

        public async Task<bool> ConnectAsync(string remotehost, int destprt)
        {
            if(_tcpSocket != null)
            {
                if (_tcpSocket.Connected()) _tcpSocket.Dispose();
            }
            if (_tcpSocket == null)
            {
                _tcpSocket = new TCPSocket(remotehost, destprt, this._proxy, this.WsaSockRecieveBufSize, this.WsaSockSendBufSize);
            }
            _tcpSocket.ConnectTimeout = this.ConnectTimeout;
            _tcpSocket.WriteTimeout = this.WriteTimeout;
            _tcpSocket.ReadTimeout = this.ReadTimeout;
            if (!await _tcpSocket.ConnectAsync().ConfigureAwait(false)) return false;
            _tcpns = _tcpSocket.GetStream();

            if (destprt == 443)
            {
                SecuredTCPStream stcps = new SecuredTCPStream(_tcpSocket);
                this._stcps = stcps;
                _connectedWithTLS = false;
                try
                {
                    _connectedWithTLS = await stcps.NegotiateTLSConnection(remotehost, this.validationCallback, this.certificateRequestCallback).ConfigureAwait(false);
                }
                catch (Exception){}
                if (_connectedWithTLS) return true;
            }
            else
            {
                return true;
            }
            return false;
        }

        public async Task Dispose()
        {
            if (_stcps != null)
            {
                try
                {
                    await _stcps.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception) { }
            }
            if (_tcpns != null)
            {
                try
                {
                    _tcpns.Dispose();
                }
                catch (Exception) { }
            }

            if (_tcpSocket != null)
            {
                try
                {
                    _tcpSocket.Dispose();
                }
                catch (Exception) { }
            }
        }
    }
}