import re
import os
import urllib.parse as urllib
import random
import gzip
from io import BytesIO
import zlib

class StringHandler():

    def FilterHeaders(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            if k in headers:
                del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def EncodeContentBody(self, text, encoding):
        if isinstance(text, str):
            text = text.encode('utf-8')
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = BytesIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def DecodeContentBody(self, data, encoding, host, path, resheaders, reqheaders, mhost):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = BytesIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)

        try:
            if isinstance(text, bytes):
                text = text.decode('utf-8')
            host = self.GetHostname(reqheaders, mhost, host)
            fname = self.GetFname(path)
            filename = "%s/%s" %(host, fname)
            if not os.path.isfile(filename):
                open(filename, 'a').close()
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(text)
            return text
        except Exception as e:
            print(e)
            return text

    def GetHostname(self, r, m, h):
        if not r.get('Origin'):
            if r.get('Referer'):
                if re.search(m, r.get('Referer')):
                    if h != m:
                        ndir = "%s/%s" %(m,h)
                        h = ndir
        elif r.get('Origin'):
            if not r.get('Referer'):
                if r.get('Host') in r.get('Origin'):
                    h = "%s/%s" %(r.get('Origin').rsplit('//')[1],h)
                else:
                    h = "%s/%s" %(r.get('Origin').rsplit('//')[1],h)
            else:
                if r.get('Origin') in r.get('Referer'):
                    h = "%s/%s" %(r.get('Origin').rsplit('//')[1],h)
                else:
                    h = "%s/%s/%s" %(r.get('Origin').rsplit('//')[1],r.get('Referer').rsplit('//')[1].rsplit('/')[0],h)
        if not os.path.lexists(h):
            os.makedirs(h, 0o755)
        return h
    
    def GetFname(self, p):       
        if re.search("\&", p):
            fname = p.rsplit('&')[-1]
        elif re.search("%", p):
            fname = urllib.unquote(p)
        else:
            if p.rsplit('/')[-1] != "":
                fname = p.rsplit('/')[-1]
            else:
                fname = "index.html"
                return fname
        arr = ['\\', '/', ':', '*', '?', '"', '<', '>', '|', ';']
        for i in arr:
            fname = fname.replace(i, '')
        fname = self.FnameOffset(fname)
        return fname
    
    def FnameOffset(self, fn):
        if len(fn) > 256:    
            offset = int(random.randint(1,200))
            eoffset = int(offset) + 8
            return fn[offset:eoffset]
        else:
            return fn