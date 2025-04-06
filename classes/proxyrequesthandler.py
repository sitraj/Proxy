from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import os
import time
from sys import platform
from subprocess import PIPE, Popen
import ssl
from _thread import get_ident
import http.client as httplib
from bs4 import BeautifulSoup
import urllib.request as urllib2
import urllib.parse as urlparse
import socket
import importlib.util
import sys
from classes.stringhandler import StringHandler
PluginFolder = "./plugins"
MainModule = "__init__"

def GetPlugins():
    plugins = []
    possibleplugins = os.listdir(PluginFolder)
    for i in possibleplugins:
        location = os.path.join(PluginFolder, i)
        if not os.path.isdir(location) or not MainModule + ".py" in os.listdir(location):
            continue
        spec = importlib.util.spec_from_file_location(MainModule, os.path.join(location, MainModule + ".py"))
        plugins.append({"name": i, "spec": spec})
    return plugins

def LoadPlugin(plugin):
    module = importlib.util.module_from_spec(plugin["spec"])
    plugin["spec"].loader.exec_module(module)
    return module

for i in GetPlugins():
    print("Loading plugin " + i["name"])
    plugin = LoadPlugin(i)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    CAKey = 'ca.key'
    CACert = 'ca.crt'
    CertKey = 'cert.key'
    CertDir = 'certs/'
    timeout = 5
    rbufsize = -1
    wbufsize = 0
    
    lock = threading.Lock()

    if not os.path.isdir(CertDir):
        os.makedirs(CertDir, 0o755)
    
    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
    
    def do_CONNECT(self):
        if os.path.isfile(self.CACert) and os.path.isfile(self.CAKey) and os.path.isfile(self.CertKey) and os.path.isdir(self.CertDir):
            self.ConnectIntercept()
        else:
            sys.exit(0)
            return

    def ConnectIntercept(self):
        hostname = self.path.split(":")[0]
        CertPath = "%s/%s.crt" %(self.CertDir.rstrip('/'),hostname)
        
        with self.lock:
            if not os.path.isfile(CertPath):
                epoch = "%d" %(time.time() * 1000)
                if platform == "win32":
                    p1 = Popen(["C:\\OpenSSL-Win64\\bin\\openssl.exe", "req", "-new", "-key", self.CertKey, "-subj", "/CN=%s" % hostname], stdout=PIPE) 
                    p2 = Popen(["C:\\OpenSSL-Win64\\bin\\openssl.exe", "x509", "-req", "-days", "3650", "-CA", self.CACert, "-CAkey", self.CAKey, "-set_serial", epoch, "-out", CertPath], stdin=p1.stdout, stderr=PIPE)
                    p2.communicate()
                else:                                                                                                                                                                       
                    p1 = Popen(["openssl", "req", "-new", "-key", self.CertKey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                    p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.CACert, "-CAkey", self.CAKey, "-set_serial", epoch, "-out", CertPath], stdin=p1.stdout, stderr=PIPE)
                    p2.communicate()

        self.wfile.write(("%s %d %s\r\n" %(self.protocol_version, 200, 'Connection Established')).encode('utf-8'))
        self.end_headers()
        self.connection = ssl.wrap_socket(self.connection, keyfile=self.CertKey, certfile=CertPath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)
        
        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def do_GET(self):            
        Thread = get_ident()
        req = self

        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        time.sleep(2)
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                rpath = req.path
                req.path = "https://%s%s" %(req.headers['Host'], req.path)
                conn = httplib.HTTPSConnection(req.headers['Host'])
                conn.request("GET", rpath)
                res = conn.getresponse()
                r1 = res.read()
                soup = BeautifulSoup(r1.decode('utf-8', errors='ignore'), "html.parser")
                plugin.FindText(soup, req.headers['Host'])
                plugin.FindXSS(req.path)
            else:
                req.path = "http://%s%s" %(req.headers['Host'], req.path)
                url = urllib2.urlopen(req.path).read()
                soup = BeautifulSoup(url.decode('utf-8', errors='ignore'), "html.parser")
                plugin.FindText(soup, req.headers['Host'])
                plugin.FindXSS(req.path)
        elif req.path[:5] == "http:":
            url = urllib2.urlopen(req.path).read()
            soup = BeautifulSoup(url.decode('utf-8', errors='ignore'), "html.parser")
            plugin.FindText(soup, req.headers['Host'])
            plugin.FindXSS(req.path)
        req_body_modified, ThreadID = plugin.RequestHandler(req, req_body, get_ident())
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))
        
        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', StringHandler().FilterHeaders(req.headers))
        
        try:
            not_required = ['User-Agent', 'Accept-Language', 'charset', 'Date', 'Expires', 'Last-Modified', 'Content-Length', 'q:', ]
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            
            host = req.headers.get('Host', '')
            f = "headers.txt"
            if not req.headers.get('Origin'):                
                if not req.headers.get('Referer'):
                    myhost = conn.host
                elif req.headers.get('Referer'):
                    myhost = req.headers.get('Referer').rsplit('//')[1].rsplit('/')[0]
            elif req.headers.get('Origin'):
                myhost = req.headers.get('Origin').rsplit('//')[1]
                
            with open(f, "a+", encoding='utf-8') as head:
                head.write("\n---------------------------------------------------------------------------------------------------------------\n        #####Request Header#####\n")
                for line in req.headers.headers:
                    count = 0
                    for h in not_required:
                        if h in line:
                            count += 1
                    if count == 0:
                        head.write(line)
                conn.request(self.command, path, req_body, dict(req.headers))
                res = conn.getresponse()
                
                version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
                
                setattr(res, 'headers', res.msg)
                setattr(res, 'response_version', version_table[res.version])
                head.write("\n\n        #####Response Header#####\n")
                for line in res.headers.headers:
                    count = 0
                    for h in not_required:
                        if h in line:
                            count += 1
                    if count == 0:
                        head.write(line)
                if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                    plugin.ResponseHandler(req, req_body, req, '', '', '')
                    setattr(res, 'headers', StringHandler().FilterHeaders(res.headers))
                    self.RelayStreaming(res)
                    with self.lock:
                        self.SaveHandler(req, req_body, res, '')
                    return
                res_body = res.read()
            
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return
        
        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = StringHandler().DecodeContentBody(res_body, content_encoding, conn.host, path, res.headers, req.headers, myhost)
        res_body_modified = plugin.ResponseHandler(req, req_body, res, res_body_plain, get_ident(), ThreadID)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = StringHandler().EncodeContentBody(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', StringHandler().FilterHeaders(res.headers))

        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason)).encode('utf-8'))
        for line in res.headers.headers:
            self.wfile.write(line.encode('utf-8'))
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.SaveHandler(req, req_body, res, res_body_plain)

    def RelayStreaming(self, res):
        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason)).encode('utf-8'))
        for line in res.headers.headers:
            self.wfile.write(line.encode('utf-8'))
        self.end_headers()
        try:
            while True:
                chunk = res.read(16384)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def SaveHandler(self, req, req_body, res, res_body):
        pass
