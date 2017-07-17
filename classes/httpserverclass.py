from SocketServer import ThreadingMixIn
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import socket
import sys
import ssl

class HTTPServerClass(ThreadingMixIn, HTTPServer):
#class HTTPServerClass(HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True
    
    def handle_error(self, request, client_address):
        cls,e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)
