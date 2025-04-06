from socketserver import ThreadingMixIn
from http.server import HTTPServer
import socket
import sys
import ssl

class HTTPServerClass(ThreadingMixIn, HTTPServer):
#class HTTPServerClass(HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True
    allow_reuse_address = True
    
    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)
