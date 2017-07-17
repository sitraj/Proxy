from classes.proxyrequesthandler import ProxyRequestHandler
from classes.httpserverclass import HTTPServerClass

def main(HandlerClass = ProxyRequestHandler, ServerClass = HTTPServerClass, protocol="HTTP/1.1"):
    port = 8081
    server_address = ('localhost', port)
    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)
    socaddr = httpd.socket.getsockname()
    print "Serving HTTP proxy on %s:%d..." %(socaddr[0],socaddr[1])
    httpd.serve_forever()

if __name__ == '__main__':
    main()