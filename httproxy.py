#!/usr/bin/env python3
import sys
import ssl
import socket
import select
import threading

def connect(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect((addr, 443))
    s = ssl.wrap_socket(s)
    return s

def pconnect(addr):
    addr = addr.split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect((addr[0], int(addr[1])))
    return s

def getHeader(req, header):
    ret = b""
    for i in req.split(b"\r\n"):
        if(i.startswith(header.encode()) or i.startswith(header.encode())):
            ret = i.split(b":")[1].strip()
            break
    return ret

def getLength(req):
    return getHeader(req, "Content-Length")

def recv(conn):
    ret = b""
    while(ret[-4:] != b"\r\n\r\n"):
        rcv = conn.recv(1)
        ret += rcv
    if(b"Content-Length:" in ret):
        l = int(getLength(ret).decode())
        while(l):
            rcv = conn.recv(l)
            ret += rcv
            l -= len(rcv)
    return ret

def getHost(req):
    return getHeader(req, "Host")

def handleProxy(addr, req):
    host = getHost(req).decode()
    userAgent = getHeader(req, "User-Agent").decode()
    preq = ("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Connection: keep-alive\r\nUser-Agent: %s\r\n\r\n" % (host, host, userAgent)).encode()
    pconn = pconnect(addr)
    pconn.sendall(preq)
    recv(pconn)
    pconn = ssl.wrap_socket(pconn)
    return pconn


def handle(conn, proxy=""):
    req = recv(conn)
    dest = getHost(req)
    if(not dest):
        print("[!] Missing Host field!")
        return conn.close()
    if(proxy):
        nc = handleProxy(proxy, req)
    else:
        nc = connect(dest)
    print("       Routing request to %s" % dest.decode())
    nc.sendall(req)
    res = recv(nc)
    conn.sendall(res)
    while True:
        try:
            req = recv(conn)
            nc.sendall(req)
            res = recv(nc)
            conn.sendall(res)
        except:
            break
    nc.close()
    conn.close()

def main():
    proxy = ""
    if("-p" in sys.argv):
        opt = sys.argv.index("-p")
        try:
            proxy = sys.argv[opt+1]
        except:
            print("Missing proxy url!")
            print("(./%s -p addr:port {localServerListeningPort})" % sys.argv[0])
            return
        if(len(proxy.split(":")) != 2):
            print("Invalid proxy url!")
            print("(./%s -p addr:port {localServerListeningPort})" % sys.argv[0])
            return
        del sys.argv[opt+1]
        del sys.argv[opt]
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 443
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    s.listen(89)
    s = ssl.wrap_socket(s, certfile="./server.pem", server_side=True)
    print("[*] Serving HTTPS on 0.0.0.0 on port %i" % port)
    while(True):
        try:
            conn, addr = s.accept()
        except ssl.SSLError:
            print("[!] SSL error!")
            continue
        print("[!] Connection received from %s" % addr[0])
        t = threading.Thread(target=handle, args=(conn,proxy))
        t.start()

if(__name__ == "__main__"):
    main()
