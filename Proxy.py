import socket
import sys
import os
import argparse
import re

BUFFER_SIZE = 1000000

parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

try:
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Created socket')
except:
    print('Failed to create socket')
    sys.exit()

try:
    serverSocket.bind((proxyHost, proxyPort))
    print('Port is bound')
except:
    print('Port is already in use')
    sys.exit()

try:
    serverSocket.listen(1)
    print('Listening to socket')
except:
    print('Failed to listen')
    sys.exit()

while True:
    print('Waiting for connection...')
    try:
        clientSocket, addr = serverSocket.accept()
        print('Received a connection')
    except:
        print('Failed to accept connection')
        sys.exit()

    try:
        message_bytes = clientSocket.recv(BUFFER_SIZE)
    except:
        print('Failed to receive data from client')
        clientSocket.close()
        continue

    message = message_bytes.decode('utf-8', errors='ignore')
    print('Received request:')
    print('< ' + message)

    requestParts = message.split()
    if len(requestParts) < 3:
        print("Malformed request.")
        clientSocket.close()
        continue

    method = requestParts[0]
    URI = requestParts[1]
    version = requestParts[2]

    print('Method:		' + method)
    print('URI:		' + URI)
    print('Version:	' + version)
    print('')

    URI = re.sub('^(/?)http(s?)://', '', URI, count=1)
    URI = URI.replace('/..', '')
    resourceParts = URI.split('/', 1)
    hostname = resourceParts[0]
    resource = '/'
    if len(resourceParts) == 2:
        resource = resource + resourceParts[1]

    print('Requested Resource:	' + resource)

    try:
        cacheLocation = './' + hostname + resource
        if cacheLocation.endswith('/'):
            cacheLocation += 'default'

        print('Cache location:		' + cacheLocation)

        fileExists = os.path.isfile(cacheLocation)
        if fileExists:
            with open(cacheLocation, "rb") as cacheFile:
                cacheData = cacheFile.read()
                clientSocket.sendall(cacheData)
                print('Cache hit! Served from cache.')
        else:
            raise FileNotFoundError
    except:
        try:
            originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            address = socket.gethostbyname(hostname)
            originServerSocket.connect((address, 80))
            print('Connected to origin Server')

            originServerRequest = f"GET {resource} HTTP/1.1"
            originServerRequestHeader = f"Host: {hostname}"
            request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'
            originServerSocket.sendall(request.encode())
            print('Request sent to origin server')

            response = b""
            while True:
                chunk = originServerSocket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                response += chunk

            clientSocket.sendall(response)

            cacheDir, file = os.path.split(cacheLocation)
            if not os.path.exists(cacheDir):
                os.makedirs(cacheDir)
            with open(cacheLocation, 'wb') as cacheFile:
                cacheFile.write(response)
                print('Saved to cache.')

            originServerSocket.close()
            clientSocket.shutdown(socket.SHUT_WR)
        except Exception as e:
            print('Origin server request failed:', e)

    try:
        clientSocket.close()
    except:
        print('Failed to close client socket')
