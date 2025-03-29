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
    # ~~~~ INSERT CODE ~~~~
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~
    print('Created socket')
except:
    print('Failed to create socket')
    sys.exit()

try:
    # ~~~~ INSERT CODE ~~~~
    serverSocket.bind((proxyHost, proxyPort))
    serverSocket.listen(1)
    # ~~~~ END CODE INSERT ~~~~
    print('Socket bound and listening')
except:
    print('Port in use or listen failed')
    sys.exit()

while True:
    print('Waiting for connection...')
    try:
        # ~~~~ INSERT CODE ~~~~
        clientSocket, addr = serverSocket.accept()
        # ~~~~ END CODE INSERT ~~~~
        print(f"Received a connection from {addr}")
    except:
        print('Failed to accept connection')
        continue

    try:
        # ~~~~ INSERT CODE ~~~~
        message_bytes = clientSocket.recv(BUFFER_SIZE)
        # ~~~~ END CODE INSERT ~~~~
    except:
        print('Error receiving data')
        clientSocket.close()
        continue

    message = message_bytes.decode('utf-8', errors='ignore')
    print('Received request:')
    print(message)

    requestParts = message.split()
    if len(requestParts) < 3:
        print("Malformed request.")
        clientSocket.close()
        continue

    method, URI, version = requestParts[0], requestParts[1], requestParts[2]

    URI = re.sub('^(/?)http(s?)://', '', URI, count=1)
    URI = URI.replace('/..', '')
    resourceParts = URI.split('/', 1)
    hostname = resourceParts[0]
    resource = '/' + resourceParts[1] if len(resourceParts) == 2 else '/'

    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation += 'default'

    print('Method:		', method)
    print('URI:		', URI)
    print('Version:	', version)
    print('Cache path:	', cacheLocation)

    # ~~~~ INSERT CODE ~~~~
    if os.path.isfile(cacheLocation):
        try:
            with open(cacheLocation, 'rb') as cacheFile:
                clientSocket.sendall(cacheFile.read())
                print("Cache hit. Sent from cache.")
        except:
            print("Error reading from cache")
        clientSocket.close()
        continue
    # ~~~~ END CODE INSERT ~~~~

    try:
        # ~~~~ INSERT CODE ~~~~
        originSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        originAddress = socket.gethostbyname(hostname)
        originSocket.connect((originAddress, 80))
        # ~~~~ END CODE INSERT ~~~~
        print("Connected to origin server")
    except Exception as e:
        print("Connection to origin server failed:", e)
        clientSocket.close()
        continue

    requestLine = f"GET {resource} HTTP/1.1\r\n"
    headers = f"Host: {hostname}\r\n\r\n"
    fullRequest = requestLine + headers

    try:
        # ~~~~ INSERT CODE ~~~~
        originSocket.sendall(fullRequest.encode())
        # ~~~~ END CODE INSERT ~~~~
        print("Request sent to origin server")
    except:
        print("Sending request to origin failed")
        originSocket.close()
        clientSocket.close()
        continue

    try:
        # ~~~~ INSERT CODE ~~~~
        response = b""
        while True:
            chunk = originSocket.recv(BUFFER_SIZE)
            if not chunk:
                break
            response += chunk
        clientSocket.sendall(response)
        # ~~~~ END CODE INSERT ~~~~

        # Step 8A: Detect redirect (301 or 302)
        try:
            headers = response.split(b'\r\n\r\n')[0].decode(errors='ignore')
            status_line = headers.split('\r\n')[0]
            if '301' in status_line or '302' in status_line:
                print(f"Redirect Detected: {status_line}")
        except:
            print("Failed to detect redirect.")

        # Step 8B: Parse Cache-Control header
        should_cache = True
        try:
            header_data = response.split(b'\r\n\r\n')[0].decode(errors='ignore')
            for line in header_data.split('\r\n'):
                if line.lower().startswith('cache-control:'):
                    if 'max-age=0' in line.lower():
                        print("Cache-Control: max-age=0 → Skipping cache")
                        should_cache = False
                    else:
                        print(f"{line}")
        except Exception as e:
            print("Failed to parse Cache-Control:", e)

        if should_cache:
            cacheDir, file = os.path.split(cacheLocation)
            if not os.path.exists(cacheDir):
                os.makedirs(cacheDir)
            with open(cacheLocation, 'wb') as cacheFile:
                cacheFile.write(response)
                print('Saved to cache.')

    except Exception as e:
        print("Failed to receive/send data:", e)

    try:
        clientSocket.close()
        originSocket.close()
    except:
        print("Error closing sockets")
