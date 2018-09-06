#!/usr/bin/env python
"""
RCON line-based console

Usage:
    rconsole <host> 
    rconsole <host> <port>

Options:
    host  RCON Server host name.
    port  RCON port [default: 25575]
"""

import sys, socket, struct, cmd
from getpass import getpass
from docopt import docopt

# IDs
DEFAULT_ID = 1
AUTH_ID = 2 # Not really necessary

# Types
SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0

NUL = b'\x00'

def make_rcon_packet(body = '', ID = DEFAULT_ID, Type = SERVERDATA_EXECCOMMAND):
	body = body.encode('utf-8') + NUL
	size = 9 + len(body)
	return struct.pack('<3i', size, ID, Type) + body + NUL

def read_rcon_packet(packet):
	size, ID, Type = struct.unpack('<3i', packet[:12])
	body = packet[12:-2].decode('utf-8')
	return body, ID, Type

def authenticate(sock, password):
	auth_packet = make_rcon_packet(password, ID = AUTH_ID, Type = SERVERDATA_AUTH)

	sock.sendall(auth_packet)
	resp = sock.recv(1024)
	body, ID, Type = read_rcon_packet(resp)
	return ID == AUTH_ID

class RCONShell(cmd.Cmd):
    prompt = '> '
    file = None

    def __init__(self, target, *args, **kwds):
        super().__init__(self, *args, **kwds)
        try:
            self.password = getpass()
        except KeyboardInterrupt as e:
            print()
            exit()

        try:
            self.sock = socket.socket()
            self.sock.settimeout(3)
            self.sock.connect(target)
        except socket.timeout as err:
            print("Authentication timed out, server probably not running.",
                    file=sys.stderr)
            sys.exit(1)
        except OSError as err:
            print("Cannot create socket", file=sys.stderr)
            sys.exit(1)

        auth = authenticate(self.sock, self.password)
        if not auth:
            print("Incorrect password", file=sys.stderr)
            sys.exit(1)


    def default(self, body):
        self.sock.send(make_rcon_packet(body))
        resp = self.sock.recv(4096)
        body, ID, Type = read_rcon_packet(resp)
        if body:
            print(body)

    def do_EOF(self, line):
        self.sock.close()
        print()
        return True

if __name__ == '__main__':
    args = docopt(__doc__, version = '1.0')
    sys.argv = sys.argv[:1]

    host = args['<host>']
    port = args['<port>'] or 25575
    try:
        port = int(port)
    except ValueError as e:
        print("Bad port.", file=sys.stderr)
        sys.exit(1)

    target = host, port

    shell = RCONShell(target)
    shell.cmdloop()
