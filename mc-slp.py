#!/usr/bin/python3

import socket, socketserver, subprocess
import struct, json, io, shlex, copy
import sys, traceback

from random import randint

import argparse
parser = argparse.ArgumentParser(
	description = "Shell server for handling minecraft SLP requests",
	formatter_class = argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('--description', help = "server description text")
parser.add_argument('--ping',
help = """
	ping another server instead of serving.
	return codes
	0 on success
	4 on connection error
""",
	action = 'store_true')
parser.add_argument('--job', help = 'command for server to run on each client ping.')
parser.add_argument('host', nargs = '?', default = "0.0.0.0:25565",
help = "address to use 'host:port' format. Minecraft does not support IPv6.")

class MCFormatError(Exception):
	"""Minecraft protocol format error"""
	pass

class MCField:
	pass

class MCPacket:
	def __init__(self, *fields, pid = 0, values = None):
		super().__setattr__('fields', fields)
		self.pid = pid
		if not values:
			self.values = {name: None for name, cls in fields}
		else:
			if set(name for name, cls in self.fields) == set(values):
				self.values = values
			else:
				raise MCFormatError(f"Incorrect field values: {fields} {values}")

	@property
	def size(self):
		if None not in self.values:
			size = len(MCVarInt(self.pid))
			size += sum(len(cls(self.values[name])) for name, cls in self.fields)
			return size
		else:
			return MCFormatError("Incomplete MCPacket")

	def __len__(self):
		size = self.size
		return len(MCVarInt(size)) + size

	def __getattr__(self, name):
		for field, cls in self.fields:
			if field == name:
				return self.values[name]
		else:
			raise AttributeError(name)

	def __setattr__(self, name, value):
		for field, cls in self.fields:
			if field == name:
				self.values[name] = value
				return
		else:
			super().__setattr__(name, value)

	def __repr__(self):
		pairs = [f"{name}={cls(self.values[name])!r}" for name, cls in self.fields]
		return "MCPacket<" + ', '.join(pairs) + ">"

	def pack(self):
		data = MCVarInt(self.size).pack()
		data += MCVarInt(self.pid).pack()
		for name, cls in self.fields:
			data += cls(self.values[name]).pack()
		return data

	def recv(self, sock):
		size = MCVarInt.recv(sock)
		data = sock.recv(size.value)
		while len(data) < size.value:
			data += sock.recv(size.value - len(data))
		data = io.BytesIO(data)
		self.pid = MCVarInt.read(data).value

		for name, cls in self.fields:
			setattr(self, name, cls.read(data).value)

		rem = data.read(80)
		if rem:
			raise MCFormatError(f"Unexpected data: {rem!r}.")

	@classmethod
	def create(cls, values):
		fields = [(name, type(value)) for name, value in values]
		values = {name: value.value for name, value in values}
		return cls(*fields, values = values)

class MCStruct(MCField):
	fmt = ''
	def __init__(self, value = 0):
		self.value = value

	def __len__(self):
		return struct.calcsize(self.fmt)

	def __repr__(self):
		return f"{type(self).__name__}({self.value})"

	def pack(self):
		return struct.pack(self.fmt, self.value)

	def unpack(self, value):
		return struct.unpack(self.fmt, value)[0]

	@classmethod
	def read(cls, rfile):
		data = rfile.read(struct.calcsize(cls.fmt))
		return cls(*struct.unpack(cls.fmt, data))

class MCShort(MCStruct):
	fmt = '>h'

class MCLong(MCStruct):
	fmt = '>l'

class MCVarInt(MCField):
	"""
	VarInt type from the Minecraft protocol.
	7 LSB are data bits. MSB of 0 indicates this byte is the last.
	"""
	def __init__(self, value: int):
		self._value = value
	
	def __len__(self):
		return (self.value.bit_length() - 1) // 7 + 1 if self.value else 1

	def __repr__(self):
		return f"MCVarInt({self.value})"

	@property
	def value(self):
		return self._value

	def pack(self):
		if not self.value: return b"\x00"

		parts = [(self.value >> (7 * k)) & 0x7f for k in range(len(self))]
		return bytes([byte | 0x80 for byte in parts[:-1]]) + bytes(parts[-1:])

	@classmethod
	def unpack(cls, bs: bytes):
		if not bs or bs[-1] & 0x80:
			raise ValueError(f"Expected MCVarInt, not {bs!r}")

		byte = lambda n, k: (n & 0x7f) << (7 * k)
		return cls(sum(byte(n, k) for k, n in enumerate(bs)))
	
	@classmethod
	def read(cls, rfile):
		bs = rfile.read(1)
		while bs and bs[-1] & 0x80:
			bs += rfile.read(1)
		return cls.unpack(bs)

	@classmethod
	def recv(cls, sock):
		bs = sock.recv(1)
		while bs and bs[-1] & 0x80:
			bs += sock.recv(1)
		return cls.unpack(bs)

class MCString(MCField):
	"""
	String type from the Minecraft protocol.
	string length as a VarInt followed by the data.
	"""
	def __init__(self, value):
		if isinstance(value, str):
			self.data = value.encode('utf-8')
		elif isinstance(value, bytes):
			self.data = value
		else:
			raise ValueError(value)

	def __len__(self):
		return len(MCVarInt(len(self.data))) + len(self.data)

	def __repr__(self):
		return f"MCString({self.data!r})"
	
	def pack(self):
		return MCVarInt(len(self.data)).pack() + self.data

	@property
	def value(self):
		return self.data.decode('utf-8')

	@value.setter
	def value(self, new):
		self.__init__(self, new)

	@classmethod
	def unpack(cls, bs):
		rfile = io.BytesIO(bs)
		return cls.read(rfile)

	@classmethod
	def read(cls, rfile):
		size = MCVarInt.read(rfile)
		return cls(rfile.read(size.value))

class MinecraftServer(socketserver.TCPServer):
	allow_reuse_address = True

	def __init__(self, *args, status = {}, job = None, **kwds):
		super().__init__(*args, **kwds)
		self.status = status
		self.job = job

class MinecraftRequestHandler(socketserver.BaseRequestHandler):
	def mc_send(self, pkt: MCPacket):
		"""Send one MCPacket"""
		self.request.sendall(pkt.pack())

	def mc_recv(self, pkt: MCPacket):
		"""Fill one MCPacket with stream data"""
		pkt.recv(self.request)

class SLPHandler(MinecraftRequestHandler):
	def do_run(self):
		print(f"Request from {self.client_address[0]}.")
		if hasattr(self.server, 'run'):
			ret = self.server.run.poll()
		else:
			ret = 0
		# Only run job if last job has exited succesfully
		if ret == 0:
			cmd = shlex.split(self.server.job)
			proc = subprocess.Popen(cmd)
			self.server.run = proc
			print(f"Running aux job [{proc.pid}]: {' '.join(proc.args)}")

	def setup(self):
		self.request.settimeout(1)

	def handle(self):
		pk_hello = MCPacket(
			('proto', MCVarInt ),
			('host' , MCString ),
			('port' , MCShort  ),
			('next' , MCVarInt )
		)
		pk_push = MCPacket()
		pk_srv = MCPacket(('status', MCString))
		pk_ping = MCPacket(
			('zero' , MCLong),
			('nonce', MCLong)
		)

		try:
			self.mc_recv(pk_hello)
			self.mc_recv(pk_push)

			status = copy.deepcopy(self.server.status)
			status['version']['protocol'] = pk_hello.proto
			pk_srv.status = json.dumps(status)
			self.mc_send(pk_srv)
		except (MCFormatError, socket.timeout) as error:
			print(f"Bad request from {self.client_address}", file = sys.stderr)
			raise

		# This was a valid conversation, start the aux job
		if self.server.job:
			self.do_run()

		# Client may send optional echo
		try:
			self.mc_recv(pk_ping)
			self.mc_send(pk_ping)
		except (MCFormatError, socket.timeout) as error:
			# Client did not request an echo
			pass

def sl_serve(target, status, job):
	with MinecraftServer(target, SLPHandler, status = status, job = job) as server:
		server.serve_forever()

def sl_ping(target):
	host, port = target

	pk_hello = MCPacket.create([
		('proto', MCVarInt(480)  ),
		('host' , MCString(host) ),
		('port' , MCShort(port)  ),
		('next' , MCVarInt(1)    )
	])
	pk_push = MCPacket()
	pk_srv = MCPacket(('status', MCString))
	pk_ping = MCPacket.create([
		('zero' , MCLong(0)),
		('nonce', MCLong(randint(0, 2**16)))
	])
	pk_ping.pid = 1

	with socket.socket() as sock:
		sock.settimeout(3)
		try:
			sock.connect(target)
			sock.sendall(pk_hello.pack())
			sock.sendall(pk_push.pack())
			pk_srv.recv(sock)
		except socket.timeout as timeout:
			print(f"{host}:{port} is offline.", file = sys.stderr)
			sys.exit(4)
		except socket.gaierror as error:
			print(f"Cannot resolve {host}.", file = sys.stderr)
			sys.exit(4)
		except socket.error as error:
			print(error, file = sys.stderr)
			sys.exit(4)
		try:
			sock.sendall(pk_ping.pack())
			pk_ping.recv(sock)
		except (MCFormatError, socket.error) as error:
			# Server doesn't support echo
			pass

	return json.loads(pk_srv.status)

if __name__ == '__main__':
	try:
		args = parser.parse_args()
		if ':' in args.host:
			host, port = args.host.rsplit(':', 1)
			target = host, int(port)
		else:
			target = args.host, 25565
	except ValueError as error:
		print(f"Invalid host: {args.host}", file = sys.stderr)
		sys.exit(1)

	if args.ping:
		status = sl_ping(target)
		print(json.dumps(status))
		sys.exit(0)

	status = {
		'version': {
			'name': 'latest',
		},
		'players': {
			'max': 0,
			'online': 0,
		},
		'description': {
			'text': 'SLP idle server'
		}
	}

	if args.description is not None:
		status['description']['text'] = args.description

	try:
		sl_serve(target, status, args.job)
	except KeyboardInterrupt as intr:
		pass
