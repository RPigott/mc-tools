import socket, socketserver, subprocess
import struct, json, io, copy
import sys, traceback

class MinecraftServer(socketserver.TCPServer):
	def __init__(self, server_info, *args, **kwds):
		super().__init__(*args, **kwds)
		self.server_info = server_info
		self.job = None

	def mc_pack(payload, pid = 0):
		pid = MCVarInt(pid)
		size = MCVarInt(len(pid) + len(payload))
		return size.pack() + pid.pack() + payload

class MCFormatError(Exception):
	"""Minecraft protocol format error"""
	pass

class MCVarInt:
	"""
	VarInt type from the Minecraft protocol.
	7 LSB are data bits. MSB of 0 indicates this byte is the last.
	"""
	def __init__(self, value: int):
		self.value = value
	
	def __len__(self):
		return (self.value.bit_length() - 1) // 7 + 1 if self.value else 1

	def __repr__(self):
		return f"MCVarInt({self.value})"

	def pack(self):
		if not self.value: return b"\x00"

		parts = [(self.value >> (7 * k)) & 0x7f for k in range(len(self))]
		return bytes([byte | 0x80 for byte in parts[:-1]]) + bytes(parts[-1:])

	@staticmethod
	def unpack(bs):
		if not bs or bs[-1] & 0x80:
			raise ValueError(f"Expected MCVarInt, not {bs!r}")

		byte = lambda n, k: (n & 0x7f) << (7 * k)
		return MCVarInt(sum(byte(n, k) for k, n in enumerate(bs)))
	
	@staticmethod
	def read(rfile):
		bs = rfile.read(1)
		while bs and bs[-1] & 0x80:
			bs += rfile.read(1)
		return MCVarInt.unpack(bs)

class MCString:
	"""
	String type from the Minecraft protocol.
	string length as a VarInt followed by the data.
	"""
	def __init__(self, data):
		if isinstance(data, str):
			self.data = data.encode('utf-8')
		elif isinstance(data, bytes):
			self.data = data
		else:
			raise ValueError

	def __len__(self):
		return len(MCVarInt(len(self.data))) + len(self.data)

	def __repr__(self):
		return f"MCString({self.data!r})"
	
	def pack(self):
		return MCVarInt(len(self.data)).pack() + self.data

	@staticmethod
	def unpack(bs):
		rfile = io.BytesIO(bs)
		return MCString.read(rfile)

	@staticmethod
	def read(rfile):
		size = MCVarInt.read(rfile)
		return MCString(rfile.read(size.value))

class MinecraftRequestHandler(socketserver.StreamRequestHandler):

	def mc_recv(self):
		"""Return one minecraft protocol packet"""
		try:
			size = MCVarInt.read(self.rfile)
			pid = MCVarInt.read(self.rfile)
			data = self.rfile.read(size.value - len(pid))
			buf = io.BytesIO(data)
			return buf, pid.value
		except ValueError as error:
			raise MCFormatError from error

	def mc_send(self, payload, pid = 0):
		"""Send one minecraft protocol packet"""
		pid = MCVarInt(pid)
		size = MCVarInt(len(payload) + len(pid))
		data = size.pack() + pid.pack() + payload
		self.wfile.write(data)

class SLPHandler(MinecraftRequestHandler):

	def handle(self):
		# Read protocol things
		packet, pid = self.mc_recv() # Hello
		req, _ = self.mc_recv() # empty request

		# Read the client hello
		server_info = copy.deepcopy(self.server.server_info)
		protocol = MCVarInt.read(packet)
		server_info['version']['protocol'] = protocol.value
		addr = MCString.read(packet)
		port, = struct.unpack('>h', packet.read(2))
		state = MCVarInt.read(packet)

		# Always return our status, don't care about other requests
		status = MCString(json.dumps(server_info))
		self.mc_send(status.pack())

		# Client expects an echo
		packet, pid = self.mc_recv()
		self.mc_send(packet.read(), pid = pid)

		# This was a valid conversation, start the aux job
		retcode = self.server.job.poll() if self.server.job else 0
		if retcode == 0:
			cmd = "gcloud compute instances start mc-server-test".split()
			self.server.job = subprocess.Popen(cmd)
		job = self.server.job
		print(f"Request from {self.client_address[0]}. Running aux job [{job.pid}]: {' '.join(job.args)}")

def serve(target, server_info):
	with MinecraftServer(server_info, target, SLPHandler) as server:
		server.serve_forever()

def ping(target):
	host, port = target
	payload  = MCVarInt(477).pack()
	payload += MCString(host).pack()
	payload += struct.pack('>h', port)
	payload += MCVarInt(1).pack()
	pid = MCVarInt(0)
	size = MCVarInt(len(payload) + len(pid))
	packet = size.pack() + pid.pack() + payload
	req = MCVarInt(1).pack() + MCVarInt(0).pack()
	try:
		with socket.socket() as sock:
			sock.connect(target)
			sock.sendall(packet)
			sock.sendall(req)
			proto = io.BytesIO(sock.recv(10))
			size = MCVarInt.read(proto)
			pid = MCVarInt.read(proto)
			status = proto.read()
			while len(status) < size.value - len(size) - len(pid):
				status += sock.recv(2**12)
	except ConnectionError as error:
		traceback.print_exc()
		sys.exit(2)
	
	server_info = json.loads(MCString.unpack(status).data.decode('utf-8'))
	return server_info

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(
		description = "Shell server for handling minecraft SLP requests",
		formatter_class = argparse.ArgumentDefaultsHelpFormatter)

	parser.add_argument('--description', help = "server description text")
	parser.add_argument('--ping',
	help = """
		ping another server instead of serving.
		return codes indicate
		0 if the server is empty,
		1 if there are players online
	""",
		action = 'store_true')
	parser.add_argument('--serve', help = "create an SLP server. The default action.", action = 'store_true')
	parser.add_argument('--host', default = "0.0.0.0",
		help = "address to listen on. Minecraft does not support IPv6.")
	parser.add_argument('--port',
		help = "port to listen on.",
		default = 25565, type = int)

	args = parser.parse_args()
	target = args.host, args.port

	if args.ping:
		server_info = ping(target)
		if server_info['players']['online']:
			sys.exit(1)
		else:
			sys.exit(0)

	server_info = {
		'version': {
			'name': 'latest',
		},
		'players': {
			'max': 0,
			'online': 0
		},
		'description': {
			'text': 'SLP idle server'
		}
	}

	if args.description is not None:
		server_info['description']['text'] = args.description

	serve(target, server_info)
