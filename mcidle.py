import socket, socketserver
import struct, json, io
from operator import or_

SERVER_INFO = {
	'version': {
		'name': '1.14',
	},
	'players': {
		'max': 0,
		'online': 0
	},
	'description': {
		'text': 'GCP idle server'
	}
}

def pack_varint(n):
	parts = [(n >> (7 * k)) & 0x7f for k in range((n.bit_length() - 1) // 7 + 1)]
	bits = [0x80] * (len(parts) - 1) + [0x00]
	res = b''
	for part, bit in zip(parts, bits):
		res += struct.pack('B', bit | part)
	return res

def unpack_varint(b):
	return sum((n & 0x7f) << (7 * k) for k, n in enumerate(b))

def pack_string(s):
	return pack_varint(len(s)) + s.encode('utf-8')

class MCVarInt:
	def __init__(self, value):
		self.value = value
	
	def pack(self):
		if not self.value:
			return b"\x00"
	
		parts = [(self.value >> (7 * k)) & 0x7f for k in range((self.value.bit_length() - 1) // 7 + 1)]
		bits = [0x80] * (len(parts) - 1) + [0x00]
		bs = b''
		for part, bit in zip(parts, bits):
			bs += struct.pack('B', bit | part)
		return bs

	@staticmethod
	def unpack(bs):
		return MCVarInt(sum((n & 0x7f) << (7 * k) for k, n in enumerate(bs)))
	
	@staticmethod
	def read(rfile):
		bs = rfile.read(1)
		if not bs:
			return None
		while bs[-1] & 0x80:
			bs += rfile.read(1)
		return MCVarInt.unpack(bs)

	def __len__(self):
		return len(self.pack())

	def __repr__(self):
		return f"MCVarInt({self.value})"

class MCString:
	def __init__(self, data):
		if isinstance(data, str):
			self.data = data.encode('utf-8')
		elif isinstance(data, bytes):
			self.data = data
		else:
			raise TypeError
	
	def pack(self):
		return MCVarInt(len(self.data)).pack() + self.data

	@staticmethod
	def read(rfile):
		size = MCVarInt.read(rfile)
		return MCString(rfile.read(size.value))

	def __repr__(self):
		return f"MCString({self.data!r})"

class MinecraftRequestHandler(socketserver.StreamRequestHandler):
	def mc_recv(self):
		"""Return one minecraft protocol packet"""
		size = MCVarInt.read(self.rfile)
		if not size:
			return None, 0
		pid = MCVarInt.read(self.rfile)
		data = self.rfile.read(size.value - len(pid))
		buf = io.BytesIO(data)
		return buf, pid.value

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
		if not packet:
			return
		req, _ = self.mc_recv() # empty request

		# Read the client hello
		protocol = MCVarInt.read(packet)
		SERVER_INFO['version']['protocol'] = protocol.value
		addr = MCString.read(packet)
		port, = struct.unpack('>h', packet.read(2))
		state = MCVarInt.read(packet)

		# Always return our status, don't care about other requests
		status = MCString(json.dumps(SERVER_INFO))
		self.mc_send(status.pack())

		# Client expects an echo
		packet, pid = self.mc_recv()
		self.mc_send(packet.read(), pid = pid)

if __name__ == '__main__':
	target = 'localhost', 25565
	with socketserver.TCPServer(target, SLPHandler) as server:
		server.serve_forever()
