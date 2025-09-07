#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket, time, pyaes, struct, os, msvcrt, random, hashlib, hmac

SERVER_HOST = "localhost"
KEY_EXCHANGE_PORT = 42441

class C:
	def __init__(self):
		self.s = None
		self.k = None
		self.m = None
		self.enc = False
		self.t = 0

	def enc_msg(self, msg, k):
		iv = os.urandom(16)
		b = msg.encode('utf-8')
		pad = 16 - (len(b) % 16)
		b += chr(pad) * pad
		a = pyaes.AESModeOfOperationCBC(k, iv=iv)
		out = ""
		for i in range(0, len(b), 16):
			out += a.encrypt(b[i:i+16])
		return iv + out

	def dec_msg(self, data, k):
		if len(data) < 16:
			return None
		iv, enc = data[:16], data[16:]
		if len(enc) % 16 != 0:
			return None
		a = pyaes.AESModeOfOperationCBC(k, iv=iv)
		out = ""
		for i in range(0, len(enc), 16):
			out += a.decrypt(enc[i:i+16])
		pad = ord(out[-1])
		if pad == 0 or pad > 16:
			return None
		return out[:-pad].decode('utf-8')

	def send(self, msg):
		if self.enc:
			p = self.enc_msg(msg, self.k)
			if not p:
				return False
			if self.m:
				mac = hmac.new(self.m, p, hashlib.sha256).digest()
				p += mac
			self.s.send(struct.pack('>I', len(p)) + p)
			return True
		else:
			self.s.send((msg + '\n').encode('utf-8'))
			return True

	def recv(self):
		if self.enc:
			try:
				self.s.settimeout(0.1)
				d = self.s.recv(4)
			except socket.timeout:
				return None
			if len(d) != 4:
				return None
			ln = struct.unpack('>I', d)[0]
			buf = ""
			while len(buf) < ln:
				try:
					c = self.s.recv(ln - len(buf))
				except socket.timeout:
					return None
				if not c:
					return None
				buf += c
			if self.m and ln >= 32:
				data_part, mac_part = buf[:-32], buf[-32:]
				exp = hmac.new(self.m, data_part, hashlib.sha256).digest()
				if exp != mac_part:
					return None
				payload = data_part
			else:
				payload = buf
			return self.dec_msg(payload, self.k)
		else:
			data = self.s.recv(1024).decode('utf-8').strip()
			return data if data else None

	def connect(self):
		try:
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.s.connect((SERVER_HOST, KEY_EXCHANGE_PORT))
			d = self.s.recv(2)
			if len(d) != 2:
				return False
			alen = struct.unpack('>H', d)[0]
			Ab = ""
			while len(Ab) < alen:
				c = self.s.recv(alen - len(Ab))
				if not c:
					return False
				Ab += c
			P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
			G = 2
			A = int(Ab.encode('hex'), 16)
			b = random.getrandbits(256)
			B = pow(G, b, P)
			Bh = hex(B)[2:].rstrip('L')
			if len(Bh) % 2:
				Bh = '0' + Bh
			Bb = Bh.decode('hex')
			self.s.send(struct.pack('>H', len(Bb)) + Bb)
			S = pow(A, b, P)
			Sh = hex(S)[2:].rstrip('L')
			if len(Sh) % 2:
				Sh = '0' + Sh
			Sb = Sh.decode('hex')
			self.k = hashlib.sha256(Sb + "|KEY").digest()
			self.m = hashlib.sha256(Sb + "|MAC").digest()
			self.enc = True
			msg = self.recv()
			if msg:
				print msg
			return True
		except Exception:
			return False

	def loop(self):
		if not self.connect():
			return
		try:
			while True:
				now = time.time()
				if now - self.t > 5:
					self.send("/")
					self.t = now
				if msvcrt.kbhit():
					try:
						m = raw_input()
						if m.lower() in ['/quit', '/exit']:
							break
						if not self.send(m):
							break
					except EOFError:
						break
				r = self.recv()
				if r and r.strip() != "*Ping!*":
					print r
				time.sleep(0.01)
		except KeyboardInterrupt:
			pass
		finally:
			try:
				self.s.close()
			except:
				pass

if __name__ == "__main__":
	C().loop()
