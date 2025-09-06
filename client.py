#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
import time
import pyaes
import struct
import os
import msvcrt

HOST = "dmconnect.hoho.ws"
PORT = 42440
AES_KEY_SIZE = 32

class UltraCompactClient:
    def __init__(self):
        self.socket = None
        self.encryption_key = None
        self.use_encryption = False
        self.running = True
        self.last_ping_time = 0

    def encrypt_message(self, message, key):
        try:
            iv = os.urandom(16)
            
            message_bytes = message.encode('utf-8')
            padding_length = 16 - (len(message_bytes) % 16)
            padded_message = message_bytes + chr(padding_length) * padding_length
            
            aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
            
            encrypted_data = ""
            for i in range(0, len(padded_message), 16):
                block = padded_message[i:i+16]
                encrypted_block = aes.encrypt(block)
                encrypted_data += encrypted_block
            
            return iv + encrypted_data
        except Exception as e:
            print "Encryption error: %s" % str(e)
            return None

    def decrypt_message(self, encrypted_data, key):
        try:
            if len(encrypted_data) < 16:
                return None
                
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            
            if len(encrypted) % 16 != 0:
                return None
            
            aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
            
            decrypted = ""
            for i in range(0, len(encrypted), 16):
                block = encrypted[i:i+16]
                decrypted_block = aes.decrypt(block)
                decrypted += decrypted_block
            
            padding_length = ord(decrypted[-1])
            if padding_length > 16 or padding_length == 0:
                return None
                
            message_bytes = decrypted[:-padding_length]
            return message_bytes.decode('utf-8')
        except Exception as e:
            print "Decryption error: %s" % str(e)
            return None

    def send_message(self, message):
        try:
            if self.use_encryption:
                encrypted = self.encrypt_message(message, self.encryption_key)
                if encrypted:
                    length = struct.pack('>I', len(encrypted))
                    self.socket.send(length + encrypted)
                    return True
            else:
                self.socket.send((message + '\n').encode('utf-8'))
                return True
        except Exception as e:
            print "Send error: %s" % str(e)
            return False

    def receive_message(self):
        try:
            if self.use_encryption:
                self.socket.settimeout(0.1)
                
                length_data = self.socket.recv(4)
                if len(length_data) != 4:
                    return None
                
                length = struct.unpack('>I', length_data)[0]
                
                encrypted_data = ''
                while len(encrypted_data) < length:
                    chunk = self.socket.recv(length - len(encrypted_data))
                    if not chunk:
                        return None
                    encrypted_data += chunk
                
                return self.decrypt_message(encrypted_data, self.encryption_key)
            else:
                data = self.socket.recv(1024).decode('utf-8').strip()
                return data if data else None
        except socket.timeout:
            return None
        except Exception as e:
            print "Receive error: %s" % str(e)
            return None

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            
            self.encryption_key = self.socket.recv(AES_KEY_SIZE)
            if len(self.encryption_key) == AES_KEY_SIZE:
                self.use_encryption = True

                message = self.receive_message()
                if message:
                    print message
                
                return True
            else:
                print "Failed to get encryption key."
                return False
        except Exception as e:
            print "Connection failed: %s" % str(e)
            return False

    def check_for_messages(self):
        try:
            message = self.receive_message()
            if message:
                if message.strip() != "*Ping!*":
                    print message
                return True

            return True
        except Exception as e:
            print "Receiver error: %s" % str(e)
            return False

    def run(self):
        if not self.connect():
            return
        
        try:
            while self.running:
                current_time = time.time()
                
                if current_time - self.last_ping_time > 5:
                    self.send_message("/")
                    self.last_ping_time = current_time
                
                if msvcrt.kbhit():
                    try:
                        message = raw_input()
                        if message.lower() in ['/quit', '/exit']:
                            break
                        if not self.send_message(message):
                            break
                    except EOFError:
                        break
                
                self.check_for_messages()
                time.sleep(0.01)
                        
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            print "Disconnected."

if __name__ == "__main__":
    client = UltraCompactClient()
    client.run()
