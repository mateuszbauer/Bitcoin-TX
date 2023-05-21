#!/usr/bin/env python3

import hashlib, base58, ecdsa
from hexdump import hexdump
import qrcode
import os, struct, time
import socket

TESTNET = int(os.getenv("TESTNET", 0))
VERSION = 70002


def dsha256(x):
	return hashlib.sha256(hashlib.sha256(x).digest()).digest()

def sha256(x):
	return hashlib.sha256(x).digest()

'''
Solution for "ValueError: unsupported hash type ripemd160":
	https://github.com/openssl/openssl/issues/16994
'''
def ripemd160(x):
	h = hashlib.new('ripemd160')
	h.update(x)
	return h.digest()

'''
From https://developer.bitcoin.org/devguide/wallets.html#private-key-formats

In Bitcoin, a private key in standard format is 256-bit number, between the values:
0x01 and 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140
'''
def create_private_key():
	return os.urandom(32)

def create_public_key(private_key):
	pk = ecdsa.SigningKey.from_string(private_key,
		curve=ecdsa.SECP256k1).get_verifying_key().to_string('compressed')

	assert (len(pk) == 33)
	assert (pk[0] == 0x02 or pk[0] == 0x03)
	return pk

'''
From https://developer.bitcoin.org/devguide/wallets.html#wallet-import-format-wif

Assuming mainnet address and compressed public key:
1. Take a private key
2. Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses
3. Append a 0x01 byte after it if it should be used with compressed public keys 
4. Perform a SHA-256 hash on the extended key.
5. Perform a SHA-256 hash on result of SHA-256 hash.
6. Take the first four bytes of the second SHA-256 hash; this is the checksum.
7. Add the four checksum bytes from point 5 at the end of the extended key from point 2.
8. Convert the result from a byte string into a Base58 string using Base58Check encoding.
'''
def create_wallet_import_format(private_key):
	netbyte = b'\xef' if TESTNET == 1 else b'\x80'
	extended_key = b'\x01' + netbyte + private_key
	checksum = dsha256(extended_key)[:4]
	return base58.b58encode((extended_key + checksum))
	
'''
From https://en.bitcoin.it/wiki/Protocol_documentation#Addresses
'''
def generate_address(public_key):
	version = b'\x6f' if TESTNET == 1 else b'\x00'
	key_hash = version + ripemd160(sha256(public_key))
	checksum = dsha256(key_hash)[:4]
	address = base58.b58encode(key_hash + checksum)
	return address

def generate_qrcode(address, file):
	qrcode.make(address).save(file)

'''
From https://en.bitcoin.it/wiki/Protocol_documentation#Common_structures

-----------+-------------+-----------+----------------------------------------------------
Field size | Description | Data type | Comment
-----------+-------------+-----------+----------------------------------------------------
4          | magic       | uint32_t  | 0xD9B4BEF9 for main network, 0xDAB5BFFA for testnet
-----------+-------------+-----------+----------------------------------------------------
12         | command     | char[12]  | NULL padded, ascii string identifying content 
-----------+-------------+-----------+----------------------------------------------------
4          | length      | uint32_t  | Payload length in number of bytes
-----------+-------------+-----------+----------------------------------------------------
4          | checksum    | uint32_t  | First 4 bytes of sha256(sha256(payload))
-----------+-------------+-----------+----------------------------------------------------
?          | payload     | uchar[]   | Actual data
-----------+-------------+-----------+----------------------------------------------------
'''
def make_message(command, payload):
	magic = 0xDAB5BFFA if TESTNET == 1 else 0xD9B4BEF9
	return struct.pack('<I12sI4s', magic, command.encode('ascii'),
		len(payload), dsha256(payload)[:4]) + payload

def prepare_version_msg():
	version = VERSION   # 4 bytes
	services = 1 # 8 bytes
	timestamp = int(time.time()) # 8 bytes
	addr_recv = b'\x00' * 26 # 26 bytes
	addr_from = b'\x00' * 26 # 26 bytes
	nonce = os.urandom(8) # 8 bytes
	user_agent = b'\x00' # 0x00 if 0 bytes long
	start_height = b'\x00' # 4 bytes

	payload = struct.pack('<IQQ26s26s8s1s4s', version, services, timestamp,
		addr_recv, addr_from, nonce, user_agent, start_height)
	return make_message('version', payload)

def main():
	sk = create_private_key()
	pk = create_public_key(sk)
	wif = create_wallet_import_format(sk)
	addr = generate_address(pk)
	generate_qrcode(addr, 'addr.png')

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(('91.206.17.195', 8333))

	msg = prepare_version_msg() 
	hexdump(msg)

	sock.send(msg)
	ret = sock.recv(2000)
	print("------ response ------")
	hexdump(ret)

if __name__ == '__main__':
	main()

