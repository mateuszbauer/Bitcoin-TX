#!/usr/bin/env python3

import hashlib, base58, ecdsa, binascii
from hexdump import hexdump
import qrcode
import os, struct, time
import socket

VERSION = 70002
MAGIC = 0xD9B4BEF9

def dsha256(x):
	return hashlib.sha256(hashlib.sha256(x).digest()).digest()

def sha256(x):
	return hashlib.sha256(x).digest()

def ripemd160(x):
	'''
	Solution for "ValueError: unsupported hash type ripemd160":
		https://github.com/openssl/openssl/issues/16994
	'''
	h = hashlib.new('ripemd160')
	h.update(x)
	return h.digest()

def btc_to_satoshi(x):
	return int(x * 1000000000)

def create_private_key():
	'''
	https://developer.bitcoin.org/devguide/wallets.html#private-key-formats
	'''
	return os.urandom(32)

def create_public_key(private_key):
	pk = ecdsa.SigningKey.from_string(private_key,
		curve=ecdsa.SECP256k1).get_verifying_key().to_string('compressed')
	assert (len(pk) == 33)
	assert (pk[0] == 0x02 or pk[0] == 0x03)
	return pk

def create_wallet_import_format(private_key):
	'''
	https://developer.bitcoin.org/devguide/wallets.html#wallet-import-format-wif
	'''
	extended_key = b'\x80' + private_key + b'\x01'
	checksum = dsha256(extended_key)[:4]
	return base58.b58encode((extended_key + checksum))
	
def generate_address(public_key):
	'''
	https://en.bitcoin.it/wiki/Protocol_documentation#Addresses
	'''
	key_hash = b'\x00' + ripemd160(sha256(public_key))
	checksum = dsha256(key_hash)[:4]
	return base58.b58encode(key_hash + checksum)

def generate_qrcode(address, file):
	qrcode.make(address).save(file)

def pack_message(command, payload):
	'''
	From https://en.bitcoin.it/wiki/Protocol_documentation#Common_structures
	'''
	return struct.pack('<I12sI4s', MAGIC, command.encode('ascii'),
		len(payload), dsha256(payload)[:4]) + payload

def recv_message(sock):
	magic, command, length, checksum = struct.unpack('<I12sI4s', sock.recv(24))
	payload = sock.recv(length)
	assert magic == MAGIC
	assert length == len(payload)
	assert checksum == dsha256(payload)[:4]
	return command.decode('ascii'), payload

def prepare_version_msg():
	'''
	https://en.bitcoin.it/wiki/Protocol_documentation#version
	'''
	services = 1
	addr_recv = b'\x00' * 26
	addr_from = b'\x00' * 26
	nonce = os.urandom(8)
	user_agent = b'\x00'
	start_height = b'\x00\x00\x00\x00'
	payload = struct.pack('<IQQ26s26s8s1s4s', VERSION, services, int(time.time()),
		addr_recv, addr_from, nonce, user_agent, start_height)

	return pack_message('version', payload)

def prepare_verack_msg():
	'''
	https://en.bitcoin.it/wiki/Protocol_documentation#verack
	'''
	return pack_message('verack', b'')

def prepare_raw_tx(tx_hash_id, value, recv_addr):
	'''
	https://en.bitcoin.it/wiki/Protocol_documentation#tx
	'''
	version = 1
	tx_in_count = 1
	tx_hash_id = binascii.unhexlify(tx_hash_id)
	assert len(tx_hash_id) == 32
	output_index = 0
	sequence = b'\xff\xff\xff\xff'
	tx_out_count = 1
	value = btc_to_satoshi(value)
	lock_time = b'\x00\x00\x00\x00'
	scriptPubKey = b'\x76' + b'\xa9' + b'\x14' + base58.b58decode(recv_addr) + b'\x88' + b'\xac'
	scriptSig = scriptPubKey
	return struct.pack('<IB32sIB', version, tx_in_count, tx_hash_id, output_index, len(scriptSig)) + \
		scriptSig + struct.pack('<4sBQB', sequence, tx_out_count, value, len(scriptPubKey)) + \
		scriptPubKey + lock_time

def sign_tx_msg(raw_tx, private_key):
	pass

def prepare_tx_msg(tx_hash_id, value, private_key, recv_addr):
	raw_tx = prepare_raw_tx(tx_hash_id, value, recv_addr)
	signed_tx = sign_tx_msg(raw_tx, private_key)
	return signed_tx

def main():
	value = 0.9999
	sample_hash = "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48"
	addr = "1KZ51E55Q7z4DANd74mj4xu4rnBfW5FyzY"
	raw_tx = prepare_raw_tx(sample_hash, value, addr)
	hexdump(raw_tx)

	'''
	sk = create_private_key()
	pk = create_public_key(sk)
	wif = create_wallet_import_format(sk)
	addr = generate_address(pk)
	generate_qrcode(addr, 'addr.png')

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(('13.53.236.175', 8333))

	msg = prepare_version_msg() 
	hexdump(msg)
	sock.send(msg)

	cmd, payload = recv_message(sock)
	print(cmd)
	hexdump(payload)

	msg = prepare_verack_msg()
	hexdump(msg)
	sock.send(msg)

	cmd, payload = recv_message(sock)
	print(cmd)
	hexdump(payload)
	'''

if __name__ == '__main__':
	main()

