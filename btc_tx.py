#!/usr/bin/env python3

import numpy as np
import os
import hashlib, base58, ecdsa
from hexdump import hexdump
import qrcode

class BTC_TX:
	def __init__(self):
		self.sk = BTC_TX.create_private_key()
		self.pk = BTC_TX.create_public_key(self.sk)
		self.WIF = BTC_TX.create_wallet_import_format(self.pk)
		self.address = self.generate_address(self.pk)

	@staticmethod
	def dsha256(x):
		return hashlib.sha256(hashlib.sha256(x).digest()).digest()

	@staticmethod
	def sha256(x):
		return hashlib.sha256(x).digest()

	'''
	Solution for "ValueError: unsupported hash type ripemd160":
		https://github.com/openssl/openssl/issues/16994
	'''
	@staticmethod
	def ripemd160(x):
		h = hashlib.new('ripemd160')
		h.update(x)
		return h.digest()
	
	'''
	From https://developer.bitcoin.org/devguide/wallets.html#private-key-formats

	In Bitcoin, a private key in standard format is 256-bit number, between the values:
	0x01 and 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140
	'''
	@staticmethod
	def create_private_key():
		return os.urandom(32)

	@staticmethod
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
	@staticmethod
	def create_wallet_import_format(private_key):
		extended_key = b'\x01' + b'\x80' + private_key
		checksum = BTC_TX.dsha256(extended_key)[:4]
		return base58.b58encode((extended_key + checksum))
	
	'''
	From https://en.bitcoin.it/wiki/Protocol_documentation#Addresses
	'''
	@staticmethod
	def generate_address(public_key):
		key_hash = b'\x00' + BTC_TX.ripemd160(BTC_TX.sha256(public_key))
		checksum = BTC_TX.dsha256(key_hash)[:4]
		address = base58.b58encode(key_hash + checksum)
		return address

	def generate_qrcode(self, file):
		qrcode.make(self.address).save(file)


def main():
	tx = BTC_TX()
	tx.generate_qrcode('addr.png')

if __name__ == '__main__':
	main()

