'''
Rivest-Shamir-Adleman
'''
import random
from typing import Tuple, List
import os

class RSA:
	def __init__(self):
		'''
		konstruktor
		'''
		# muat daftar bilangan prima besar
		prime_file_path = os.path.join(os.path.abspath("."), "./assets/prime-list.txt")
		with open(prime_file_path, "r") as f:
			self.large_primes = [int(x) for x in f.read().split()]

		# bangkitkan prima-prima kecil menggunakan linear sieve
		MAX_PRIME = 10001
		mpf = [0 for i in range(MAX_PRIME)] # mpf[i] = minimum prime factor i
		self.small_primes = []
		for i in range(2, MAX_PRIME):
			if mpf[i] == 0:
				mpf[i] = i
				self.small_primes.append(i)
			j = 0;
			while j < len(self.small_primes) and \
			self.small_primes[j] <= mpf[i] and \
			i*self.small_primes[j] < MAX_PRIME:
				mpf[i * self.small_primes[j]] = self.small_primes[j]
				j += 1

	def __mod_pow(self, x: int, y: int, m: int) -> int:
		'''
		mengembalikan x pangkat y modulo m, O(log y)
		prekondisi: y >= 0
		'''
		ret = 1;
		while y > 0:
			if y % 2 == 1:
				ret = ret * x % m
			x = x * x % m
			y //= 2
		return ret

	def __gcd(self, x: int, y: int) -> int:
		'''
		mengembalikan pembagi bersama terbesar x dan y
		prekondisi: 0 <= x, y; 0 < x + y
		'''
		while y > 0:
			x, y = y, x % y
		return x

	def __encrypt_one_char(self, c: str, public_key: tuple[int, int]) -> int:
		'''
		mengembalikan pasangan titik hasil enkripsi satu huruf c
		'''
		return self.__mod_pow(ord(c), public_key[0], public_key[1])

	def __decrypt_one_char(self, c: int, private_key: int) -> str:
		'''
		mengembalikan karakter hasil dekripsi satu bilangan c
		'''
		return chr(self.__mod_pow(c, private_key[0], private_key[1]))

	def generate_random_key_pair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
		'''
		membangkitkan pasangan (kunci publik, kunci privat)
		'''
		ip = random.randint(0, len(self.small_primes) - 1)
		iq = ip
		while iq == ip: # harusnya ngulangnya nggak banyak amat
			iq = random.randint(0, len(self.small_primes) - 1)
		p = self.small_primes[ip]
		q = self.small_primes[iq]
		n = p * q
		phi = (p - 1) * (q - 1)

		# hitung kunci publik
		# pakai random, expected failurenya 6/(pi**2), harusnya cukup bagus
		e = random.randint(2, phi)
		while self.__gcd(e, phi) > 1:
			e = random.randint(2, phi)
		assert(self.__gcd(e, phi) == 1)

		# hitung kunci privat
		# pake bruteforce dulu, mungkin nanti bakal diganti extended euclid
		d = 0
		k = 0
		while (1 + k * phi) % e != 0:
			k += 1
		d = (1 + k * phi) // e
		assert(e * d % phi == 1)

		return ((e, n), (d, n))

	def encrypt(self, plaintext: str, public_key: tuple[int, int]) -> List[int]:
		'''
		mengembalikan cipherteks hasil enkripsi plaintext dengan kunci public_key
		cipherteks berisi bilangan bulat untuk setiap huruf
		ide pengembangan: cipherteks berisi bilangan bulat untuk setiap k huruf kontigu
		'''
		ciphertext = []
		for i, c in enumerate(plaintext):
			ciphertext.append(self.__encrypt_one_char(c, public_key))
		return ciphertext

	def decrypt(self, ciphertext: List[int], private_key: int) -> str:
		'''
		mengembalikan plainteks hasil dekripsi ciphertext dengan kunci private_key
		'''
		plaintext = ""
		for cs in ciphertext:
			plaintext += self.__decrypt_one_char(cs, private_key)
		return plaintext

if __name__ == "__main__":
	rsa = RSA()
	plaintext = "Semoga nilai kriptografi IF4020 A amiin"
	private_key, public_key = rsa.generate_random_key_pair()
	ciphertext = rsa.encrypt(plaintext, public_key)
	print("kunci privat:", private_key)
	print("kunci publik:", public_key)
	print("hasil encrypt:", ciphertext)
	print("hasil decrypt:", rsa.decrypt(ciphertext, private_key))
