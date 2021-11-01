'''
Elliptic Curve Elgamal
'''
import random
from typing import Tuple, List

class ECC:
	def __init__(self, a: int, b: int, m: int):
		'''
		konstruktor
		a, b, m menyatakan persamaan kurva y**2 = (x**3 + ax + b) mod m
		prekondisi: 
		1. 0 <= a, b < m 
		2. m >= 256, m prima
		3. banyak titik diskrit di kurva elliptik >= 256 
		'''
		self.eq_a = a
		self.eq_b = b
		self.mod = m

		# buat dictionary pemetaan huruf ASCII ke titik kurva
		# sekarang pake cara custom dulu, bingung sama metode Kolbitz
		self.points = []
		ys = {}
		for y in range(self.mod):
			ys[y*y % self.mod] = y
		for x in range(self.mod):
			rhs = (x*x*x + self.eq_a*x + self.eq_b) % self.mod
			if rhs in ys:
				self.points.append((x, ys[rhs]))

		assert(len(self.points) >= 256)

		self.char_to_point = {}
		self.point_to_char = {}
		for c, pt in enumerate(self.points):
			if c >= 256:
				break # cukup memetakan 256 karakter ascii saja
			self.char_to_point[chr(c)] = pt
			self.point_to_char[pt] = chr(c)

		# ambil satu titik sebagai basis
		self.base = self.points[-1]

	def __mod_pow(self, x: int, y: int) -> int:
		'''
		mengembalikan x pangkat y modulo self.mod, O(log y)
		prekondisi: y >= 0
		'''
		ret = 1;
		while y > 0:
			if y % 2 == 1:
				ret = ret * x % self.mod
			x = x * x % self.mod
			y //= 2
		return ret

	def __mod_inv(self, x: int) -> int:
		'''
		mengembalikan 1/x modulo self.mod, O(log mod)
		prekondisi: 0 <= x < self.mod
		memanfaatkan fermat's little theorem
		'''
		return self.__mod_pow(x, self.mod - 2)

	def __point_add(self, p: Tuple[int, int], q: Tuple[int, int]) -> Tuple[int, int]:
		'''
		mengembalikan penjumlahan dua titik (p dan q) di kurva elliptik, O(1)
		'''
		if p[0] != q[0]:
			m = ((p[1] - q[1]) % self.mod) * self.__mod_inv((p[0] - q[0]) % self.mod) % self.mod
			x = (m*m - p[0] - q[0]) % self.mod
			y = (m * (p[0] - x) - p[1]) % self.mod
			assert y*y % self.mod == (x*x*x + self.eq_a*x + self.eq_b) % self.mod, "(x, y) = ({}, {})".format(x, y)
			return (x, y)
		else:
			# harusnya di kasus ini p = q
			l = ((3 * p[0] * p[0] + self.eq_a) % self.mod) * self.__mod_inv(2 * p[1] % self.mod) % self.mod
			x = (l*l - 2*p[0]) % self.mod
			y = (l * (p[0] - x) - p[1]) % self.mod
			assert y*y % self.mod == (x*x*x + self.eq_a*x + self.eq_b) % self.mod, "(x, y) = ({}, {})".format(x, y)
			return (x, y) 

	def __point_scalar_prod(self, p: tuple[int, int], k: int) -> Tuple[int, int]:
		'''
		mengembalikan hasil perkalian skalar k dengan titik p di kurva elliptik, O(log k)
		prekondisi: k > 1
		kata paper (link di bawah), k yang dipake antara 1 sampai mod-1 aja, jadi harusnya gaperlu identitas
		https://informatika.stei.itb.ac.id/~rinaldi.munir/Kriptografi/2020-2021/ECC-paper.pdf
		'''
		ret = p
		k -= 1
		while k > 0:
			if k % 2 == 1:
				ret = self.__point_add(ret, p)
			p = self.__point_add(p, p)
			k /= 2
		return ret

	def __encrypt_one_char(self, c: str, public_key: tuple[int, int]) -> Tuple[Tuple[int, int], Tuple[int, int]]:
		'''
		mengembalikan pasangan titik hasil enkripsi satu huruf c
		'''
		pc = self.char_to_point[c]
		k = random.randint(1, self.mod - 1) # kata paper (link di atas) k = 0 gausah dihandle
		p1 = self.__point_scalar_prod(self.base, k)
		p2 = self.__point_add(pc, self.__point_scalar_prod(public_key, k))
		return (p1, p2)

	def __decrypt_one_char(self, c: Tuple[Tuple[int, int], Tuple[int, int]], private_key: int) -> str:
		'''
		mengembalikan karakter hasil dekripsi satu titik c
		'''
		p1 = c[0]
		p2 = c[1]
		sub = self.__point_scalar_prod(c[0], private_key)
		sub = (sub[0], -sub[1] % self.mod) # invers titik dibuat dengan mengalikan ordinat dengan -1
		p = self.__point_add(p2, sub)
		return self.point_to_char[p]

	def generate_public_key(self, private_key: int) -> Tuple[int, int]:
		'''
		menghasilkan public key dari private_key
		public key berupa titik di kurva elliptik
		'''
		return self.__point_scalar_prod(self.base, private_key)

	def generate_random_key_pair(self) -> Tuple[int, Tuple[int, int]]:
		'''
		menghasilkan pasangan (kunci privat, kunci publik acak)
		kunci privat berupa bilangan bulat
		kunci publik berupa titik di kurva elliptik
		'''
		private_key = random.randint(1, self.mod - 1) # kata paper (link di atas) k = 0 gausah dihandle
		public_key = self.generate_public_key(private_key)
		return (private_key, public_key)

	def encrypt(self, plaintext: str, public_key: tuple[int, int]) -> List[Tuple[Tuple[int, int], Tuple[int, int]]]:
		'''
		mengembalikan cipherteks hasil enkripsi plaintext dengan kunci public_key
		cipherteks berisi pasangan titik untuk setiap huruf
		'''
		ciphertext = []
		for i, c in enumerate(plaintext):
			ciphertext.append(self.__encrypt_one_char(c, public_key))
		return ciphertext

	def decrypt(self, ciphertext: List[Tuple[Tuple[int, int], Tuple[int, int]]], private_key: int) -> str:
		'''
		mengembalikan plainteks hasil dekripsi ciphertext dengan kunci private_key
		'''
		plaintext = ""
		for cs in ciphertext:
			plaintext += self.__decrypt_one_char(cs, private_key)
		return plaintext

if __name__ == "__main__":
	ecc = ECC(9, 7, 2011) # kurva elliptik y**2 = x**3 + 9x + 7 (mod 2011)
	plaintext = "Semoga nilai kriptografi IF4020 A amiin"
	private_key = 4
	public_key = ecc.generate_public_key(private_key)
	ciphertext = ecc.encrypt(plaintext, public_key)
	print("hasil encrypt:", ciphertext)
	print("hasil decrypt:", ecc.decrypt(ciphertext, private_key))