import cv2
from hashlib import sha256
from random import randrange, getrandbits


class RSA:
    def power(self, a, d, n):
        ans = 1
        while d != 0:
            if d % 2 == 1:
                ans = ((ans % n) * (a % n)) % n
            a = ((a % n) * (a % n)) % n
            d >>= 1
        return ans

    def MillerRabin(self, N, d):
        a = randrange(2, N - 1)
        x = self.power(a, d, N)
        if x == 1 or x == N - 1:
            return True
        else:
            while (d != N - 1):
                x = ((x % N) * (x % N)) % N
                if x == 1:
                    return False
                if x == N - 1:
                    return True
                d <<= 1
        return False

    def is_prime(self, N, K):
        if N == 3 or N == 2:
            return True
        if N <= 1 or N % 2 == 0:
            return False;

        # Find d such that d*(2^r)=X-1
        d = N - 1
        while d % 2 != 0:
            d /= 2

        for _ in range(K):
            if not self.MillerRabin(N, d):
                return False
        return True

    def generate_prime_candidate(self, length):
        # generate random bits
        p = getrandbits(length)
        # apply a mask to set MSB and LSB to 1
        # Set MSB to 1 to make sure we have a Number of 1024 bits.
        # Set LSB to 1 to make sure we get a Odd Number.
        p |= (1 << length - 1) | 1
        return p

    def generatePrimeNumber(self, length):
        A = 4
        while not self.is_prime(A, 20):
            A = self.generate_prime_candidate(length)
        return A

    def GCD(self, a, b):
        if a == 0:
            return b
        return self.GCD(b % a, a)

    def gcdExtended(self, E, eulerTotient):
        a1, a2, b1, b2, d1, d2 = 1, 0, 0, 1, eulerTotient, E

        while d2 != 1:
            # k
            k = (d1 // d2)

            # a
            temp = a2
            a2 = a1 - (a2 * k)
            a1 = temp

            # b
            temp = b2
            b2 = b1 - (b2 * k)
            b1 = temp

            # d
            temp = d2
            d2 = d1 - (d2 * k)
            d1 = temp

            D = b2

        if D > eulerTotient:
            D = D % eulerTotient
        elif D < 0:
            D = D + eulerTotient

        return D

    def encrypt(self, my_byte_arr, E, N):
        # Step 5: Encryption
        res = int.from_bytes(my_byte_arr, byteorder='big', signed=False)
        res = self.power(res, E, N)
        return self.intToBytes(res)

    def intToBytes(self, num):
        if num == 0:
            return b""
        else:
            return self.intToBytes(num // 256) + bytes([num % 256])

    def decrypt(self, my_byte_arr, D, N):
        res = 0
        res = int.from_bytes(my_byte_arr, byteorder='big', signed=False)
        res = self.power(res, D, N)
        return self.intToBytes(res)

    def generate_keys(self):
        # p and q prime number
        length = 256
        P = self.generatePrimeNumber(length)
        Q = self.generatePrimeNumber(length)

        print('p is:', P)
        print('q is:', Q)

        # Step 2: Calculate N=P*Q and Euler Totient Function = (P-1)*(Q-1)
        # n is a public key

        N = P * Q
        eulerTotient = (P - 1) * (Q - 1)
        print('N is:', N)
        print('eulerTotient is:', eulerTotient)

        # Step 3: Find E such that GCD(E,eulerTotient)=1(i.e., e should be co-prime) such that it satisfies this condition:-  1<E<eulerTotient

        # GCD(E,eulerTotient)=1
        E = self.generatePrimeNumber(4)
        while self.GCD(E, eulerTotient) != 1:
            E = self.generatePrimeNumber(4)
        print('E is:', E)

        # Step 4: Find D- private key.
        # For Finding D: It must satisfies this property:-  (D*E)Mod(eulerTotient)=1;
        # For Finding D we can Use Extended Euclidean Algorithm: ax+by=1 i.e., eulerTotient(x)+E(y)=GCD(eulerTotient,e)

        D = self.gcdExtended(E, eulerTotient)
        print('d is:', D)

        return N, E, D

    def hash(self, msg):
        return sha256(msg).digest()

    def verify(self, sig, msg, E, N):
        sig_num = int.from_bytes(sig, byteorder='big', signed=False)
        a = self.power(sig_num, E, N)
        return self.intToBytes(a) == self.hash(msg)

    def sign(self, msg, D, N):
        byte_arr = self.hash(msg)
        t = int.from_bytes(byte_arr, byteorder='big', signed=False)
        return self.intToBytes(self.power(t, D, N))

    def test(self):
        # rsa('123456789'.encode())

        N, E, D = self.generate_keys()

        byte_arr = b'12345678911111111234567891111111'

        print('input:', byte_arr)

        encrypted_arr = self.encrypt(byte_arr, E, N)

        print('encryption:', encrypted_arr)

        decryption_arr = self.decrypt(encrypted_arr, D, N)

        print('decryption:', decryption_arr)

        print('verify: ', decryption_arr == byte_arr)

        N, E, D = self.generate_keys()

        byte_arr = sha256(b'123451651789').digest()

        print('input:', byte_arr)

        encrypted_arr = self.encrypt(byte_arr, E, N)

        print('encryption:', encrypted_arr)

        decryption_arr = self.decrypt(encrypted_arr, D, N)

        print('decryption:', decryption_arr)

        print('verify:', decryption_arr == byte_arr)

    def test2(self):
        # rsa('123456789'.encode())

        N, E, D = self.generate_keys()

        byte_arr = b'1'

        print('input:', byte_arr)

        signature = self.sign(byte_arr, D, N)

        print('signature:', signature)

        verify = self.verify(signature, byte_arr, E, N)

        print('Verification: ', verify)


myrsa = RSA()
myrsa.test2()
