"""module for encrypting and dectrypting messages"""
import random
import os


class Encrypting:
    """encrypts and decrypts messages"""

    # initialize dictioary of possible characters
    dictionary = {}
    block_size = None

    def __init__(self):
        self.n, self.e, self.eul = self._generate_public_key()
        self.__d = self.euclidean_algorithm(self.eul, self.e)[2] % self.eul
        self._create_dictionary()

    def _create_dictionary(self) -> None:
        """creates a dictionary with all the possible characters"""
        char_string = (
            " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?-+/()<>:;%&`'*@$#=[]"
            + '"'
            + "абвгґдеєжзиіїйклмнопрстуфхцчшщьюяАБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
        )
        Encrypting.dictionary = {
            char_string[i]: str(i).rjust(3, "0") for i in range(len(char_string))
        }

    def _find_block_size(self, num: int) -> None:
        block_size = 1
        for i in range(1, num):
            if int("154" * i) <= num and num < int("154" * (i + 1)):
                block_size = i
                break
        block_size *= 3
        Encrypting.block_size = block_size

    def _generate_public_key(self) -> tuple:
        """generates public key

        Returns:
            tuple: of n and e for public key and eul for calculating private key
        """
        p = self._use_prime()
        q = self._use_prime()
        self.n = p * q
        eul = (p - 1) * (q - 1)
        self.e = self._find_relatively_prime(eul)
        return self.n, self.e, eul

    def get_keys(self):
        return (self.n, self.e), (self.n, self.__d)

    # def get_public_key(self):
    #     return self.n, self.e

    # def get_private_key(self):
    #     return self.__d

    def encrypt_message(self, message: str, public_key=None) -> str:
        """encrypts a message

        Args:
            message (str): message from user

        Returns:
            list: list of encrypted blocks
        """
        public_key = public_key or (self.n, self.e)
        encrypted_str = "".join(map(lambda x: Encrypting.dictionary[x], message))

        self._find_block_size(public_key[0])
        encrypted_str = encrypted_str + "0" * (
            Encrypting.block_size - (len(encrypted_str) % Encrypting.block_size)
        )
        encrypted_msg = []
        for i in range(len(encrypted_str) // int(Encrypting.block_size)):
            encrypted_msg.append(
                self._encrypt_block(
                    encrypted_str[
                        i
                        * int(Encrypting.block_size) : (i + 1)
                        * int(Encrypting.block_size)
                    ],
                    public_key,
                )
            )
        return " ".join(map(lambda x: str(x), encrypted_msg))

    def decrypt_message(self, encrypted_msg: str, private_key=None) -> str:
        """decrypts a message

        Args:
            encrypted_msg (list): list of encrypted blocks

        Returns:
            str: decrypted message
        """
        private_key = private_key or (self.n, self.__d)
        reverse_dicitonary = {v: k for k, v in Encrypting.dictionary.items()}
        decrypted_msg = []
        encrypted_msg = encrypted_msg.split("~")[-1].split()
        self._find_block_size(private_key[0])
        for block in encrypted_msg:
            decrypted_msg.append(self._decrypt_block(block, private_key))
        for i in range(len(decrypted_msg)):
            decrypted_msg[i] = str(decrypted_msg[i]).rjust(Encrypting.block_size, "0")
        decrypted_msg = "".join(decrypted_msg)
        decrypted_str = ""
        for i in range(len(decrypted_msg) // 3):
            decrypted_str += reverse_dicitonary[
                "".join(decrypted_msg[i * 3 : (i + 1) * 3])
            ]

        return decrypted_str.lstrip(" ")

    def _decrypt_block(self, block: str, cipher_key) -> int:
        """decrypts a block of encrypted message

        Args:
            block (str): encrypted block via rsa

        Returns:
            int: decrypted block
        """
        return self.exponensial_modular(int(block), cipher_key[1], cipher_key[0])

    def _encrypt_block(self, block: str, cipher_key) -> int:
        """encrypts a block of message

        Args:
            block (str): block of message

        Returns:
            int: encrypted block via rsa
        """
        return self.exponensial_modular(int(block), cipher_key[1], cipher_key[0])

    @staticmethod
    def exponensial_modular(base: int, exponent: int, modulus: int) -> int:
        """exponensial modular

        Args:
            base (int): base of exponensial
            exponent (int): exponent of exponensial
            modulus (int): modulus of exponensial equation

        Returns:
            int: result of exponensial modular
        """
        result = 1
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent >> 1
            base = (base * base) % modulus
        return result

    @staticmethod
    def _use_prime() -> int:
        """generates a prime number"""
        primes = []
        list_primes = []
        current_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(current_dir, "primes.txt"), "r") as csvfile:
            primes = csvfile.readlines()
            for row in primes:
                list_primes.extend(list(map(int, row[:-1].split("\t"))))
        return random.choice(list_primes)

    @staticmethod
    def _find_relatively_prime(num: int) -> int:
        """finds a relatively prime number"""
        for i in range(2, num):
            rel_prime = True
            for j in range(2, i + 1):
                if i % j == 0 and num % j == 0:
                    rel_prime = False
                    break
            if rel_prime:
                return i
        print("No relatively prime number found")

    @staticmethod
    def euclidean_algorithm(a: int, b: int) -> tuple:
        """euclidean algorithm

        Args:
            a (int): number
            b (int): number

        Returns:
            tuple: gcd and coeficients of a and b for gcd
        """
        if a == 0:
            return b, 0, 1
        else:
            g, x, y = Encrypting.euclidean_algorithm(b % a, a)
            return g, y - (b // a) * x, x


if __name__ == "__main__":
    sys = Encrypting()
    public, private = sys.get_keys()
    encoded = sys.encrypt_message("Hey, my name is Paul", public)
    print("Encrypted message with rsa:", encoded)
    print(sys.decrypt_message(encoded, private))
