from binascii import hexlify
from hashlib import sha256
from os import urandom
from prime_num import primes


class DiffieHellman:
    # Current minimum recommendation is 2048 bit (group 14)
    def __init__(self, group: int = 14) -> None:
        if group not in primes:
            raise ValueError("Unsupported Group")
        self.prime = primes[group]["prime"]
        self.generator = primes[group]["generator"]

        self.__private_key = int(hexlify(urandom(32)), base=16)

    def get_private_key(self) -> str:
        return hex(self.__private_key)[2:]

    def generate_public_key(self) -> str:
        public_key = pow(self.generator, self.__private_key, self.prime)
        return hex(public_key)[2:]

    def is_valid_public_key(self, key: int) -> bool:
        # check if the other public key is valid based on NIST SP800-56
        if 2 <= key and key <= self.prime - 2:
            if pow(key, (self.prime - 1) // 2, self.prime) == 1:
                return True
        return False

    def generate_shared_key(self, other_key_str: str) -> str:
        other_key = int(other_key_str, base=16)
        if not self.is_valid_public_key(other_key):
            raise ValueError("Invalid public key")
        shared_key = pow(other_key, self.__private_key, self.prime)
        return sha256(str(shared_key).encode()).hexdigest()

    @staticmethod
    def is_valid_public_key_static(
        local_private_key_str: str, remote_public_key_str: str, prime: int
    ) -> bool:
        # check if the other public key is valid based on NIST SP800-56
        if 2 <= remote_public_key_str and remote_public_key_str <= prime - 2:
            if pow(remote_public_key_str, (prime - 1) // 2, prime) == 1:
                return True
        return False

    @staticmethod
    def generate_shared_key_static(
        local_private_key_str: str, remote_public_key_str: str, group: int = 14
    ) -> str:
        local_private_key = int(local_private_key_str, base=16)
        remote_public_key = int(remote_public_key_str, base=16)
        prime = primes[group]["prime"]
        if not DiffieHellman.is_valid_public_key_static(
            local_private_key, remote_public_key, prime
        ):
            raise ValueError("Invalid public key")
        shared_key = pow(remote_public_key, local_private_key, prime)
        return sha256(str(shared_key).encode()).hexdigest()


### testing if dh works ###
alice = DiffieHellman()
bob = DiffieHellman()

alice_private = alice.get_private_key()
alice_public = alice.generate_public_key()

bob_private = bob.get_private_key()
bob_public = bob.generate_public_key()

# generating shared key using the DH object
alice_shared = alice.generate_shared_key(bob_public)
bob_shared = bob.generate_shared_key(alice_public)
assert alice_shared == bob_shared

# generating shared key using static methods
alice_shared = DiffieHellman.generate_shared_key_static(
    alice_private, bob_public)
bob_shared = DiffieHellman.generate_shared_key_static(
    bob_private, alice_public)
#print(alice_shared == bob_shared)
