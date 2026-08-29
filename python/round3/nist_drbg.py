"""
NIST AES-256-CTR DRBG for deterministic KAT generation.

Per NIST SP 800-90A. Used only for test vector generation,
not for production randomness.
"""

from Crypto.Cipher import AES


class NistDRBG:
    """AES-256-CTR DRBG per NIST SP 800-90A."""

    def __init__(self, seed_48bytes):
        self.key = b'\x00' * 32
        self.v = b'\x00' * 16
        self._update(seed_48bytes)
        self.reseed_counter = 1

    def _update(self, provided_data):
        temp = b''
        cipher = AES.new(self.key, AES.MODE_ECB)
        for _ in range(3):
            v_int = int.from_bytes(self.v, 'big') + 1
            self.v = v_int.to_bytes(16, 'big')
            temp += cipher.encrypt(self.v)
        if provided_data:
            temp = bytes(a ^ b for a, b in zip(temp, provided_data))
        self.key = temp[:32]
        self.v = temp[32:48]

    def randombytes(self, num_bytes):
        result = b''
        cipher = AES.new(self.key, AES.MODE_ECB)
        remaining = num_bytes
        while remaining > 0:
            v_int = int.from_bytes(self.v, 'big') + 1
            self.v = v_int.to_bytes(16, 'big')
            block = cipher.encrypt(self.v)
            take = min(16, remaining)
            result += block[:take]
            remaining -= take
        self._update(None)
        self.reseed_counter += 1
        return result[:num_bytes]
