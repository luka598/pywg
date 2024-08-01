from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib
import hmac

"""
DH(private key, public key): Curve25519 point multiplication of private key and public key, returning 32 bytes of output
DH_GENERATE(): generate a random Curve25519 private key, returning 32 bytes of output
RAND(len): return len random bytes of output
DH_PUBKEY(private key): calculate a Curve25519 public key from private key, returning 32 bytes of output
AEAD(key, counter, plain text, auth text): ChaCha20Poly1305 AEAD, as specified in RFC7539, with its nonce being composed of 32 bits of zeros followed by the 64-bit little-endian value of counter
XAEAD(key, nonce, plain text, auth text): XChaCha20Poly1305 AEAD, with a random 24-byte nonce
AEAD_LEN(plain len): plain len + 16
HMAC(key, input): HMAC-Blake2s(key, input, 32), returning 32 bytes of output
MAC(key, input): Keyed-Blake2s(key, input, 16), returning 16 bytes of output
HASH(input): Blake2s(input, 32), returning 32 bytes of output
TAI64N(): TAI64N timestamp of current time which is 12 bytes
CONSTRUCTION: the UTF-8 value Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, 37 bytes
IDENTIFIER: the UTF-8 value WireGuard v1 zx2c4 Jason@zx2c4.com, 34 bytes
LABEL_MAC1: the UTF-8 value mac1----, 8 bytes
LABEL_COOKIE: the UTF-8 value cookie--, 8 bytes
"""


def DH(private, public):
    priv = x25519.X25519PrivateKey.from_private_bytes(private)
    pub = x25519.X25519PublicKey.from_public_bytes(public)
    return priv.exchange(pub)


def DH_GENERATE():
    return x25519.X25519PrivateKey.generate().private_bytes_raw()


def MY_PASSWD_DH_GENERATE_PAIR(passwd):
    priv = x25519.X25519PrivateKey.from_private_bytes(HASH(passwd))
    pub = priv.public_key()
    return (priv.private_bytes_raw(), pub.public_bytes_raw())


def MY_DH_GENERATE_PAIR():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return (priv.private_bytes_raw(), pub.public_bytes_raw())


def RAND():
    raise NotImplementedError


def DH_PUBKEY(private):
    priv = x25519.X25519PrivateKey.from_private_bytes(private)
    return priv.public_key().public_bytes_raw()


def AEAD(key, counter, plain_text, auth_text):
    nonce = b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plain_text, auth_text)
    return ciphertext


def MY_DECRYPT_AEAD(key, counter, cipher_text, auth_text):
    nonce = b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")
    cipher = ChaCha20Poly1305(key=key)

    try:
        plaintext = cipher.decrypt(nonce, cipher_text, auth_text)
        return plaintext
    except Exception as e:
        raise ValueError("Decryption failed: {}".format(e))


def XAEAD(key, nonce, plain_text, auth_text):
    raise NotImplementedError


def AEAD_LEN(plain_len):
    return plain_len + 16


def HMAC(key, x):
    return hmac.digest(key, x, hashlib.blake2s)


def MAC(key, x):
    return hashlib.blake2s(x, key=key, digest_size=16).digest()


def HASH(x):
    return hashlib.blake2s(x).digest()


def TAI64N():
    raise NotImplementedError


CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".encode("utf-8")
IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".encode("utf-8")
LABEL_MAC1 = "mac1----".encode("utf-8")
LABEL_COOKIE = "cookie--".encode("utf-8")
