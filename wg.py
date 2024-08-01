import socket
import struct
import base64
import itertools
from typing import Any, Optional

from scapy.all import IP, send

from wg_utils import (
    DH,
    CONSTRUCTION,
    IDENTIFIER,
    HASH,
    MAC,
    HMAC,
    LABEL_MAC1,
    MY_PASSWD_DH_GENERATE_PAIR,
    MY_DH_GENERATE_PAIR,
    AEAD,
    MY_DECRYPT_AEAD,
)

PASSWD = "kita"
PRIVATE_KEY, PUBLIC_KEY = MY_PASSWD_DH_GENERATE_PAIR(PASSWD.encode("utf-8"))


class State:
    SAVED_STATES = {}
    B_INDEX_GENERATOR = itertools.count()

    def __init__(self):
        self.A_static_public: Any = None
        self.B_static_public = PUBLIC_KEY

        self.A_ephemeral_private: Any = None
        self.A_ephemeral_public: Any = None
        self.B_ephemeral_private, self.B_ephemeral_public = MY_DH_GENERATE_PAIR()

        self.A_index: Any = None
        self.B_index = next(self.B_INDEX_GENERATOR)

        self.preshared_key = b"\x00" * 32

        self.chaining_key = HASH(CONSTRUCTION)
        self.hash = HASH(HASH(self.chaining_key + IDENTIFIER) + self.B_static_public)

        self.sending_key: Any = None
        self.receiving_key: Any = None
        self.sending_key_counter = 0
        self.receiving_key_counter = 0

    def save(self):
        self.SAVED_STATES[self.B_index] = self

    @staticmethod
    def recover(B_index: int) -> Optional["State"]:
        if B_index not in State.SAVED_STATES:
            raise RuntimeError(f"State with recieving index {B_index} not found!")
        return State.SAVED_STATES[B_index]


def parse_type_1(data):
    p, mac1, mac2 = struct.unpack("<116s16s16s", data)
    print(p, mac1, mac2)
    assert mac1 == MAC(HASH(LABEL_MAC1 + PUBLIC_KEY), p)
    assert mac2 == b"\x00" * 16
    (
        message_type,
        sender_index,
        unencrypted_ephemeral,
        encrypted_static,
        encrypted_timestamp,
        mac1,
        mac2,
    ) = struct.unpack("<BxxxI32s48s28s16s16s", data)

    # Creating initiator
    state = State()
    state.save()

    state.A_index = sender_index

    state.A_ephemeral_public = unencrypted_ephemeral
    state.hash = HASH(state.hash + unencrypted_ephemeral)

    temp = HMAC(state.chaining_key, unencrypted_ephemeral)
    state.chaining_key = HMAC(temp, b"\x01")

    temp = HMAC(state.chaining_key, DH(PRIVATE_KEY, unencrypted_ephemeral))
    state.chaining_key = HMAC(temp, b"\x01")
    key = HMAC(temp, state.chaining_key + b"\x02")

    state.A_static_public = MY_DECRYPT_AEAD(key, 0, encrypted_static, state.hash)
    state.hash = HASH(state.hash + encrypted_static)

    temp = HMAC(state.chaining_key, DH(PRIVATE_KEY, state.A_static_public))
    state.chaining_key = HMAC(temp, b"\x01")
    key = HMAC(temp, state.chaining_key + b"\x02")

    timestamp = MY_DECRYPT_AEAD(key, 0, encrypted_timestamp, state.hash)
    state.hash = HASH(state.hash + encrypted_timestamp)

    return construct_type_2(state)


def construct_type_2(state: State) -> bytes:
    message_type = 2
    sender_index = state.B_index
    receiver_index = state.A_index

    unencrypted_ephemeral = state.B_ephemeral_public
    state.hash = HASH(state.hash + unencrypted_ephemeral)

    temp = HMAC(state.chaining_key, unencrypted_ephemeral)
    state.chaining_key = HMAC(temp, b"\x01")

    temp = HMAC(
        state.chaining_key,
        DH(state.B_ephemeral_private, state.A_ephemeral_public),
    )
    state.chaining_key = HMAC(temp, b"\x01")

    temp = HMAC(
        state.chaining_key, DH(state.B_ephemeral_private, state.A_static_public)
    )
    state.chaining_key = HMAC(temp, b"\x01")

    temp = HMAC(state.chaining_key, state.preshared_key)
    state.chaining_key = HMAC(temp, b"\x01")
    temp2 = HMAC(temp, state.chaining_key + b"\x02")
    key = HMAC(temp, temp2 + b"\x03")
    state.hash = HASH(state.hash + temp2)

    encrypted_nothing = AEAD(key, 0, b"", state.hash)
    state.hash = HASH(state.hash + encrypted_nothing)

    msg = struct.pack(
        "<III32s16s",
        message_type,
        sender_index,
        receiver_index,
        unencrypted_ephemeral,
        encrypted_nothing,
    )
    msg = msg + MAC(HASH(b"mac1----" + state.A_static_public), msg) + b"\x00" * 16

    temp1 = HMAC(state.chaining_key, b"")
    temp2 = HMAC(temp1, b"\x01")
    temp3 = HMAC(temp1, temp2 + b"\x02")
    state.receiving_key = temp2
    state.sending_key = temp3
    state.receiving_key_counter = 0
    state.sending_key_counter = 0

    return msg


def parse_type_4(data) -> bytes:
    (message_type, receiver_index, counter) = struct.unpack_from("BxxxIQ", data)
    encrypted_encapsulated_packet = data[struct.calcsize("BxxxIQ") :]

    if (state := State.recover(receiver_index)) is None:
        return b""

    print(message_type, receiver_index, counter)
    state.receiving_key_counter += 1
    encapsulated_packet = MY_DECRYPT_AEAD(
        state.receiving_key, counter, encrypted_encapsulated_packet, b""
    )
    print(IP(encapsulated_packet))

    return b""


def parse_packet(data) -> bytes:
    message_type = struct.unpack("<B", data[:1])[0]
    print(f">>> {message_type}, {len(data)} bytes")
    if message_type == 1:
        return parse_type_1(data)
    elif message_type == 4:
        parse_type_4(data)
        return b""
    else:
        print("UNKNOWN PACKET!")
        return b""


print("======== PEER CONFIG ========")
print("Public key:", base64.b64encode(PUBLIC_KEY).decode())
print("Endpoint:" "?.?.?.?:????")
print("=============================")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9000))

while True:
    data, src = sock.recvfrom(1024)
    print(f"[{src[0]}:{src[1]}] >>> {len(data)} bytes")
    response = parse_packet(data)
    if len(response) > 0:
        sock.sendto(response, src)
        print(f"[{src[0]}:{src[1]}] <<< {len(response)} bytes")
