# lnutils.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Secret

import hmac
import hashlib
from mnemonic import Mnemonic
import bip32utils

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1,
    ECDSA,
    derive_private_key,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from gi.repository import Gio

SECRET_STORE_SCHEMA = Secret.Schema.new("one.k8ie.Voucher.seeds",
    Secret.SchemaFlags.NONE,
    {
        "label": Secret.SchemaAttributeType.STRING
    }
)

def generate_key(label: str, settings: Gio.Settings) -> None:
    mnemo = Mnemonic("english").generate(strength=256)
    Secret.password_store_sync(SECRET_STORE_SCHEMA, {"label": label}, Secret.COLLECTION_DEFAULT, label, mnemo, None)
    # TODO: Don't overwrite the whole list
    settings.set_strv("identities", [label])


def derive_lnurl_master_key(label: str) -> bytes:
    """
    Derive the LNURL-auth master key from a BIP-39 mnemonic.
    Uses BIP-32 derivation path m/138'/0 as per the LNURL-auth spec.
    """
    seed = Mnemonic.to_seed(Secret.password_lookup_sync(SECRET_STORE_SCHEMA, {"label": label}, None))

    # Derive the root key from the seed
    root_key = bip32utils.BIP32Key.fromEntropy(seed)

    # Derive m/138'/0 (138' is hardened, as per LNURL-auth spec)
    lnurl_master = root_key.ChildKey(138 + bip32utils.BIP32_HARDEN).ChildKey(0)

    return lnurl_master.PrivateKey()


def derive_domain_key(master_key: bytes, domain: str) -> EllipticCurvePrivateKey:
    """
    Derive a domain-specific private key using HMAC-SHA256.
    The master key is the HMAC secret, the domain is the message.
    The resulting 32 bytes are used directly as a SECP256K1 private key.
    """
    domain_key_bytes = hmac.new(
        key=master_key,
        msg=domain.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()

    # Convert the 32 raw bytes into a SECP256K1 private key
    private_key = derive_private_key(
        int.from_bytes(domain_key_bytes, byteorder="big"),
        SECP256K1(),
        default_backend(),
    )

    return private_key


def get_public_key_hex(private_key: EllipticCurvePrivateKey) -> str:
    """Get the compressed public key in hex (this is your linking key for the domain)."""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    ).hex()


def der_to_low_s_der(der_sig: bytes) -> bytes:
    """
    Convert a DER-encoded signature to a 64-byte compact signature.
    Each of r and s is zero-padded to 32 bytes.
    """
    SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    SECP256K1_HALF_N = SECP256K1_N // 2
    r, s = decode_dss_signature(der_sig)
    if s > SECP256K1_HALF_N:
        s = SECP256K1_N - s
    return encode_dss_signature(r, s)

def sign_k1(k1_hex: str, domain: str) -> str:
    """
    Sign the k1 challenge provided by the LNURL-auth service.
    k1 is a 32-byte hex string provided by the service.
    Returns the DER-encoded signature as hex.
    """
    master_key = derive_lnurl_master_key("key 1")
    domain_key = derive_domain_key(master_key, domain)
    pub_key_hex = get_public_key_hex(domain_key)

    k1_bytes = bytes.fromhex(k1_hex)
    signature = domain_key.sign(k1_bytes, ECDSA(Prehashed(hashes.SHA256())))
    signature_tweaked = der_to_low_s_der(signature)
    return (signature_tweaked.hex(), pub_key_hex)
