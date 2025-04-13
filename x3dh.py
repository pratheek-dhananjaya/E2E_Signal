# x3dh.py
from crypto_utils import generate_dh_keypair, dh_exchange, hkdf

class PreKeyBundle:
    def __init__(self, identity_key, signed_prekey, one_time_prekey=None):
        self.identity_key = identity_key          # IK_B
        self.signed_prekey = signed_prekey        # SPK_B
        self.one_time_prekey = one_time_prekey    # OPK_B (optional)

def compute_x3dh_shared_secret(
    alice_identity_priv, alice_ephemeral_priv,
    bob_prekey_bundle,
    bob_identity_pub,   # IK_B
    bob_signed_prekey,  # SPK_B
    bob_one_time_prekey=None  # OPK_B (optional)
):
    # DH1: DH(IK_A, SPK_B)
    dh1 = dh_exchange(alice_identity_priv, bob_signed_prekey)

    # DH2: DH(EK_A, IK_B)
    dh2 = dh_exchange(alice_ephemeral_priv, bob_identity_pub)

    # DH3: DH(EK_A, SPK_B)
    dh3 = dh_exchange(alice_ephemeral_priv, bob_signed_prekey)

    # DH4 (optional): DH(EK_A, OPK_B)
    if bob_one_time_prekey:
        dh4 = dh_exchange(alice_ephemeral_priv, bob_one_time_prekey)
        combined = dh1 + dh2 + dh3 + dh4
    else:
        combined = dh1 + dh2 + dh3

    # Derive session key using HKDF
    session_key = hkdf(combined, info=b"X3DH")
    return session_key
