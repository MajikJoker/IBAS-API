from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hashlib

# Helper function to hash an identity
def hash_identity(identity: str):
    return hashlib.sha256(identity.encode()).digest()

# PKG Class to generate master secret key (MSK) and derive private keys
class PKG:
    def __init__(self):
        # Generate Master Secret Key (MSK)
        self.msk = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.msk.public_key()
    
    def generate_private_key(self, identity: str):
        # Hash the identity to generate a point on the curve
        identity_hash = hash_identity(identity)
        identity_point = ec.derive_private_key(int.from_bytes(identity_hash, 'big'), ec.SECP256R1(), default_backend())
        
        # Obtain the order of the curve
        curve_order = self.msk.private_numbers().private_value.curve.curve.order

        # Derive the user's private key using MSK and curve order
        private_key_value = (self.msk.private_numbers().private_value * identity_point.private_numbers().private_value) % curve_order
        private_key = ec.derive_private_key(private_key_value, ec.SECP256R1(), default_backend())
        
        return private_key

# The rest of the implementation remains the same

# Example usage
pkg = PKG()

# Generate private keys for users based on their identities
private_key_user1 = pkg.generate_private_key("user1@example.com")
private_key_user2 = pkg.generate_private_key("user2@example.com")

# Users sign their messages
user1 = User("user1@example.com", private_key_user1)
user2 = User("user2@example.com", private_key_user2)

message1 = "Hello from user1"
message2 = "Hello from user2"

signature1 = user1.sign_message(message1)
signature2 = user2.sign_message(message2)

# Aggregate signatures
aggregated_signature = aggregate_signatures([signature1, signature2])

# Verify the aggregated signature
is_valid = verify_aggregated_signature(aggregated_signature, pkg.public_key, ["user1@example.com", "user2@example.com"], [message1, message2])

print(f"Is the aggregated signature valid? {is_valid}")
