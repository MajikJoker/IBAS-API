from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os

class SimpleSigner:
    def __init__(self, identity):
        self.identity = identity
        self.key = None
        self.public_key = None

    def generate_keys(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def save_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'wb') as f:
            f.write(self.key.export_key())
        with open(public_key_file, 'wb') as f:
            f.write(self.public_key.export_key())

    def load_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'rb') as f:
            self.key = RSA.import_key(f.read())
        with open(public_key_file, 'rb') as f:
            self.public_key = RSA.import_key(f.read())

    def sign(self, data):
        message = self.identity.encode() + data
        h = SHA256.new(message)
        signature = pkcs1_15.new(self.key).sign(h)
        return signature

    def verify(self, identity, data, signature):
        message = identity.encode() + data
        h = SHA256.new(message)
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def aggregate_signatures(signatures):
        return b''.join(signatures)

    @staticmethod
    def verify_aggregate(identities, data, aggregate_signature, public_keys):
        signature_len = len(aggregate_signature) // len(public_keys)
        for i, pub_key in enumerate(public_keys):
            message = identities[i].encode() + data
            message_hash = SHA256.new(message)
            signature_part = aggregate_signature[i * signature_len:(i + 1) * signature_len]
            try:
                pkcs1_15.new(pub_key).verify(message_hash, signature_part)
            except (ValueError, TypeError):
                return False
        return True

def main():
    signers = []
    public_keys = []
    signatures = []

    num_signers = int(input("Enter the number of signers: "))

    for i in range(num_signers):
        identity = input(f"Enter identity for signer {i+1}: ")
        signer = SimpleSigner(identity)
        signer.generate_keys()
        signer.save_keys(f'private_key{i+1}.pem', f'public_key{i+1}.pem')
        signer.load_keys(f'private_key{i+1}.pem', f'public_key{i+1}.pem')
        signers.append(signer)
        public_keys.append(signer.public_key)

    data = input("Enter the data to be signed: ").encode()

    for signer in signers:
        signature = signer.sign(data)
        signatures.append(signature)

    aggregate_signature = SimpleSigner.aggregate_signatures(signatures)

    identities = [signer.identity for signer in signers]
    is_valid = SimpleSigner.verify_aggregate(identities, data, aggregate_signature, public_keys)
    
    if is_valid:
        print("Aggregate signature valid:", is_valid)
    else:
        print("Aggregate signature valid:", is_valid)

if __name__ == "__main__":
    main()
