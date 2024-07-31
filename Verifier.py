from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os

class SimpleSigner:
    def __init__(self, identity):
        self.identity = identity  # Store the identity of the signer
        self.key = None  # Placeholder for the RSA private key
        self.public_key = None  # Placeholder for the RSA public key

    def generate_keys(self):
        self.key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
        self.public_key = self.key.publickey()  # Extract the public key

    def save_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'wb') as f:
            f.write(self.key.export_key())  # Save the private key to a file
        with open(public_key_file, 'wb') as f:
            f.write(self.public_key.export_key())  # Save the public key to a file

    def load_keys(self, private_key_file, public_key_file):
        with open(private_key_file, 'rb') as f:
            self.key = RSA.import_key(f.read())  # Load the private key from a file
        with open(public_key_file, 'rb') as f:
            self.public_key = RSA.import_key(f.read())  # Load the public key from a file

    def sign(self, data):
        message = self.identity.encode() + data  # Concatenate the identity with the data
        h = SHA256.new(message)  # Create a SHA-256 hash of the message
        signature = pkcs1_15.new(self.key).sign(h)  # Sign the hash with the private key
        return signature  # Return the signature

    def verify(self, identity, data, signature):
        message = identity.encode() + data  # Concatenate the identity with the data
        h = SHA256.new(message)  # Create a SHA-256 hash of the message
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)  # Verify the signature with the public key
            return True  # Return True if verification is successful
        except (ValueError, TypeError):
            return False  # Return False if verification fails

    @staticmethod
    def aggregate_signatures(signatures):
        return b''.join(signatures)  # Concatenate all signatures into one aggregate signature

    @staticmethod
    def verify_aggregate(identities, data, aggregate_signature, public_keys):
        signature_len = len(aggregate_signature) // len(public_keys)  # Calculate the length of each individual signature
        for i, pub_key in enumerate(public_keys):
            message = identities[i].encode() + data  # Concatenate the identity with the data
            message_hash = SHA256.new(message)  # Create a SHA-256 hash of the message
            signature_part = aggregate_signature[i * signature_len:(i + 1) * signature_len]  # Extract the corresponding part of the aggregate signature
            try:
                pkcs1_15.new(pub_key).verify(message_hash, signature_part)  # Verify the part of the aggregate signature
            except (ValueError, TypeError):
                return False  # Return False if any part fails verification
        return True  # Return True if all parts are successfully verified

def main():
    signers = []  # List to hold all signer objects
    public_keys = []  # List to hold all public keys
    signatures = []  # List to hold all signatures

    num_signers = int(input("Enter the number of signers: "))  # Ask for the number of signers

    for i in range(num_signers):
        identity = input(f"Enter identity for signer {i+1}: ")  # Ask for the identity of each signer
        signer = SimpleSigner(identity)  # Create a new signer object
        signer.generate_keys()  # Generate RSA keys for the signer
        signer.save_keys(f'private_key{i+1}.pem', f'public_key{i+1}.pem')  # Save the keys to files
        signer.load_keys(f'private_key{i+1}.pem', f'public_key{i+1}.pem')  # Load the keys from files
        signers.append(signer)  # Add the signer to the list
        public_keys.append(signer.public_key)  # Add the public key to the list

    data = input("Enter the data to be signed: ").encode()  # Ask for the data to be signed and encode it to bytes

    for signer in signers:
        signature = signer.sign(data)  # Each signer signs the data
        signatures.append(signature)  # Add the signature to the list

    aggregate_signature = SimpleSigner.aggregate_signatures(signatures)  # Aggregate all signatures into one

    identities = [signer.identity for signer in signers]  # List of identities of all signers
    is_valid = SimpleSigner.verify_aggregate(identities, data, aggregate_signature, public_keys)  # Verify the aggregate signature
    
    if is_valid:
        print("Aggregate signature valid:", is_valid)  # Print if the aggregate signature is valid
    else:
        print("Aggregate signature valid:", is_valid)  # Print if the aggregate signature is not valid

if __name__ == "__main__":
    main()  # Execute the main function if the script is run directly
