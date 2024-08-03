from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.toolbox.IBEnc import IBEnc

class PKG:
    def __init__(self, groupObj):
        self.group = groupObj
        self.g = self.group.random(G1)
        self.master_secret = self.group.random(ZR)
        self.public_key = self.master_secret * self.g

    def extract_private_key(self, identity):
        id_hash = self.group.hash(identity, G1)
        private_key = self.master_secret * id_hash
        return private_key

class IBAS(IBEnc):
    def __init__(self, groupObj):
        IBEnc.__init__(self)
        self.group = groupObj

    def sign(self, private_key, message):
        m_hash = self.group.hash(message, G1)
        signature = private_key * m_hash
        return signature

    def aggregate_signatures(self, signatures):
        agg_signature = self.group.init(G1)
        for sig in signatures:
            agg_signature += sig
        return agg_signature

    def verify(self, public_key, identities, messages, aggregate_signature):
        lhs = pair(aggregate_signature, self.g)
        rhs = self.group.init(G2)
        for i in range(len(identities)):
            id_hash = self.group.hash(identities[i], G1)
            m_hash = self.group.hash(messages[i], G1)
            rhs += pair(public_key, id_hash * m_hash)
        return lhs == rhs
