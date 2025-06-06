# blockchain_core.py
import time
import json
import base64
import math
import hashlib
import uuid

# NEW: Import the BFT threshold function
from byzantine_fault_tolerant import get_bft_endorsement_threshold

# --- Part 1: Cryptographic Primitives & Wallet (Simulated) ---

def cryptographic_hash(data):
    """
    Computes the SHA-256 hash of data.
    """
    if isinstance(data, dict):
        data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    elif isinstance(data, list):
        if all(isinstance(item, dict) for item in data) and len(data) > 0:
            try:
                data_str = json.dumps(sorted(data, key=lambda x: (x.get('timestamp', 0), x.get('sender', ''), json.dumps(x, sort_keys=True, separators=(',', ':')))), separators=(',', ':'))
            except TypeError:
                data_str = json.dumps(data, separators=(',', ':'))
        else:
            data_str = json.dumps(data, separators=(',', ':'))
    else:
        data_str = str(data)

    data_bytes = data_str.encode('utf-8')
    return hashlib.sha256(data_bytes).hexdigest()

simple_hash = cryptographic_hash

class Wallet:
    """
    Simulated Wallet for a blockchain participant.
    """
    def __init__(self, owner_id):
        self.owner_id = owner_id
        self._private_key = f"PRIVATE_KEY_{owner_id}_{str(uuid.uuid4())[:8]}"
        self.public_key = f"PUBLIC_KEY_{owner_id}_{str(uuid.uuid4())[:8]}"
        print(f"Wallet created for {owner_id}: Public Key: {self.public_key}")

    @property
    def private_key(self):
        return self._private_key

    def sign_message(self, message_hash):
        """
        Simulates signing a message hash with the private key.
        """
        return simple_hash(f"{message_hash}-{self._private_key}")


# --- Simulated Encryption/Decryption Functions ---

def simulate_encrypt(data, encryption_key):
    """Simulates encrypting data."""
    if not isinstance(data, str):
        data = json.dumps(data)
    encrypted_bytes = base64.b64encode(data.encode('utf-8'))
    return f"ENC:{encryption_key}:{encrypted_bytes.decode('utf-8')}"

def simulate_decrypt(encrypted_data, decryption_key):
    """Simulates decrypting data."""
    if not encrypted_data.startswith("ENC:"):
        return encrypted_data
    parts = encrypted_data.split(':', 2)
    if len(parts) < 3: return None
    stored_key = parts[1]
    base64_encoded_data = parts[2]
    if stored_key != decryption_key:
        print(f"Decryption failed: Provided key '{decryption_key}' does not match stored key '{stored_key}'.")
        return None
    try:
        decoded_bytes = base64.b64decode(base64_encoded_data.encode('utf-8'))
        try: return json.loads(decoded_bytes.decode('utf-8'))
        except json.JSONDecodeError: return decoded_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error during simulated decryption: {e}")
        return None


# --- Part 2: Transaction ---

class Transaction:
    def __init__(self, sender, recipient, amount, timestamp=None, data=None, is_encrypted=False, tx_type="standard"):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.data = data if data is not None else {}
        self.signature = None
        self.is_encrypted = is_encrypted
        self.tx_type = tx_type

    def to_dict(self):
        """Converts transaction data to a dictionary for hashing/serialization."""
        return {
            'sender': self.sender, 'recipient': self.recipient, 'amount': self.amount,
            'timestamp': self.timestamp, 'data': self.data,
            'is_encrypted': self.is_encrypted, 'tx_type': self.tx_type
        }

    @classmethod
    def from_dict(cls, data_dict):
        """Creates a Transaction object from a dictionary."""
        tx = cls(data_dict['sender'], data_dict['recipient'], data_dict['amount'],
                 data_dict['timestamp'], data_dict.get('data', {}),
                 data_dict.get('is_encrypted', False), data_dict.get('tx_type', 'standard'))
        tx.signature = data_dict.get('signature')
        return tx

    def calculate_hash(self):
        """Calculates a hash of the transaction data."""
        temp_dict = self.to_dict()
        temp_dict.pop('signature', None)
        return simple_hash(temp_dict)

    def sign(self, wallet_private_key):
        """Simulates signing the transaction."""
        self.signature = simple_hash(f"{self.calculate_hash()}-{wallet_private_key}")
        print(f"Transaction signed by {self.sender}. Simulated Signature: {self.signature[:10]}...")

    def is_valid_signature(self, sender_public_key):
        """Simulates signature validation."""
        if not self.signature: return False
        return self.sender in sender_public_key and self.signature is not None


# --- Part 3: Block ---

class Block:
    def __init__(self, index, transactions, previous_hash, miner, timestamp=None, nonce=0):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.miner = miner
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.nonce = nonce
        self.current_hash = self.calculate_hash()

    def to_dict(self):
        """Converts block data to a dictionary for hashing/serialization."""
        transaction_dicts = [tx.to_dict() for tx in self.transactions]
        return {
            'index': self.index, 'transactions': transaction_dicts, 'previous_hash': self.previous_hash,
            'miner': self.miner, 'timestamp': self.timestamp, 'nonce': self.nonce
        }

    @classmethod
    def from_dict(cls, data_dict):
        """Creates a Block object from a dictionary."""
        transactions = [Transaction.from_dict(tx_data) for tx_data in data_dict['transactions']]
        block = cls(data_dict['index'], transactions, data_dict['previous_hash'],
                    data_dict['miner'], data_dict['timestamp'], data_dict['nonce'])
        block.current_hash = data_dict['current_hash']
        return block

    def calculate_hash(self):
        """Calculates the hash of the block."""
        temp_dict = self.to_dict()
        if 'transactions' in temp_dict and all(isinstance(item, dict) for item in temp_dict['transactions']):
            temp_dict['transactions'] = sorted(temp_dict['transactions'], key=lambda x: (x.get('timestamp',0), x.get('sender',''), json.dumps(x, sort_keys=True, separators=(',', ':'))))
        return simple_hash(temp_dict)


# --- Part 4: Blockchain (Ledger) ---

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.participating_organizations = {}
        self.policies = {}
        self.authorized_miners = set()
        self.proposed_blocks = {}
        self.current_state = {}
        self.create_genesis_block()

    @property
    def last_block(self):
        return self.chain[-1]

    def create_genesis_block(self):
        genesis_block = Block(0, [], "0", miner="System")
        self.chain.append(genesis_block)
        print("Genesis block created.")

    def is_miner_authorized(self, miner_address):
        return miner_address in self.authorized_miners

    def add_authorized_miner(self, miner_address):
        if miner_address not in self.authorized_miners:
            self.authorized_miners.add(miner_address)
            print(f"Miner '{miner_address}' added to authorized list.")
        else:
            print(f"Miner '{miner_address}' is already authorized.")
    
    def remove_authorized_miner(self, miner_address):
        if miner_address in self.authorized_miners:
            self.authorized_miners.remove(miner_address)
            print(f"Miner '{miner_address}' removed from authorized list.")
            return True
        return False

    def get_endorsement_threshold(self):
        """
        Returns the endorsement threshold based on the BFT calculation.
        """
        return get_bft_endorsement_threshold(len(self.authorized_miners))

    def add_transaction(self, transaction):
        if not isinstance(transaction, Transaction):
            print("Error: Provided object is not a Transaction instance.")
            return False
        
        sender_public_key = self.get_organization_public_key(transaction.sender)
        if not sender_public_key:
            print(f"Invalid transaction: Sender '{transaction.sender}' is not a registered organization or has no public key.")
            return False
        if not transaction.is_valid_signature(sender_public_key):
            print(f"Invalid transaction signature from {transaction.sender} for tx {transaction.calculate_hash()}.")
            return False

        if self.policies.get('restrict_sender_to_registered_orgs', False):
            if transaction.sender not in self.participating_organizations:
                print(f"Policy Violation: Sender '{transaction.sender}' is not a registered organization.")
                return False
        
        if transaction.tx_type == "PolicyUpdate":
            authorized_proposers = self.policies.get('authorized_policy_proposers', [])
            if transaction.sender not in authorized_proposers:
                print(f"Policy Violation: Sender '{transaction.sender}' is not an authorized policy proposer.")
                return False
            if not isinstance(transaction.data, dict) or 'policy_name' not in transaction.data or 'policy_value' not in transaction.data:
                print("PolicyUpdate transaction data is malformed.")
                return False
        
        if not transaction.is_encrypted:
            if transaction.data.get('type') == 'ventilator_log':
                if not transaction.data.get('patient_id') or not transaction.data.get('duration_hrs'):
                    print("Policy Violation: Ventilator log missing required data (patient_id or duration_hrs).")
                    return False
                if not isinstance(transaction.data.get('duration_hrs'), (int, float)):
                    print("Policy Violation: Ventilator log duration_hrs must be a number.")
                    return False
                if transaction.data.get('duration_hrs') < self.policies.get('min_ventilator_duration_hrs', 0):
                    print(f"Policy Violation: Ventilator duration {transaction.data.get('duration_hrs')} hrs is below minimum required {self.policies.get('min_ventilator_duration_hrs', 0)} hrs.")
                    return False
            elif transaction.data.get('type') == 'patient_transfer':
                if not transaction.data.get('patient_id') or not transaction.data.get('from_hospital') or not transaction.data.get('to_hospital'):
                    print("Policy Violation: Patient transfer missing required data.")
                    return False

        self.pending_transactions.append(transaction)
        data_display = f"Type: {transaction.tx_type}, Encrypted: {transaction.is_encrypted}"
        if not transaction.is_encrypted and transaction.data.get('type'):
            data_display += f", Data Type: {transaction.data['type']}"
        print(f"Transaction added to pending: {transaction.sender} -> {transaction.recipient}, Amount: {transaction.amount}, {data_display}")
        return True

    def propose_block(self, miner_address):
        if not self.is_miner_authorized(miner_address):
            print(f"Error: Miner '{miner_address}' is not authorized to propose blocks.")
            return None
        if not self.pending_transactions:
            print("No pending transactions to create a block proposal.")
            return None
        sorted_transactions = sorted(self.pending_transactions, key=lambda x: (x.timestamp, x.sender, x.recipient))
        new_block = Block(
            index=len(self.chain), transactions=sorted_transactions, previous_hash=self.last_block.current_hash,
            miner=miner_address, timestamp=time.time()
        )
        print(f"Block #{new_block.index} proposed by '{miner_address}' with {len(new_block.transactions)} transactions. Hash: {new_block.current_hash}")
        return new_block

    def add_proposed_block(self, block):
        if not isinstance(block, Block):
            print("Error: Provided object is not a Block instance.")
            return False
        if block.index != len(self.chain):
            print(f"Invalid proposed block index. Expected {len(self.chain)}, got {block.index}")
            return False
        if block.previous_hash != self.last_block.current_hash:
            print(f"Invalid proposed block previous hash for block {block.index}.")
            return False
        if block.calculate_hash() != block.current_hash:
            print(f"Invalid proposed block current hash for block {block.index}. Recalculated: {block.calculate_hash()}, stored: {block.current_hash}")
            return False
        if block.current_hash not in self.proposed_blocks:
            self.proposed_blocks[block.current_hash] = {'block': block, 'endorsements': set()}
            print(f"Proposed block #{block.index} from '{block.miner}' added to proposed pool.")
            return True
        else:
            print(f"Proposed block #{block.index} from '{block.miner}' already in proposed pool.")
            return False

    def endorse_block(self, block_hash, endorser_id):
        if endorser_id not in self.authorized_miners:
            print(f"Endorsement denied: '{endorser_id}' is not an authorized validator.")
            return False
        if block_hash not in self.proposed_blocks:
            print(f"Endorsement failed: Block with hash {block_hash} not found in proposed pool.")
            return False
        self.proposed_blocks[block_hash]['endorsements'].add(endorser_id)
        print(f"Block '{block_hash[:8]}...' endorsed by '{endorser_id}'. Total endorsements: {len(self.proposed_blocks[block_hash]['endorsements'])}")
        return True

    def add_block(self, block):
        if not isinstance(block, Block):
            print("Error: Provided object is not a Block instance.")
            return False
        if not self.is_miner_authorized(block.miner):
            print(f"Validation Error: Block {block.index} was mined by unauthorized miner '{block.miner}'.")
            return False
        if block.index != len(self.chain):
            print(f"Invalid block index. Expected {len(self.chain)}, got {block.index}")
            return False
        if block.previous_hash != self.last_block.current_hash:
            print(f"Invalid previous hash for block {block.index}. Expected {self.last_block.current_hash}, got {block.previous_hash}")
            return False
        if block.calculate_hash() != block.current_hash:
            print(f"Invalid current hash for block {block.index}. Recalculated: {block.calculate_hash()}, stored: {block.current_hash}")
            return False

        for tx in block.transactions:
            sender_public_key_for_validation = self.get_organization_public_key(tx.sender)
            if not sender_public_key_for_validation:
                print(f"Validation Error: Block {block.index} contains transaction from unregistered sender '{tx.sender}'.")
                return False
            if not tx.is_valid_signature(sender_public_key_for_validation):
                print(f"Validation Error: Block {block.index} contains invalid transaction signature for tx {tx.calculate_hash()}.")
                return False
            
            if tx.tx_type == "PolicyUpdate":
                authorized_proposers = self.policies.get('authorized_policy_proposers', [])
                if tx.sender not in authorized_proposers:
                    print(f"Validation Error: Block {block.index} contains PolicyUpdate transaction from unauthorized sender '{tx.sender}'.")
                    return False
                if not isinstance(tx.data, dict) or 'policy_name' not in tx.data or 'policy_value' not in tx.data:
                    print(f"Validation Error: Block {block.index} contains malformed PolicyUpdate transaction.")
                    return False
                self.set_policy(tx.data['policy_name'], tx.data['policy_value'])
                print(f"  Applied policy '{tx.data['policy_name']}'='{tx.data['policy_value']}' from transaction in block {block.index}.")

        self.chain.append(block)
        self.apply_transactions_to_state(block.transactions)
        included_tx_hashes = {tx.calculate_hash() for tx in block.transactions}
        self.pending_transactions = [tx for tx in self.pending_transactions if tx.calculate_hash() not in included_tx_hashes]
        if block.current_hash in self.proposed_blocks:
            del self.proposed_blocks[block.current_hash]
        print(f"Block #{block.index} successfully added to the chain by '{block.miner}' and pending transactions updated.")
        return True

    def is_chain_valid(self):
        temp_policies = {}
        temp_state = {}

        for i in range(len(self.chain)):
            current_block = self.chain[i]
            
            if i > 0:
                previous_block = self.chain[i-1]
                if current_block.calculate_hash() != current_block.current_hash:
                    print(f"Validation Error: Block {current_block.index} has an incorrect hash.")
                    return False
                if current_block.previous_hash != previous_block.current_hash:
                    print(f"Validation Error: Block {current_block.index} has incorrect previous hash link.")
                    return False
            
            if current_block.miner != "System" and current_block.miner not in self.authorized_miners:
                print(f"Validation Error: Chain contains block {current_block.index} mined by unauthorized miner '{current_block.miner}'.")
                return False

            for tx in current_block.transactions:
                sender_public_key_for_validation = self.get_organization_public_key(tx.sender)
                if not sender_public_key_for_validation:
                    print(f"Validation Error: Block {current_block.index} contains transaction from unregistered sender '{tx.sender}'.")
                    return False
                if not tx.is_valid_signature(sender_public_key_for_validation):
                    print(f"Validation Error: Block {current_block.index} contains invalid transaction signature for tx {tx.calculate_hash()}.")
                    return False
                
                if tx.tx_type == "PolicyUpdate":
                    authorized_proposers_for_validation = temp_policies.get('authorized_policy_proposers', [])
                    if tx.sender not in authorized_proposers_for_validation:
                        print(f"Validation Error: Block {current_block.index} contains PolicyUpdate transaction from unauthorized sender '{tx.sender}'.")
                        return False
                    if not isinstance(tx.data, dict) or 'policy_name' not in tx.data or 'policy_value' not in tx.data:
                        print(f"Validation Error: Block {current_block.index} contains malformed PolicyUpdate transaction.")
                        return False
                    temp_policies[tx.data['policy_name']] = tx.data['policy_value']
                
                if temp_policies.get('restrict_sender_to_registered_orgs', False):
                    if tx.sender not in self.participating_organizations and tx.tx_type != "PolicyUpdate":
                        print(f"Validation Error: Block {current_block.index} contains transaction from unregistered sender '{tx.sender}'.")
                        return False
                
                if not tx.is_encrypted:
                    if tx.data.get('type') == 'ventilator_log':
                        if not tx.data.get('patient_id') or not tx.data.get('duration_hrs'):
                            print(f"Validation Error: Block {current_block.index} has ventilator log missing data.")
                            return False
                        if not isinstance(tx.data.get('duration_hrs'), (int, float)):
                            print(f"Validation Error: Block {current_block.index} has ventilator log with non-numeric duration.")
                            return False
                        if tx.data.get('duration_hrs') < temp_policies.get('min_ventilator_duration_hrs', 0):
                            print(f"Validation Error: Block {current_block.index} has ventilator duration below min policy.")
                            return False
                    elif tx.data.get('type') == 'patient_transfer':
                        if not tx.data.get('patient_id') or not tx.data.get('from_hospital') or not tx.data.get('to_hospital'):
                            print("Policy Violation: Patient transfer missing required data.")
                            return False

                self.apply_transactions_to_state(tx, temp_state_dict=temp_state)

        return True

    def register_organization(self, org_name, public_key):
        self.participating_organizations[org_name] = public_key
        print(f"Organization '{org_name}' registered with public key '{public_key}'.")

    def get_organization_public_key(self, org_name):
        return self.participating_organizations.get(org_name)

    def get_chain_as_list(self):
        chain_data = []
        for block in self.chain:
            block_dict = block.to_dict()
            block_dict['current_hash'] = block.current_hash
            chain_data.append(block_dict)
        return chain_data

    def replace_chain(self, new_chain_data):
        new_chain = []
        for block_data in new_chain_data:
            block = Block.from_dict(block_data)
            new_chain.append(block)

        original_chain = list(self.chain)
        original_pending_transactions = list(self.pending_transactions)
        original_policies = dict(self.policies)
        original_authorized_miners = set(self.authorized_miners)
        original_proposed_blocks = dict(self.proposed_blocks)
        original_state = dict(self.current_state)

        self.chain = new_chain
        self.policies = {}
        self.current_state = {}
        self.proposed_blocks = {}
        
        if self.is_chain_valid() and len(self.chain) > len(original_chain):
            print("Chain replaced successfully with a longer, valid chain.")
            self._rebuild_state_and_policies_from_chain()

            included_tx_hashes = set()
            for block in self.chain:
                for tx in block.transactions:
                    included_tx_hashes.add(tx.calculate_hash())
            self.pending_transactions = [tx for tx in self.pending_transactions if tx.calculate_hash() not in included_tx_hashes]

            blocks_to_remove_from_proposed = [block_hash for block_hash, data in self.proposed_blocks.items() if data['block'].index < len(self.chain)]
            for block_hash in blocks_to_remove_from_proposed:
                if block_hash in self.proposed_blocks:
                    del self.proposed_blocks[block_hash]

            return True
        else:
            print("New chain is not longer or not valid. Reverting to original chain and state.")
            self.chain = original_chain
            self.pending_transactions = original_pending_transactions
            self.policies = original_policies
            self.authorized_miners = original_authorized_miners
            self.proposed_blocks = original_proposed_blocks
            self.current_state = original_state
            return False

    def _rebuild_state_and_policies_from_chain(self):
        self.policies = {}
        self.current_state = {}
        for block in self.chain:
            for tx in block.transactions:
                if tx.tx_type == "PolicyUpdate":
                    self.set_policy(tx.data['policy_name'], tx.data['policy_value'])
                self.apply_transactions_to_state(tx)
        print("Policies and world state rebuilt from the chain.")

    def get_pending_transactions_as_list(self):
        return [tx.to_dict() for tx in self.pending_transactions]

    def set_policy(self, policy_name, value):
        self.policies[policy_name] = value
        print(f"Policy '{policy_name}' set to '{value}'.")
    
    def apply_transactions_to_state(self, transactions_or_single_tx, temp_state_dict=None):
        state_to_update = temp_state_dict if temp_state_dict is not None else self.current_state
        txs_to_process = transactions_or_single_tx
        if not isinstance(transactions_or_single_tx, list):
            txs_to_process = [transactions_or_single_tx]

        for tx in txs_to_process:
            if tx.is_encrypted: continue
            
            if tx.data.get('type') == 'ventilator_log':
                patient_id = tx.data.get('patient_id')
                duration_hrs = tx.data.get('duration_hrs')
                if patient_id and duration_hrs is not None:
                    state_to_update[f'patient_{patient_id}_ventilator_total_hrs'] = \
                        state_to_update.get(f'patient_{patient_id}_ventilator_total_hrs', 0) + duration_hrs
                    state_to_update[f'patient_{patient_id}_last_ventilator_log'] = tx.timestamp

            elif tx.data.get('type') == 'patient_transfer':
                patient_id = tx.data.get('patient_id')
                from_hospital = tx.data.get('from_hospital')
                to_hospital = tx.data.get('to_hospital')
                if patient_id and from_hospital and to_hospital:
                    state_to_update[f'patient_{patient_id}_current_hospital'] = to_hospital
            
            elif tx.data.get('type') == 'asset_update':
                asset_id = tx.data.get('asset_id')
                asset_status = tx.data.get('status')
                if asset_id and asset_status:
                    state_to_update[f'asset_{asset_id}_status'] = asset_status

            elif tx.tx_type == "standard" and tx.data.get('item') and tx.data.get('quantity'):
                item_name = tx.data['item']
                quantity = tx.data['quantity']
                state_to_update[f'inventory_{tx.sender}_{item_name}'] = \
                    state_to_update.get(f'inventory_{tx.sender}_{item_name}', 0) - quantity
                state_to_update[f'inventory_{tx.recipient}_{item_name}'] = \
                    state_to_update.get(f'inventory_{tx.recipient}_{item_name}', 0) + quantity
