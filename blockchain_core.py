# blockchain_core.py
import time
import json

# --- Part 1: Basic Cryptographic Primitives (Simulated/Simplified) ---
def simple_hash(data):
    """
    A very, very simple hash function for demonstration purposes.
    DO NOT USE IN PRODUCTION.
    This simulates hashing without external libraries.
    """
    if isinstance(data, dict):
        data_str = json.dumps(data, sort_keys=True)
    elif isinstance(data, list):
        # Sort lists of dicts for consistent hashing if elements are dicts
        # Sort by a stable key for consistent order. Assuming 'timestamp' and 'sender' exist.
        if all(isinstance(item, dict) for item in data) and len(data) > 0 and 'timestamp' in data[0] and 'sender' in data[0]:
            data_str = json.dumps(sorted(data, key=lambda x: (x['timestamp'], x['sender'], json.dumps(x, sort_keys=True))))
        else:
            data_str = json.dumps(data)
    else:
        data_str = str(data)

    hash_value = 0
    for char in data_str:
        hash_value = (hash_value * 31 + ord(char)) % (2**32 - 1)
    return str(hash_value)

# --- Part 2: Transaction ---

class Transaction:
    def __init__(self, sender, recipient, amount, timestamp=None, data=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.data = data if data is not None else {}
        self.signature = None

    def to_dict(self):
        """Converts transaction data to a dictionary for hashing/serialization."""
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'data': self.data
        }

    @classmethod
    def from_dict(cls, data_dict):
        """Creates a Transaction object from a dictionary."""
        tx = cls(data_dict['sender'], data_dict['recipient'], data_dict['amount'], data_dict['timestamp'], data_dict['data'])
        tx.signature = data_dict.get('signature')
        return tx

    def calculate_hash(self):
        """Calculates a hash of the transaction data."""
        # Ensure signature is not part of the data hashed for signing
        temp_dict = self.to_dict()
        temp_dict.pop('signature', None) # Remove signature before hashing for consistency
        return simple_hash(temp_dict)

    def sign(self, private_key):
        """
        Simulates signing the transaction.
        For demonstration, we just set a dummy signature based on sender and data.
        """
        # A real signature would use private_key to sign self.calculate_hash()
        self.signature = "signed_by_" + self.sender + "_" + simple_hash(self.to_dict())

    def is_valid_signature(self, public_key):
        """
        Simulates signature validation.
        For demonstration, we check if it's not None and looks plausible for the sender.
        """
        if self.signature is None:
            return False
        # Basic check: signature must start with expected prefix and public_key matches sender
        expected_prefix = "signed_by_" + self.sender + "_"
        return self.signature.startswith(expected_prefix) and public_key == self.sender


# --- Part 3: Block ---

class Block:
    def __init__(self, index, transactions, previous_hash, timestamp=None, nonce=0):
        self.index = index
        self.transactions = transactions # List of Transaction objects
        self.previous_hash = previous_hash
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.nonce = nonce
        self.current_hash = self.calculate_hash() # Calculate hash upon creation

    def to_dict(self):
        """Converts block data to a dictionary for hashing/serialization."""
        # Convert Transaction objects within the block to dictionaries for consistent hashing
        transaction_dicts = [tx.to_dict() for tx in self.transactions]
        return {
            'index': self.index,
            'transactions': transaction_dicts,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }

    @classmethod
    def from_dict(cls, data_dict):
        """Creates a Block object from a dictionary."""
        transactions = [Transaction.from_dict(tx_data) for tx_data in data_dict['transactions']]
        block = cls(data_dict['index'], transactions, data_dict['previous_hash'], data_dict['timestamp'], data_dict['nonce'])
        block.current_hash = data_dict['current_hash'] # Ensure hash is set from the received data
        return block

    def calculate_hash(self):
        """Calculates the hash of the block."""
        # Create a dictionary suitable for hashing, excluding current_hash if it exists
        temp_dict = self.to_dict()
        # Sort transactions for consistent hashing (important for consensus)
        # Ensure sorting on multiple keys for stable order if timestamps are identical
        if 'transactions' in temp_dict and all(isinstance(item, dict) for item in temp_dict['transactions']):
            temp_dict['transactions'] = sorted(temp_dict['transactions'], key=lambda x: (x['timestamp'], x['sender'], json.dumps(x, sort_keys=True)))
        return simple_hash(temp_dict)


# --- Part 4: Blockchain (Ledger) ---

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.participating_organizations = {} # { "OrgName": "PublicKey" }
        self.policies = {} # New: For "Board of Government" policies
        self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the first block in the chain."""
        genesis_block = Block(0, [], "0")
        self.chain.append(genesis_block)
        print("Genesis block created.")

    @property
    def last_block(self):
        """Returns the last block in the chain."""
        return self.chain[-1]

    def add_transaction(self, transaction):
        """Adds a new transaction to the list of pending transactions after validation."""
        if not isinstance(transaction, Transaction):
            print("Error: Provided object is not a Transaction instance.")
            return False
        if not transaction.is_valid_signature(transaction.sender):
            print(f"Invalid transaction signature from {transaction.sender}.")
            return False

        # Apply policies for transaction validation (e.g., sender must be registered)
        if self.policies.get('restrict_sender_to_registered_orgs', False):
            if transaction.sender not in self.participating_organizations:
                print(f"Policy Violation: Sender '{transaction.sender}' is not a registered organization.")
                return False
        
        # You can add more complex policy checks here based on transaction.data
        # Example: check if 'ventilator_log' transaction contains 'patient_id'
        if transaction.data.get('type') == 'ventilator_log':
            if not transaction.data.get('patient_id') or not transaction.data.get('duration_hrs'):
                print("Policy Violation: Ventilator log missing required data (patient_id or duration_hrs).")
                return False

        self.pending_transactions.append(transaction)
        print(f"Transaction added to pending: {transaction.sender} -> {transaction.recipient}, Amount: {transaction.amount}, Data: {transaction.data.get('type')}")
        return True

    def create_block(self, miner_address):
        """
        Creates a new block with pending transactions.
        This is the step before it's validated and added to the chain by consensus.
        """
        if not self.pending_transactions:
            print("No pending transactions to create a block.")
            return None

        # Sort transactions for consistent block hash
        sorted_transactions = sorted(self.pending_transactions, key=lambda x: (x.timestamp, x.sender, x.recipient))

        new_block = Block(
            index=len(self.chain),
            transactions=sorted_transactions,
            previous_hash=self.last_block.current_hash,
            timestamp=time.time()
        )
        # Clear pending transactions AFTER block creation for this node
        # In a real system, pending transactions might be removed from all nodes
        # upon successful block propagation and validation.
        self.pending_transactions = []
        print(f"Block #{new_block.index} created by {miner_address} with {len(new_block.transactions)} transactions. Hash: {new_block.current_hash}")
        return new_block

    def add_block(self, block):
        """Adds a new, validated block to the chain."""
        if not isinstance(block, Block):
            print("Error: Provided object is not a Block instance.")
            return False

        # Basic validation: ensure it links correctly and its hash is correct
        if block.index != len(self.chain):
            print(f"Invalid block index. Expected {len(self.chain)}, got {block.index}")
            return False
        if block.previous_hash != self.last_block.current_hash:
            print(f"Invalid previous hash for block {block.index}. Expected {self.last_block.current_hash}, got {block.previous_hash}")
            return False
        if block.calculate_hash() != block.current_hash:
            print(f"Invalid current hash for block {block.index}. Recalculated: {block.calculate_hash()}, stored: {block.current_hash}")
            return False

        # After basic checks, add to chain
        self.chain.append(block)
        # Remove any transactions included in this new block from pending_transactions
        included_tx_hashes = {tx.calculate_hash() for tx in block.transactions}
        self.pending_transactions = [tx for tx in self.pending_transactions if tx.calculate_hash() not in included_tx_hashes]

        print(f"Block #{block.index} successfully added to the chain and pending transactions updated.")
        return True

    def is_chain_valid(self):
        """Verifies the integrity of the entire blockchain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # Check if the block's hash is correct (recalculate and compare)
            if current_block.calculate_hash() != current_block.current_hash:
                print(f"Validation Error: Block {current_block.index} has an incorrect hash.")
                return False

            # Check if the previous_hash link is correct
            if current_block.previous_hash != previous_block.current_hash:
                print(f"Validation Error: Block {current_block.index} has incorrect previous hash link.")
                return False
            
            # Re-validate all transactions within the block
            for tx in current_block.transactions:
                # We need the original signature which is part of the tx object
                if not tx.is_valid_signature(tx.sender):
                    print(f"Validation Error: Block {current_block.index} contains invalid transaction signature.")
                    return False
                # Add more complex transaction validation here if necessary (e.g. policy checks)
                # Note: This is simplified. Full validation would check against the current state
                # of the blockchain (e.g. account balances, preventing double spends)
        return True

    def register_organization(self, org_name, public_key):
        """Registers a participating organization."""
        self.participating_organizations[org_name] = public_key
        print(f"Organization '{org_name}' registered with public key '{public_key}'.")

    def get_organization_public_key(self, org_name):
        return self.participating_organizations.get(org_name)

    def get_chain_as_list(self):
        """Returns the entire blockchain as a list of dictionaries, suitable for serialization."""
        chain_data = []
        for block in self.chain:
            block_dict = block.to_dict()
            block_dict['current_hash'] = block.current_hash # Explicitly add current_hash
            chain_data.append(block_dict)
        return chain_data

    def replace_chain(self, new_chain_data):
        """
        Replaces the current chain with a new one if the new one is longer and valid.
        This is crucial for network synchronization.
        """
        new_chain = []
        for block_data in new_chain_data:
            block = Block.from_dict(block_data) # Use from_dict to reconstruct
            new_chain.append(block)

        # Temporarily replace to validate
        original_chain = list(self.chain) # Make a copy to revert
        self.chain = new_chain

        if self.is_chain_valid() and len(self.chain) > len(original_chain):
            print("Chain replaced successfully with a longer, valid chain.")
            # Clear pending transactions that might have been included in the new chain
            included_tx_hashes = set()
            for block in self.chain:
                for tx in block.transactions:
                    included_tx_hashes.add(tx.calculate_hash())
            self.pending_transactions = [tx for tx in self.pending_transactions if tx.calculate_hash() not in included_tx_hashes]
            return True
        else:
            print("New chain is not longer or not valid. Reverting to original chain.")
            self.chain = original_chain
            return False

    def get_pending_transactions_as_list(self):
        """Returns pending transactions as a list of dictionaries for serialization."""
        return [tx.to_dict() for tx in self.pending_transactions]

    def set_policy(self, policy_name, value):
        """Sets a network policy from the Board of Government."""
        self.policies[policy_name] = value
        print(f"Policy '{policy_name}' set to '{value}'.")