# blockchain_core.py
import time
import json
import base64 # For a more "realistic" simulated encryption output
import math # For calculating majority/threshold

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
        if all(isinstance(item, dict) for item in data) and len(data) > 0:
            # Try to sort by common keys, fall back to full JSON dump if keys aren't present
            try:
                data_str = json.dumps(sorted(data, key=lambda x: (x.get('timestamp', 0), x.get('sender', ''), json.dumps(x, sort_keys=True))))
            except TypeError: # Fallback if items are not consistently structured for sorting
                data_str = json.dumps(data)
        else:
            data_str = json.dumps(data)
    else:
        data_str = str(data)

    hash_value = 0
    for char in data_str:
        hash_value = (hash_value * 31 + ord(char)) % (2**32 - 1)
    return str(hash_value)

# --- Simulated Encryption/Decryption Functions ---
# In a real system, this would involve actual cryptographic libraries (e.g., PyCryptodome)
# and a robust key management system (e.g., KMS, hardware security modules).

def simulate_encrypt(data, encryption_key):
    """
    Simulates encrypting data.
    In a real scenario, `encryption_key` would be a proper cryptographic key
    and the process would use a strong encryption algorithm (AES, RSA, etc.).
    For this demo, we just encode and prepend a marker.
    """
    if not isinstance(data, str):
        data = json.dumps(data) # Convert dicts/lists to string for encryption
    
    # A very simple "encryption"
    encrypted_bytes = base64.b64encode(data.encode('utf-8'))
    return f"ENC:{encryption_key}:{encrypted_bytes.decode('utf-8')}"

def simulate_decrypt(encrypted_data, decryption_key):
    """
    Simulates decrypting data.
    Checks if the decryption key matches the one used for "encryption".
    """
    if not encrypted_data.startswith("ENC:"):
        # Not an encrypted string from our simulation
        return encrypted_data # Or raise an error

    parts = encrypted_data.split(':', 2) # Split into 'ENC', 'key', 'base64_data'
    if len(parts) < 3:
        print("Error: Malformed simulated encrypted data string.")
        return None

    stored_key = parts[1]
    base64_encoded_data = parts[2]

    if stored_key != decryption_key:
        print(f"Decryption failed: Provided key '{decryption_key}' does not match stored key '{stored_key}'.")
        return None
    
    try:
        decoded_bytes = base64.b64decode(base64_encoded_data.encode('utf-8'))
        # Assuming original data was JSON, try to decode it back
        try:
            return json.loads(decoded_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            return decoded_bytes.decode('utf-8') # Return as string if not JSON
    except Exception as e:
        print(f"Error during simulated decryption: {e}")
        return None


# --- Part 2: Transaction ---

class Transaction:
    def __init__(self, sender, recipient, amount, timestamp=None, data=None, is_encrypted=False, tx_type="standard"): # New: tx_type
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.data = data if data is not None else {}
        self.signature = None
        self.is_encrypted = is_encrypted
        self.tx_type = tx_type # Standard, PolicyUpdate, AssetTransfer, etc.

    def to_dict(self):
        """Converts transaction data to a dictionary for hashing/serialization."""
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'data': self.data,
            'is_encrypted': self.is_encrypted,
            'tx_type': self.tx_type # Include new attribute
        }

    @classmethod
    def from_dict(cls, data_dict):
        """Creates a Transaction object from a dictionary."""
        tx = cls(
            data_dict['sender'],
            data_dict['recipient'],
            data_dict['amount'],
            data_dict['timestamp'],
            data_dict.get('data', {}),
            data_dict.get('is_encrypted', False),
            data_dict.get('tx_type', 'standard') # Use .get with default
        )
        tx.signature = data_dict.get('signature')
        return tx

    def calculate_hash(self):
        """Calculates a hash of the transaction data."""
        temp_dict = self.to_dict()
        temp_dict.pop('signature', None)
        return simple_hash(temp_dict)

    def sign(self, private_key):
        """
        Simulates signing the transaction.
        """
        self.signature = "signed_by_" + self.sender + "_" + simple_hash(self.to_dict())

    def is_valid_signature(self, public_key):
        """
        Simulates signature validation.
        """
        if self.signature is None:
            return False
        expected_prefix = "signed_by_" + self.sender + "_"
        return self.signature.startswith(expected_prefix) and public_key == self.sender


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
            'index': self.index,
            'transactions': transaction_dicts,
            'previous_hash': self.previous_hash,
            'miner': self.miner,
            'timestamp': self.timestamp,
            'nonce': self.nonce
        }

    @classmethod
    def from_dict(cls, data_dict):
        """Creates a Block object from a dictionary."""
        transactions = [Transaction.from_dict(tx_data) for tx_data in data_dict['transactions']]
        block = cls(
            data_dict['index'],
            transactions,
            data_dict['previous_hash'],
            data_dict['miner'],
            data_dict['timestamp'],
            data_dict['nonce']
        )
        block.current_hash = data_dict['current_hash']
        return block

    def calculate_hash(self):
        """Calculates the hash of the block."""
        temp_dict = self.to_dict()
        if 'transactions' in temp_dict and all(isinstance(item, dict) for item in temp_dict['transactions']):
            temp_dict['transactions'] = sorted(temp_dict['transactions'], key=lambda x: (x.get('timestamp',0), x.get('sender',''), json.dumps(x, sort_keys=True)))
        return simple_hash(temp_dict)


# --- Part 4: Blockchain (Ledger) ---

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.participating_organizations = {} # { "OrgName": "PublicKey" }
        self.policies = {} # For "Board of Government" policies
        self.authorized_miners = set() # Set of node IDs authorized to mine/validate
        self.proposed_blocks = {} # Stores {'block_hash': {'block': Block, 'endorsements': set()}}
        self.current_state = {} # New: Simple in-memory world state
        self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the first block in the chain."""
        genesis_block = Block(0, [], "0", miner="System")
        self.chain.append(genesis_block)
        print("Genesis block created.")

    @property
    def last_block(self):
        """Returns the last block in the chain."""
        return self.chain[-1]

    def is_miner_authorized(self, miner_address):
        """Checks if a given address is authorized to mine/propose blocks."""
        return miner_address in self.authorized_miners

    def add_authorized_miner(self, miner_address):
        """Adds an organization to the list of authorized miners."""
        if miner_address not in self.authorized_miners:
            self.authorized_miners.add(miner_address)
            print(f"Miner '{miner_address}' added to authorized list.")
        else:
            print(f"Miner '{miner_address}' is already authorized.")
    
    def remove_authorized_miner(self, miner_address):
        """Removes an organization from the list of authorized miners."""
        if miner_address in self.authorized_miners:
            self.authorized_miners.remove(miner_address)
            print(f"Miner '{miner_address}' removed from authorized list.")
            return True
        return False

    def get_endorsement_threshold(self):
        """Calculates the minimum number of endorsements required for a block."""
        if not self.authorized_miners:
            return 1 # If no authorized miners, technically only one is needed (e.g., genesis)
        # Simple majority: ceil((2/3) * N) for PBFT-like resilience (f=1/3, need 2f+1)
        # Or just simple majority: math.ceil(len(self.authorized_miners) / 2) + 1
        # For simplicity, let's use a simple majority for now for active nodes.
        return max(1, math.ceil(len(self.authorized_miners) / 2) + 1)


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
        
        # Policy for PolicyUpdate transactions (only authorized BOG can create them)
        if transaction.tx_type == "PolicyUpdate":
            # This is a conceptual check. In a real system, you'd verify a
            # specific "Board of Governance" role or multi-sig.
            # For demo, let's say 'Hospital_1' is authorized to propose policies.
            if transaction.sender != "Hospital_1": # Or check a list of "BOG_members"
                print(f"Policy Violation: Only 'Hospital_1' is authorized to propose PolicyUpdate transactions.")
                return False
            # Check if the policy change data is well-formed
            if not isinstance(transaction.data, dict) or 'policy_name' not in transaction.data or 'policy_value' not in transaction.data:
                print("PolicyUpdate transaction data is malformed.")
                return False
        
        # General data validation based on transaction type (if not encrypted)
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
            # Add other transaction type specific policies here
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
        """
        Creates a new block proposal with pending transactions.
        This block is NOT yet added to the chain; it awaits endorsements.
        """
        if not self.is_miner_authorized(miner_address):
            print(f"Error: Miner '{miner_address}' is not authorized to propose blocks.")
            return None

        if not self.pending_transactions:
            print("No pending transactions to create a block proposal.")
            return None

        sorted_transactions = sorted(self.pending_transactions, key=lambda x: (x.timestamp, x.sender, x.recipient))

        # IMPORTANT: Do not clear pending transactions here. They are cleared only AFTER
        # the block is successfully added to the chain (in add_block).
        # This allows pending transactions to remain if a block proposal fails consensus.

        new_block = Block(
            index=len(self.chain),
            transactions=sorted_transactions,
            previous_hash=self.last_block.current_hash,
            miner=miner_address,
            timestamp=time.time()
        )
        print(f"Block #{new_block.index} proposed by '{miner_address}' with {len(new_block.transactions)} transactions. Hash: {new_block.current_hash}")
        return new_block

    def add_proposed_block(self, block):
        """Adds a block to the proposed pool if it's valid and not already there."""
        if not isinstance(block, Block):
            print("Error: Provided object is not a Block instance.")
            return False
        
        # Basic validation: ensure it links correctly and its hash is correct
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
        """Records an endorsement for a proposed block."""
        if endorser_id not in self.authorized_miners:
            print(f"Endorsement denied: '{endorser_id}' is not an authorized validator.")
            return False
        
        if block_hash not in self.proposed_blocks:
            print(f"Endorsement failed: Block with hash {block_hash} not found in proposed pool.")
            return False
        
        self.proposed_blocks[block_hash]['endorsements'].add(endorser_id)
        print(f"Block '{block_hash}' endorsed by '{endorser_id}'. Total endorsements: {len(self.proposed_blocks[block_hash]['endorsements'])}")
        return True


    def add_block(self, block):
        """
        Adds a new, validated block to the chain.
        This method is now called after a block has received enough endorsements.
        """
        if not isinstance(block, Block):
            print("Error: Provided object is not a Block instance.")
            return False

        # --- PoA Consensus Check: Is the miner authorized? ---
        if not self.is_miner_authorized(block.miner):
            print(f"Validation Error: Block {block.index} was mined by unauthorized miner '{block.miner}'.")
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

        # Validate transactions within the block
        for tx in block.transactions:
            if not tx.is_valid_signature(tx.sender):
                print(f"Validation Error: Block {block.index} contains invalid transaction signature.")
                return False
            # Re-apply transaction policies to ensure they are still valid based on current policies
            # This is simplified; a full re-validation might be complex.
            # Here, we ensure basic structure and authorized sender if policy is active.
            if self.policies.get('restrict_sender_to_registered_orgs', False):
                if tx.sender not in self.participating_organizations:
                    print(f"Validation Error: Block {block.index} contains transaction from unregistered sender '{tx.sender}'.")
                    return False
            # Apply PolicyUpdate transactions when adding the block
            if tx.tx_type == "PolicyUpdate":
                self.set_policy(tx.data['policy_name'], tx.data['policy_value'])

        # After all checks, add to chain
        self.chain.append(block)
        
        # Apply transactions to world state AFTER block is added to chain
        self.apply_transactions_to_state(block.transactions)

        # Clear pending transactions that were included in this new block
        included_tx_hashes = {tx.calculate_hash() for tx in block.transactions}
        self.pending_transactions = [tx for tx in self.pending_transactions if tx.calculate_hash() not in included_tx_hashes]

        # Remove the block from the proposed_blocks pool
        if block.current_hash in self.proposed_blocks:
            del self.proposed_blocks[block.current_hash]

        print(f"Block #{block.index} successfully added to the chain by '{block.miner}' and pending transactions updated.")
        return True

    def is_chain_valid(self):
        """Verifies the integrity of the entire blockchain."""
        temp_policies = {} # Policies as they evolve through the chain
        temp_state = {} # State as it evolves through the chain

        for i in range(len(self.chain)):
            current_block = self.chain[i]
            
            # Genesis block has no previous hash to check
            if i > 0:
                previous_block = self.chain[i-1]
                # Check if the block's hash is correct (recalculate and compare)
                if current_block.calculate_hash() != current_block.current_hash:
                    print(f"Validation Error: Block {current_block.index} has an incorrect hash.")
                    return False

                # Check if the previous_hash link is correct
                if current_block.previous_hash != previous_block.current_hash:
                    print(f"Validation Error: Block {current_block.index} has incorrect previous hash link.")
                    return False
            
            # --- PoA Consensus Check: Is the block's miner authorized? ---
            # For genesis block, "System" is always authorized.
            if current_block.miner != "System" and current_block.miner not in self.authorized_miners:
                print(f"Validation Error: Chain contains block {current_block.index} mined by unauthorized miner '{current_block.miner}'.")
                return False

            # Re-validate all transactions within the block, considering evolving policies
            for tx in current_block.transactions:
                if not tx.is_valid_signature(tx.sender):
                    print(f"Validation Error: Block {current_block.index} contains invalid transaction signature for tx {tx.calculate_hash()}.")
                    return False
                
                # Apply PolicyUpdate transactions encountered in this block
                if tx.tx_type == "PolicyUpdate":
                    if not isinstance(tx.data, dict) or 'policy_name' not in tx.data or 'policy_value' not in tx.data:
                        print(f"Validation Error: Block {current_block.index} contains malformed PolicyUpdate transaction.")
                        return False
                    # Update temporary policies for subsequent transaction validation in this block/chain
                    temp_policies[tx.data['policy_name']] = tx.data['policy_value']
                    print(f"  (Validation) Applied policy '{tx.data['policy_name']}'='{tx.data['policy_value']}' from block {current_block.index}.")
                    
                    # Policy for PolicyUpdate transactions themselves: only authorized BOG can create them.
                    # This check is on the 'sender' of the PolicyUpdate transaction itself.
                    if tx.sender != "Hospital_1": # Assuming Hospital_1 is the sole BOG for policy updates
                        print(f"Validation Error: Block {current_block.index} contains PolicyUpdate transaction from unauthorized sender '{tx.sender}'.")
                        return False
                
                # Re-check policy 'restrict_sender_to_registered_orgs' with current policies
                if temp_policies.get('restrict_sender_to_registered_orgs', False):
                    if tx.sender not in self.participating_organizations and tx.tx_type != "PolicyUpdate": # PolicyUpdate bypasses this specific sender restriction for initial BOG setup
                        print(f"Validation Error: Block {current_block.index} contains transaction from unregistered sender '{tx.sender}'.")
                        return False
                
                # Re-check specific data policies for non-encrypted transactions
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
                    # Add other transaction type specific policies here for chain validation

                # Apply transactions to a temporary state during chain validation
                self.apply_transactions_to_state(tx, temp_state_dict=temp_state) # Pass temp_state to apply to

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
            block_dict['current_hash'] = block.current_hash
            chain_data.append(block_dict)
        return chain_data

    def replace_chain(self, new_chain_data):
        """
        Replaces the current chain with a new one if the new one is longer and valid.
        This is crucial for network synchronization.
        """
        new_chain = []
        for block_data in new_chain_data:
            block = Block.from_dict(block_data)
            new_chain.append(block)

        original_chain = list(self.chain) # Make a copy to revert
        original_pending_transactions = list(self.pending_transactions)
        original_policies = dict(self.policies) # Copy policies
        original_authorized_miners = set(self.authorized_miners) # Copy authorized miners
        original_state = dict(self.current_state) # Copy current state

        # Temporarily set to new chain for validation
        self.chain = new_chain
        # Reset policies and state for validation from scratch
        self.policies = {} 
        self.current_state = {}
        # Keep authorized_miners as they are the source of truth for the validation itself.
        # Policies will be reapplied by is_chain_valid.
        
        if self.is_chain_valid() and len(self.chain) > len(original_chain):
            print("Chain replaced successfully with a longer, valid chain.")
            # Re-apply policies and rebuild state based on the newly adopted chain
            self._rebuild_state_and_policies_from_chain()

            # Clear pending transactions that might have been included in the new chain
            included_tx_hashes = set()
            for block in self.chain:
                for tx in block.transactions:
                    included_tx_hashes.add(tx.calculate_hash())
            self.pending_transactions = [tx for tx in self.pending_transactions if tx.calculate_hash() not in included_tx_hashes]

            # Clear proposed blocks that might have been included in the new chain
            blocks_to_remove_from_proposed = [block_hash for block_hash, data in self.proposed_blocks.items() if data['block'].index < len(self.chain)]
            for block_hash in blocks_to_remove_from_proposed:
                del self.proposed_blocks[block_hash]

            return True
        else:
            print("New chain is not longer or not valid. Reverting to original chain and state.")
            self.chain = original_chain
            self.pending_transactions = original_pending_transactions
            self.policies = original_policies
            self.authorized_miners = original_authorized_miners # Restore if it was changed
            self.current_state = original_state
            return False

    def _rebuild_state_and_policies_from_chain(self):
        """Rebuilds the policies and current_state by re-processing the entire chain."""
        self.policies = {} # Reset policies
        self.current_state = {} # Reset state
        for block in self.chain:
            for tx in block.transactions:
                if tx.tx_type == "PolicyUpdate":
                    self.set_policy(tx.data['policy_name'], tx.data['policy_value'])
                self.apply_transactions_to_state(tx)
        print("Policies and world state rebuilt from the chain.")


    def get_pending_transactions_as_list(self):
        """Returns pending transactions as a list of dictionaries for serialization."""
        return [tx.to_dict() for tx in self.pending_transactions]

    def set_policy(self, policy_name, value):
        """Sets a network policy. Used internally after PolicyUpdate transactions are confirmed."""
        self.policies[policy_name] = value
        print(f"Policy '{policy_name}' set to '{value}'.")
    
    def apply_transactions_to_state(self, transactions_or_single_tx, temp_state_dict=None):
        """
        Applies the effects of transactions to the blockchain's current_state.
        If temp_state_dict is provided, applies to that instead (for chain validation).
        """
        state_to_update = temp_state_dict if temp_state_dict is not None else self.current_state

        # Ensure we can handle both a list of transactions or a single transaction
        txs_to_process = transactions_or_single_tx
        if not isinstance(transactions_or_single_tx, list):
            txs_to_process = [transactions_or_single_tx]

        for tx in txs_to_process:
            if tx.is_encrypted:
                # We cannot process encrypted data into the world state directly
                # World state usually tracks unencrypted, agreed-upon facts.
                continue
            
            # Example state updates based on transaction type
            if tx.data.get('type') == 'ventilator_log':
                patient_id = tx.data.get('patient_id')
                duration_hrs = tx.data.get('duration_hrs')
                if patient_id and duration_hrs is not None:
                    state_to_update[f'patient_{patient_id}_ventilator_total_hrs'] = \
                        state_to_update.get(f'patient_{patient_id}_ventilator_total_hrs', 0) + duration_hrs
                    state_to_update[f'patient_{patient_id}_last_ventilator_log'] = tx.timestamp
                    print(f"  State Updated: Patient {patient_id} ventilator hours updated. (Total: {state_to_update[f'patient_{patient_id}_ventilator_total_hrs']})")

            elif tx.data.get('type') == 'patient_transfer':
                patient_id = tx.data.get('patient_id')
                from_hospital = tx.data.get('from_hospital')
                to_hospital = tx.data.get('to_hospital')
                if patient_id and from_hospital and to_hospital:
                    state_to_update[f'patient_{patient_id}_current_hospital'] = to_hospital
                    print(f"  State Updated: Patient {patient_id} transferred to {to_hospital}.")
            
            elif tx.data.get('type') == 'asset_update':
                asset_id = tx.data.get('asset_id')
                asset_status = tx.data.get('status')
                if asset_id and asset_status:
                    state_to_update[f'asset_{asset_id}_status'] = asset_status
                    print(f"  State Updated: Asset {asset_id} status updated to {asset_status}.")

            # Other types of transactions might also update the state
            # For "standard" transactions, if they have an 'item' and 'quantity', track inventory
            elif tx.tx_type == "standard" and tx.data.get('item') and tx.data.get('quantity'):
                item_name = tx.data['item']
                quantity = tx.data['quantity']
                # Example: Decrement inventory for sender, increment for recipient
                state_to_update[f'inventory_{tx.sender}_{item_name}'] = \
                    state_to_update.get(f'inventory_{tx.sender}_{item_name}', 0) - quantity
                state_to_update[f'inventory_{tx.recipient}_{item_name}'] = \
                    state_to_update.get(f'inventory_{tx.recipient}_{item_name}', 0) + quantity
                print(f"  State Updated: Inventory for {item_name} updated between {tx.sender} and {tx.recipient}.")

