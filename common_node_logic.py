# common_node_logic.py
import json
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
import os
import sys
# NEW IMPORTS
from http.server import BaseHTTPRequestHandler, HTTPServer # <--- ADD THESE IMPORTS

# Add the directory containing blockchain_core.py and byzantine_fault_tolerant.py
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import core blockchain logic, including the new Wallet class
from blockchain_core import Blockchain, Transaction, Block, simple_hash, simulate_encrypt, simulate_decrypt, Wallet


# These global variables will be set by the individual node files' start_node function
_node_id = None
_node_port = None
_node_encryption_key = None
_peers = []
_node_blockchain = None
_node_wallet = None


class NodeCommunication:
    """Helper class for inter-node communication."""

    @staticmethod
    def _send_post_request(url, payload):
        """Helper to send a POST request with JSON payload."""
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to connect to {url}: {e.reason}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error sending POST to {url}: {e}") from e

    @staticmethod
    def broadcast_transaction(transaction):
        """Broadcasts a transaction to all known peers."""
        print(f"\nBroadcasting transaction from {transaction.sender} to peers...")
        for peer in _peers:
            try:
                NodeCommunication._send_post_request(
                    f"{peer['address']}/transactions/new",
                    transaction.to_dict()
                )
                print(f"  Sent transaction to {peer['id']}")
            except ConnectionError as e:
                print(f"  Skipping {peer['id']}: {e}")
            except RuntimeError as e:
                print(f"  Error broadcasting to {peer['id']}: {e}")

    @staticmethod
    def broadcast_block_proposal(block):
        """Broadcasts a newly PROPOSED block to all known peers for endorsement."""
        print(f"\nBroadcasting block proposal #{block.index} to peers for endorsement...")
        for peer in _peers:
            try:
                NodeCommunication._send_post_request(
                    f"{peer['address']}/propose_block",
                    {"block": block.to_dict()}
                )
                print(f"  Sent block proposal to {peer['id']}")
            except ConnectionError as e:
                print(f"  Skipping {peer['id']}: {e}")
            except RuntimeError as e:
                print(f"  Error broadcasting proposal to {peer['id']}: {e}")

    @staticmethod
    def broadcast_endorsement(block_hash, endorser_id):
        """Broadcasts an endorsement for a block to all known peers."""
        print(f"\nBroadcasting endorsement for block '{block_hash[:8]}...' by {endorser_id} to peers...")
        for peer in _peers:
            try:
                NodeCommunication._send_post_request(
                    f"{peer['address']}/endorse_block",
                    {"block_hash": block_hash, "endorser_id": endorser_id}
                )
                print(f"  Sent endorsement to {peer['id']}")
            except ConnectionError as e:
                print(f"  Skipping {peer['id']}: {e}")
            except RuntimeError as e:
                print(f"  Error broadcasting endorsement to {peer['id']}: {e}")

    @staticmethod
    def fetch_chain(peer_address):
        """Fetches the full chain from a given peer."""
        try:
            with urllib.request.urlopen(f"{peer_address}/chain", timeout=5) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.URLError as e:
            print(f"  Network error fetching chain from {peer_address}: {e.reason}")
            return None
        except Exception as e:
            print(f"  Error fetching chain from {peer_address}: {e}")
            return None

    @staticmethod
    def resolve_conflicts(current_blockchain_instance, all_peers_list):
        """
        Consensus algorithm: Simplified longest-chain rule.
        """
        longest_chain_data = None
        max_length = len(current_blockchain_instance.chain)

        print(f"\n{_node_id} resolving conflicts: Checking peers for longer chains...")
        for peer in all_peers_list:
            print(f"  Fetching chain from {peer['id']} ({peer['address']})...")
            chain_response = NodeCommunication.fetch_chain(peer['address'])

            if chain_response and 'chain' in chain_response and chain_response['length'] > max_length:
                print(f"  {peer['id']} has a longer chain (length {chain_response['length']}). Validating...")
                
                temp_blockchain_for_validation = Blockchain()
                temp_blockchain_for_validation.chain = []
                temp_blockchain_for_validation.authorized_miners = set(current_blockchain_instance.authorized_miners)
                
                if temp_blockchain_for_validation.replace_chain(chain_response['chain']):
                    max_length = chain_response['length']
                    longest_chain_data = chain_response['chain']
                    print(f"  Longer valid chain found from {peer['id']}.")
                else:
                    print(f"  Chain from {peer['id']} is longer but not valid (e.g., unauthorized miner or invalid transactions).")

        if longest_chain_data:
            print(f"{_node_id}: Found a longer valid chain. Replacing our chain...")
            return current_blockchain_instance.replace_chain(longest_chain_data)
        
        print(f"{_node_id}: Our chain is the longest or no longer valid chain found among peers.")
        return False


class NodeRequestHandler(BaseHTTPRequestHandler): # This is where BaseHTTPRequestHandler was not defined
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        global _node_blockchain, _node_id, _node_encryption_key, _node_wallet
        
        if self.path == '/status':
            self._set_headers()
            response = {
                "message": f"{_node_id} is up and running!",
                "chain_length": len(_node_blockchain.chain),
                "pending_tx_count": len(_node_blockchain.pending_transactions),
                "authorized_miners": list(_node_blockchain.authorized_miners),
                "current_policies": _node_blockchain.policies,
                "proposed_blocks_count": len(_node_blockchain.proposed_blocks),
                "node_public_key": _node_wallet.public_key
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/chain':
            self._set_headers()
            response = {"chain": _node_blockchain.get_chain_as_list(), "length": len(_node_blockchain.chain)}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/pending_transactions':
            self._set_headers()
            response = {"pending_transactions": _node_blockchain.get_pending_transactions_as_list()}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/current_state':
            self._set_headers()
            response = {"current_state": _node_blockchain.current_state}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/propose_block':
            if not _node_blockchain.is_miner_authorized(_node_id):
                self._set_headers(403)
                self.wfile.write(json.dumps({"message": f"Node {_node_id} is not authorized to propose blocks."}).encode('utf-8'))
                return

            if not _node_blockchain.pending_transactions:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "No pending transactions to propose a block."}).encode('utf-8'))
                return

            proposed_block = _node_blockchain.propose_block(_node_id)
            if proposed_block:
                _node_blockchain.add_proposed_block(proposed_block)
                NodeCommunication.broadcast_block_proposal(proposed_block)
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Block proposed and broadcast for endorsement.", "block": proposed_block.to_dict()}).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps({"message": "Failed to propose block (check logs for authorization/pending transactions)."}).encode('utf-8'))
        elif self.path.startswith('/transaction/decrypt'):
            query_params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            block_index = query_params.get('block_index', [None])[0]
            tx_hash = query_params.get('tx_hash', [None])[0]

            if not block_index or not tx_hash:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Missing block_index or tx_hash"}).encode('utf-8'))
                return

            try:
                block_index = int(block_index)
                if block_index >= len(_node_blockchain.chain) or block_index < 0:
                    raise IndexError("Block index out of range")
                
                target_block = _node_blockchain.chain[block_index]
                found_tx = None
                for tx in target_block.transactions:
                    if tx.calculate_hash() == tx_hash:
                        found_tx = tx
                        break
                
                if found_tx and found_tx.is_encrypted:
                    decrypted_data = simulate_decrypt(found_tx.data, _node_encryption_key)
                    if decrypted_data is not None:
                        self._set_headers(200)
                        self.wfile.write(json.dumps({"message": "Decrypted data.", "data": decrypted_data, "original_encrypted_data": found_tx.data}).encode('utf-8'))
                    else:
                        self._set_headers(403)
                        self.wfile.write(json.dumps({"message": "Could not decrypt transaction data (incorrect key or malformed).", "encrypted_data": found_tx.data}).encode('utf-8'))
                elif found_tx and not found_tx.is_encrypted:
                    self._set_headers(200)
                    self.wfile.write(json.dumps({"message": "Transaction data is not encrypted.", "data": found_tx.data}).encode('utf-8'))
                else:
                    self._set_headers(404)
                    self.wfile.write(json.dumps({"message": "Transaction not found in specified block."}).encode('utf-8'))

            except (ValueError, IndexError) as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": f"Invalid block index or hash: {e}"}).encode('utf-8'))
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({"message": f"Server error during decryption: {e}"}).encode('utf-8'))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"message": "Not Found"}).encode('utf-8'))

    def do_POST(self):
        global _node_blockchain, _node_id, _node_wallet
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))

        if self.path == '/transactions/new':
            tx_data = data
            tx = Transaction.from_dict(tx_data)
            
            if tx.sender == _node_id:
                tx.sign(_node_wallet.private_key)

            if _node_blockchain.add_transaction(tx):
                self._set_headers(201)
                self.wfile.write(json.dumps({"message": "Transaction added to pending pool."}).encode('utf-8'))
                NodeCommunication.broadcast_transaction(tx)
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Invalid transaction."}).encode('utf-8'))

        elif self.path == '/propose_block':
            block_data = data.get('block')
            if not block_data:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "No block data provided for proposal."}).encode('utf-8'))
                return

            proposed_block = Block.from_dict(block_data)
            
            if not _node_blockchain.is_miner_authorized(proposed_block.miner):
                self._set_headers(403)
                self.wfile.write(json.dumps({"message": f"Received proposal from unauthorized miner '{proposed_block.miner}'."}).encode('utf-8'))
                return

            if _node_blockchain.add_proposed_block(proposed_block):
                if _node_blockchain.is_miner_authorized(_node_id):
                    _node_blockchain.endorse_block(proposed_block.current_hash, _node_id)
                    NodeCommunication.broadcast_endorsement(proposed_block.current_hash, _node_id)
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Block proposal received and added to pending proposals."}).encode('utf-8'))
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Invalid block proposal received or already known."}).encode('utf-8'))

        elif self.path == '/endorse_block':
            block_hash = data.get('block_hash')
            endorser_id = data.get('endorser_id')

            if not block_hash or not endorser_id:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Missing block_hash or endorser_id for endorsement."}).encode('utf-8'))
                return
            
            if _node_blockchain.endorse_block(block_hash, endorser_id):
                if block_hash in _node_blockchain.proposed_blocks:
                    current_endorsements = len(_node_blockchain.proposed_blocks[block_hash]['endorsements'])
                    required_endorsements = _node_blockchain.get_endorsement_threshold()
                    
                    if current_endorsements >= required_endorsements:
                        finalized_block = _node_blockchain.proposed_blocks[block_hash]['block']
                        print(f"Block #{finalized_block.index} '{block_hash[:8]}...' received enough endorsements ({current_endorsements}/{required_endorsements}). Attempting to add to chain.")
                        if _node_blockchain.add_block(finalized_block):
                            self._set_headers(200)
                            self.wfile.write(json.dumps({"message": f"Endorsement received. Block #{finalized_block.index} finalized and added to chain."}).encode('utf-8'))
                        else:
                            self._set_headers(500)
                            self.wfile.write(json.dumps({"message": f"Endorsement received. Block #{finalized_block.index} finalized but failed to add to chain locally."}).encode('utf-8'))
                    else:
                        self._set_headers(200)
                        self.wfile.write(json.dumps({"message": f"Endorsement received. Block '{block_hash[:8]}...' now has {current_endorsements}/{required_endorsements} endorsements."}).encode('utf-8'))
                else:
                    self._set_headers(200)
                    self.wfile.write(json.dumps({"message": "Endorsement received for unknown or already processed block."}).encode('utf-8'))
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Failed to add endorsement (invalid endorser or block not found)."}).encode('utf-8'))


        elif self.path == '/resolve_conflict':
            replaced = NodeCommunication.resolve_conflicts(_node_blockchain, _peers)
            if replaced:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Chain was replaced."}).encode('utf-8'))
            else:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Our chain is authoritative."}).encode('utf-8'))

        elif self.path == '/policy/propose':
            policy_name = data.get('policy_name')
            policy_value = data.get('policy_value')
            sender = _node_id

            if policy_name is None or policy_value is None:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Policy name and value required."}).encode('utf-8'))
                return

            policy_tx = Transaction(
                sender=sender,
                recipient="Governance_Body",
                amount=0,
                data={"policy_name": policy_name, "policy_value": policy_value},
                tx_type="PolicyUpdate"
            )
            policy_tx.sign(_node_wallet.private_key)

            if _node_blockchain.add_transaction(policy_tx):
                self._set_headers(201)
                self.wfile.write(json.dumps({"message": "PolicyUpdate transaction added to pending pool and broadcast."}).encode('utf-8'))
                NodeCommunication.broadcast_transaction(policy_tx)
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Failed to add PolicyUpdate transaction (check authorization in logs)."}).encode('utf-8'))
        
        elif self.path == '/miner/add':
            miner_id = data.get('miner_id')
            if miner_id:
                _node_blockchain.add_authorized_miner(miner_id)
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": f"Miner '{miner_id}' added to authorized list on this node."}).encode('utf-8'))
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Miner ID required."}).encode('utf-8'))

        elif self.path == '/miner/remove':
            miner_id = data.get('miner_id')
            if miner_id:
                if _node_blockchain.remove_authorized_miner(miner_id):
                    self._set_headers(200)
                    self.wfile.write(json.dumps({"message": f"Miner '{miner_id}' removed from authorized list on this node."}).encode('utf-8'))
                else:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"message": f"Miner '{miner_id}' not found in authorized list."}).encode('utf-8'))
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Miner ID required."}).encode('utf-8'))

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"message": "Not Found"}).encode('utf-8'))


def _run_node_server(host_name, node_port):
    """Internal function to start the HTTP server."""
    server_address = (host_name, node_port)
    httpd = HTTPServer(server_address, NodeRequestHandler)
    print(f"\n{_node_id} server starting on {host_name}:{node_port}")
    httpd.serve_forever()

def background_consensus_and_synchronizer():
    """
    Periodically checks for proposed blocks that have met endorsement threshold,
    tries to add them to chain, and resolves conflicts.
    """
    while True:
        for block_hash, proposal_data in list(_node_blockchain.proposed_blocks.items()):
            block = proposal_data['block']
            endorsements = proposal_data['endorsements']
            
            # Use the BFT threshold for finalization check
            if len(endorsements) >= _node_blockchain.get_endorsement_threshold():
                print(f"\n{_node_id}: Proposed block #{block.index} '{block_hash[:8]}...' has reached endorsement threshold. Attempting to add to chain.")
                if _node_blockchain.add_block(block):
                    print(f"{_node_id}: Block #{block.index} successfully added after consensus.")
                else:
                    print(f"{_node_id}: Failed to add block #{block.index} '{block_hash[:8]}...' despite endorsements (might be chain conflict). Initiating conflict resolution.")
                    NodeCommunication.resolve_conflicts(_node_blockchain, _peers)

        time.sleep(15)
        print(f"\n{_node_id}: Running background chain synchronization and proposed block management...")
        NodeCommunication.resolve_conflicts(_node_blockchain, _peers)


def _load_policies_from_file(file_path):
    """Loads policies from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            policies = json.load(f)
        print(f"Loaded policies from {file_path}: {policies}")
        return policies
    except FileNotFoundError:
        print(f"Policy file not found: {file_path}. No initial policies loaded.")
        return {}
    except json.JSONDecodeError:
        print(f"Error decoding JSON from policy file: {file_path}. Using empty policies.")
        return {}
    except Exception as e:
        print(f"An unexpected error occurred loading policies from {file_path}: {e}")
        return {}


def start_node(config_file_path):
    """
    Initializes and starts a blockchain node by loading configuration from a file.
    """
    global _node_id, _node_port, _node_encryption_key, _peers, _node_blockchain, _node_wallet
    
    try:
        with open(config_file_path, 'r') as f:
            node_config = json.load(f)
        print(f"Loaded node configuration from {config_file_path}")
    except FileNotFoundError:
        print(f"Error: Node config file not found: {config_file_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in config file: {config_file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading node config from {config_file_path}: {e}")
        sys.exit(1)

    _node_id = node_config['NODE_ID']
    _node_port = node_config['NODE_PORT']
    _node_encryption_key = node_config['NODE_ENCRYPTION_KEY']
    _peers = node_config['PEERS']
    
    _node_wallet = Wallet(_node_id)

    _node_blockchain = Blockchain()
    _node_blockchain.register_organization(_node_id, _node_wallet.public_key)

    _node_blockchain.add_authorized_miner(_node_id)
    for peer in _peers:
        _node_blockchain.add_authorized_miner(peer['id'])
    
    all_org_ids = [_node_id] + [peer['id'] for peer in _peers]
    for org_id in all_org_ids:
        if org_id not in _node_blockchain.participating_organizations:
             _node_blockchain.register_organization(org_id, f"PUBLIC_KEY_{org_id}_dummy")


    if _node_id == "Hospital_1":
        policy_file_path = node_config.get('POLICY_FILE_PATH')
        if policy_file_path:
            initial_policies = _load_policies_from_file(policy_file_path)
            if initial_policies:
                print(f"\n{_node_id}: Proposing initial network policies from file via transactions...")
                for policy_name, policy_value in initial_policies.items():
                    policy_tx = Transaction(
                        sender=_node_id,
                        recipient="Governance_Body",
                        amount=0,
                        data={"policy_name": policy_name, "policy_value": policy_value},
                        tx_type="PolicyUpdate"
                    )
                    policy_tx.sign(_node_wallet.private_key)
                    if _node_blockchain.add_transaction(policy_tx):
                        NodeCommunication.broadcast_transaction(policy_tx)
                    else:
                        print(f"Failed to add initial policy transaction for '{policy_name}'.")
            else:
                print(f"No initial policies loaded from file: {policy_file_path}")
        else:
            print("POLICY_FILE_PATH not provided in node_config for Hospital_1. No initial policies proposed.")


    server_thread = threading.Thread(target=_run_node_server, args=('0.0.0.0', _node_port))
    server_thread.daemon = True
    server_thread.start()

    sync_thread = threading.Thread(target=background_consensus_and_synchronizer)
    sync_thread.daemon = True
    sync_thread.start()

    print(f"{_node_id} running... (Ctrl+C to stop)")
    print(f"{_node_id} blockchain chain length: {len(_node_blockchain.chain)}")
    print(f"{_node_id} current policies: {_node_blockchain.policies}")
    print(f"{_node_id} authorized miners: {_node_blockchain.authorized_miners}")
    print(f"{_node_id} current world state: {_node_blockchain.current_state}")
    print(f"{_node_id} node public key: {_node_wallet.public_key}")


    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{_node_id} shutting down.")
