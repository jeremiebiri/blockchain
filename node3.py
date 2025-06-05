# node3.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import time
import urllib.request
import urllib.error
import urllib.parse

from blockchain_core import Blockchain, Transaction, Block, simple_hash, simulate_encrypt, simulate_decrypt

HOST_NAME = '0.0.0.0'
NODE_PORT = 5003 # Changed for Node 3
NODE_ID = "Hospital_3" # Changed for Node 3
NODE_PRIVATE_KEY = "Hospital_3_private_key" # Changed for Node 3
NODE_ENCRYPTION_KEY = "Hospital_3_ENC_Key" # Changed for Node 3

# All nodes should know about each other for a complete consortium network
PEERS = [
    {'id': 'Hospital_1', 'address': 'http://node1:5001'},
    {'id': 'Hospital_2', 'address': 'http://node2:5002'},
    {'id': 'Hospital_4', 'address': 'http://node4:5004'}
]

# Initialize the blockchain for this node
node_blockchain = Blockchain()
node_blockchain.register_organization(NODE_ID, NODE_ID) # Register itself

# --- PoA: Define Authorized Miners (Validators) ---
node_blockchain.add_authorized_miner(NODE_ID) # Authorize itself
for peer in PEERS:
    node_blockchain.add_authorized_miner(peer['id']) # Authorize other known nodes


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
        for peer in PEERS:
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
        for peer in PEERS:
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
        for peer in PEERS:
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
    def resolve_conflicts(current_blockchain, peers):
        """
        Consensus algorithm: Simplified longest-chain rule.
        Also responsible for checking for proposed blocks that might have been finalized
        on other chains and for triggering endorsement if a valid new block appears.
        """
        longest_chain_data = None
        max_length = len(current_blockchain.chain)

        print(f"\n{NODE_ID} resolving conflicts: Checking peers for longer chains...")
        for peer in peers:
            print(f"  Fetching chain from {peer['id']} ({peer['address']})...")
            chain_response = NodeCommunication.fetch_chain(peer['address'])

            if chain_response and 'chain' in chain_response and chain_response['length'] > max_length:
                print(f"  {peer['id']} has a longer chain (length {chain_response['length']}). Validating...")
                
                temp_blockchain_for_validation = Blockchain()
                temp_blockchain_for_validation.chain = []
                temp_blockchain_for_validation.authorized_miners = set(current_blockchain.authorized_miners)
                
                if temp_blockchain_for_validation.replace_chain(chain_response['chain']):
                    max_length = chain_response['length']
                    longest_chain_data = chain_response['chain']
                    print(f"  Longer valid chain found from {peer['id']}.")
                else:
                    print(f"  Chain from {peer['id']} is longer but not valid (e.g., unauthorized miner or invalid transactions).")

        if longest_chain_data:
            print(f"{NODE_ID}: Found a longer valid chain. Replacing our chain...")
            return current_blockchain.replace_chain(longest_chain_data)
        
        print(f"{NODE_ID}: Our chain is the longest or no longer valid chain found among peers.")
        return False


class NodeRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        if self.path == '/status':
            self._set_headers()
            response = {
                "message": f"{NODE_ID} is up and running!",
                "chain_length": len(node_blockchain.chain),
                "pending_tx_count": len(node_blockchain.pending_transactions),
                "authorized_miners": list(node_blockchain.authorized_miners),
                "current_policies": node_blockchain.policies,
                "proposed_blocks_count": len(node_blockchain.proposed_blocks)
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/chain':
            self._set_headers()
            response = {"chain": node_blockchain.get_chain_as_list(), "length": len(node_blockchain.chain)}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/pending_transactions':
            self._set_headers()
            response = {"pending_transactions": node_blockchain.get_pending_transactions_as_list()}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/current_state':
            self._set_headers()
            response = {"current_state": node_blockchain.current_state}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/propose_block':
            if not node_blockchain.is_miner_authorized(NODE_ID):
                self._set_headers(403)
                self.wfile.write(json.dumps({"message": f"Node {NODE_ID} is not authorized to propose blocks."}).encode('utf-8'))
                return

            if not node_blockchain.pending_transactions:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "No pending transactions to propose a block."}).encode('utf-8'))
                return

            proposed_block = node_blockchain.propose_block(NODE_ID)
            if proposed_block:
                node_blockchain.add_proposed_block(proposed_block)
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
                if block_index >= len(node_blockchain.chain) or block_index < 0:
                    raise IndexError("Block index out of range")
                
                target_block = node_blockchain.chain[block_index]
                found_tx = None
                for tx in target_block.transactions:
                    if tx.calculate_hash() == tx_hash:
                        found_tx = tx
                        break
                
                if found_tx and found_tx.is_encrypted:
                    decrypted_data = simulate_decrypt(found_tx.data, NODE_ENCRYPTION_KEY)
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
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))

        if self.path == '/transactions/new':
            tx_data = data
            tx = Transaction.from_dict(tx_data)

            if node_blockchain.add_transaction(tx):
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
            
            if not node_blockchain.is_miner_authorized(proposed_block.miner):
                self._set_headers(403)
                self.wfile.write(json.dumps({"message": f"Received proposal from unauthorized miner '{proposed_block.miner}'."}).encode('utf-8'))
                return

            if node_blockchain.add_proposed_block(proposed_block):
                if node_blockchain.is_miner_authorized(NODE_ID):
                    node_blockchain.endorse_block(proposed_block.current_hash, NODE_ID)
                    NodeCommunication.broadcast_endorsement(proposed_block.current_hash, NODE_ID)
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
            
            if node_blockchain.endorse_block(block_hash, endorser_id):
                if block_hash in node_blockchain.proposed_blocks:
                    current_endorsements = len(node_blockchain.proposed_blocks[block_hash]['endorsements'])
                    required_endorsements = node_blockchain.get_endorsement_threshold()
                    
                    if current_endorsements >= required_endorsements:
                        finalized_block = node_blockchain.proposed_blocks[block_hash]['block']
                        print(f"Block #{finalized_block.index} '{block_hash[:8]}...' received enough endorsements ({current_endorsements}/{required_endorsements}). Attempting to add to chain.")
                        if node_blockchain.add_block(finalized_block):
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
            replaced = NodeCommunication.resolve_conflicts(node_blockchain, PEERS)
            if replaced:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Chain was replaced."}).encode('utf-8'))
            else:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Our chain is authoritative."}).encode('utf-8'))

        elif self.path == '/policy/propose':
            policy_name = data.get('policy_name')
            policy_value = data.get('policy_value')
            sender = data.get('sender', NODE_ID)
            signature = data.get('signature', f"signed_by_{sender}_somehash")

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
            policy_tx.sign(NODE_PRIVATE_KEY)

            if node_blockchain.add_transaction(policy_tx):
                self._set_headers(201)
                self.wfile.write(json.dumps({"message": "PolicyUpdate transaction added to pending pool and broadcast."}).encode('utf-8'))
                NodeCommunication.broadcast_transaction(policy_tx)
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Failed to add PolicyUpdate transaction (check authorization in logs)."}).encode('utf-8'))
        
        elif self.path == '/miner/add':
            miner_id = data.get('miner_id')
            if miner_id:
                node_blockchain.add_authorized_miner(miner_id)
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": f"Miner '{miner_id}' added to authorized list on this node."}).encode('utf-8'))
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Miner ID required."}).encode('utf-8'))

        elif self.path == '/miner/remove':
            miner_id = data.get('miner_id')
            if miner_id:
                if node_blockchain.remove_authorized_miner(miner_id):
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


def run_node_server():
    server_address = (HOST_NAME, NODE_PORT)
    httpd = HTTPServer(server_address, NodeRequestHandler)
    print(f"\n{NODE_ID} server starting on {HOST_NAME}:{NODE_PORT}")
    httpd.serve_forever()

def background_consensus_and_synchronizer():
    """
    Periodically checks for proposed blocks that have met endorsement threshold,
    tries to add them to chain, and resolves conflicts.
    """
    while True:
        for block_hash, proposal_data in list(node_blockchain.proposed_blocks.items()):
            block = proposal_data['block']
            endorsements = proposal_data['endorsements']
            
            if len(endorsements) >= node_blockchain.get_endorsement_threshold():
                print(f"\n{NODE_ID}: Proposed block #{block.index} '{block_hash[:8]}...' has reached endorsement threshold. Attempting to add to chain.")
                if node_blockchain.add_block(block):
                    print(f"{NODE_ID}: Block #{block.index} successfully added after consensus.")
                else:
                    print(f"{NODE_ID}: Failed to add block #{block.index} '{block_hash[:8]}...' despite endorsements (might be chain conflict). Initiating conflict resolution.")
                    NodeCommunication.resolve_conflicts(node_blockchain, PEERS)

        time.sleep(15)
        print(f"\n{NODE_ID}: Running background chain synchronization and proposed block management...")
        NodeCommunication.resolve_conflicts(node_blockchain, PEERS)


if __name__ == "__main__":
    all_org_ids = [NODE_ID] + [peer['id'] for peer in PEERS]
    for org_id in all_org_ids:
        node_blockchain.register_organization(org_id, org_id)

    # Node2, Node3, Node4 do NOT propose initial policies. They will receive them via broadcast.


    server_thread = threading.Thread(target=run_node_server)
    server_thread.daemon = True
    server_thread.start()

    sync_thread = threading.Thread(target=background_consensus_and_synchronizer)
    sync_thread.daemon = True
    sync_thread.start()

    print(f"{NODE_ID} running... (Ctrl+C to stop)")
    print(f"{NODE_ID} blockchain chain length: {len(node_blockchain.chain)}")
    print(f"{NODE_ID} current policies: {node_blockchain.policies}")
    print(f"{NODE_ID} authorized miners: {node_blockchain.authorized_miners}")
    print(f"{NODE_ID} current world state: {node_blockchain.current_state}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{NODE_ID} shutting down.")
