# node1.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import time
import urllib.request
import urllib.error # Import for catching HTTP errors

# Import the core blockchain logic
from blockchain_core import Blockchain, Transaction, Block, simple_hash

HOST_NAME = '0.0.0.0'
NODE_PORT = 5001 # Changed from NODE1_PORT for generality
NODE_ID = "Hospital_1" # This node's unique identifier and public key
NODE_PRIVATE_KEY = "Hospital_1_private_key" # Simplified private key

# List of known peers (other nodes' addresses)
# In Docker, use service names for inter-container communication
PEERS = [
    {'id': 'Hospital_2', 'address': 'http://node2:5002'}
    # Add more hospitals here if needed, e.g., {'id': 'Hospital_3', 'address': 'http://node3:5003'}
]

# Initialize the blockchain for this node
node_blockchain = Blockchain()
node_blockchain.register_organization(NODE_ID, NODE_ID) # Register itself

# CONCEPTUAL: Board of Government's special node
# In a real setup, this might be a separate dedicated service or a special role
# assigned to one or more of the existing hospital nodes.
# For demo, we'll let Hospital_1 act as the policy setter.
if NODE_ID == "Hospital_1":
    node_blockchain.set_policy('restrict_sender_to_registered_orgs', True)
    node_blockchain.set_policy('min_ventilator_duration_hrs', 1)


class NodeCommunication:
    """Helper class for inter-node communication."""

    @staticmethod
    def _send_post_request(url, payload):
        """Helper to send a POST request with JSON payload."""
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as response: # Added timeout
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.URLError as e:
            # print(f"  Network error communicating with {url}: {e.reason}") # More specific error
            raise ConnectionError(f"Failed to connect to {url}: {e.reason}") from e
        except Exception as e:
            # print(f"  Error sending POST to {url}: {e}")
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
    def broadcast_block(block):
        """Broadcasts a newly mined block to all known peers."""
        print(f"\nBroadcasting block #{block.index} to peers...")
        for peer in PEERS:
            try:
                NodeCommunication._send_post_request(
                    f"{peer['address']}/blocks/new",
                    {"block": block.to_dict()}
                )
                print(f"  Sent block to {peer['id']}")
            except ConnectionError as e:
                print(f"  Skipping {peer['id']}: {e}")
            except RuntimeError as e:
                print(f"  Error broadcasting to {peer['id']}: {e}")

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
        Consensus algorithm: Our simplified version for consortium.
        If a longer valid chain exists, replace ours.
        This is a basic longest-chain rule. In a real consortium,
        it would be a more robust voting/PBFT-like mechanism.
        """
        longest_chain_data = None
        max_length = len(current_blockchain.chain)

        print(f"\n{NODE_ID} resolving conflicts: Checking peers for longer chains...")
        for peer in peers:
            print(f"  Fetching chain from {peer['id']} ({peer['address']})...")
            chain_response = NodeCommunication.fetch_chain(peer['address'])

            if chain_response and 'chain' in chain_response and chain_response['length'] > max_length:
                print(f"  {peer['id']} has a longer chain (length {chain_response['length']}). Validating...")
                # Temporarily create a dummy blockchain to validate the candidate chain
                # This avoids corrupting the current_blockchain if the candidate is invalid.
                temp_blockchain_for_validation = Blockchain()
                temp_blockchain_for_validation.chain = [] # Clear its genesis block

                if temp_blockchain_for_validation.replace_chain(chain_response['chain']): # replace_chain method includes is_chain_valid
                    max_length = chain_response['length']
                    longest_chain_data = chain_response['chain']
                    print(f"  Longer valid chain found from {peer['id']}.")
                else:
                    print(f"  Chain from {peer['id']} is longer but not valid.")

        if longest_chain_data:
            print(f"{NODE_ID}: Found a longer valid chain. Replacing our chain...")
            return current_blockchain.replace_chain(longest_chain_data)
        
        print(f"{NODE_ID}: Our chain is the longest or no longer valid chain found among peers.")
        return False


class NodeRequestHandler(BaseHTTPRequestHandler): # Renamed for clarity
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        if self.path == '/status':
            self._set_headers()
            response = {"message": f"{NODE_ID} is up and running!", "chain_length": len(node_blockchain.chain), "pending_tx_count": len(node_blockchain.pending_transactions)}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/chain':
            self._set_headers()
            response = {"chain": node_blockchain.get_chain_as_list(), "length": len(node_blockchain.chain)}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/pending_transactions':
            self._set_headers()
            response = {"pending_transactions": node_blockchain.get_pending_transactions_as_list()}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/mine_block':
            if not node_blockchain.pending_transactions:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "No pending transactions to mine."}).encode('utf-8'))
                return

            new_block = node_blockchain.create_block(NODE_ID)
            if new_block:
                # IMPORTANT: This is where we broadcast the new block
                # We need to add it to our own chain *first* (which create_block doesn't do)
                # and then broadcast it. Let's make it a separate `propose_block` function.
                if node_blockchain.add_block(new_block): # Add to self before broadcasting
                    NodeCommunication.broadcast_block(new_block)
                    self._set_headers(200)
                    self.wfile.write(json.dumps({"message": "Block created and broadcast.", "block": new_block.to_dict()}).encode('utf-8'))
                else:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"message": "Failed to add new block to local chain after creation (should not happen normally)."}).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps({"message": "Failed to create block."}).encode('utf-8'))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"message": "Not Found"}).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))

        if self.path == '/transactions/new':
            tx_data = data
            tx = Transaction.from_dict(tx_data) # Use from_dict to reconstruct

            if node_blockchain.add_transaction(tx):
                self._set_headers(201)
                self.wfile.write(json.dumps({"message": "Transaction added to pending pool."}).encode('utf-8'))
                # IMPORTANT: Broadcast the new transaction to other nodes
                # This ensures eventual consistency of pending pools
                NodeCommunication.broadcast_transaction(tx)
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Invalid transaction."}).encode('utf-8'))

        elif self.path == '/blocks/new':
            # Receive a new block proposed by another node for validation
            block_data = data.get('block')
            if not block_data:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "No block data provided."}).encode('utf-8'))
                return

            new_block = Block.from_dict(block_data) # Use from_dict to reconstruct

            # Attempt to add the block to this node's chain
            # If the block is valid and extends our chain, add it.
            # Otherwise, it might trigger a conflict resolution.
            if node_blockchain.add_block(new_block):
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "New block received and added."}).encode('utf-8'))
                # After successfully adding a block, it's good practice to try to resolve
                # conflicts in case another node has a longer chain that we just missed.
                NodeCommunication.resolve_conflicts(node_blockchain, PEERS)
            else:
                # If the block couldn't be added, it indicates a divergence or invalid block.
                # Trigger conflict resolution to get the correct chain.
                print(f"Block #{new_block.index} received but failed to add. Initiating conflict resolution.")
                NodeCommunication.resolve_conflicts(node_blockchain, PEERS)
                self._set_headers(400) # Or 409 Conflict
                self.wfile.write(json.dumps({"message": "Invalid or conflicting block received. Attempting to resolve."}).encode('utf-8'))

        elif self.path == '/resolve_conflict':
            # Endpoint to manually trigger chain synchronization/conflict resolution
            replaced = NodeCommunication.resolve_conflicts(node_blockchain, PEERS)
            if replaced:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Chain was replaced."}).encode('utf-8'))
            else:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Our chain is authoritative."}).encode('utf-8'))

        elif self.path == '/policy/set':
            # Endpoint for Board of Government to set policies (simplified)
            policy_name = data.get('name')
            policy_value = data.get('value')
            if policy_name is not None and policy_value is not None:
                # For this simple demo, any node can set a policy.
                # In real scenario, this would be restricted to authorized BOG nodes.
                node_blockchain.set_policy(policy_name, policy_value)
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": f"Policy '{policy_name}' set."}).encode('utf-8'))
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Policy name and value required."}).encode('utf-8'))

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"message": "Not Found"}).encode('utf-8'))


def run_node_server():
    server_address = (HOST_NAME, NODE_PORT)
    httpd = HTTPServer(server_address, NodeRequestHandler)
    print(f"\n{NODE_ID} server starting on {HOST_NAME}:{NODE_PORT}")
    httpd.serve_forever()

def background_synchronizer():
    """
    Periodically tries to resolve conflicts to keep the chain synchronized.
    In a real system, this might be event-driven (e.g., after receiving a new block)
    or more sophisticated.
    """
    while True:
        time.sleep(30) # Check every 30 seconds
        print(f"\n{NODE_ID}: Running background chain synchronization...")
        NodeCommunication.resolve_conflicts(node_blockchain, PEERS)


if __name__ == "__main__":
    # Register other organizations for potential future validation/permissioning
    for peer in PEERS:
        node_blockchain.register_organization(peer['id'], peer['id'])

    # Start the HTTP server in a separate thread
    server_thread = threading.Thread(target=run_node_server)
    server_thread.daemon = True
    server_thread.start()

    # Start the background synchronizer thread
    sync_thread = threading.Thread(target=background_synchronizer)
    sync_thread.daemon = True
    sync_thread.start()

    print(f"{NODE_ID} running... (Ctrl+C to stop)")
    print(f"{NODE_ID} blockchain chain length: {len(node_blockchain.chain)}")
    print(f"{NODE_ID} current policies: {node_blockchain.policies}")

    try:
        while True:
            time.sleep(1) # Keep main thread alive
    except KeyboardInterrupt:
        print(f"\n{NODE_ID} shutting down.")