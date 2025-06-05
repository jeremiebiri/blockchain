# node4.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import time
import urllib.request
import urllib.error

from blockchain_core import Blockchain, Transaction, Block, simple_hash, simulate_encrypt, simulate_decrypt

HOST_NAME = '0.0.0.0'
NODE_PORT = 5004
NODE_ID = "Hospital_4"
NODE_PRIVATE_KEY = "Hospital_4_private_key"
NODE_ENCRYPTION_KEY = "Hospital_4_ENC_Key"

# All nodes should know about each other
PEERS = [
    {'id': 'Hospital_1', 'address': 'http://node1:5001'},
    {'id': 'Hospital_2', 'address': 'http://node2:5002'},
    {'id': 'Hospital_3', 'address': 'http://node3:5003'}
]

node_blockchain = Blockchain()
node_blockchain.register_organization(NODE_ID, NODE_ID)

# --- PoA: Define Authorized Miners ---
node_blockchain.add_authorized_miner(NODE_ID)
for peer in PEERS:
    node_blockchain.add_authorized_miner(peer['id'])


class NodeCommunication:
    @staticmethod
    def _send_post_request(url, payload):
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
                    print(f"  Chain from {peer['id']} is longer but not valid (e.g., unauthorized miner).")

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
                "authorized_miners": list(node_blockchain.authorized_miners)
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
        elif self.path == '/mine_block':
            if not node_blockchain.is_miner_authorized(NODE_ID):
                self._set_headers(403)
                self.wfile.write(json.dumps({"message": f"Node {NODE_ID} is not authorized to mine blocks."}).encode('utf-8'))
                return

            if not node_blockchain.pending_transactions:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "No pending transactions to mine."}).encode('utf-8'))
                return

            new_block = node_blockchain.create_block(NODE_ID)
            if new_block:
                if node_blockchain.add_block(new_block):
                    NodeCommunication.broadcast_block(new_block)
                    self._set_headers(200)
                    self.wfile.write(json.dumps({"message": "Block created and broadcast.", "block": new_block.to_dict()}).encode('utf-8'))
                else:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"message": "Failed to add new block to local chain after creation (should not happen normally)."}).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps({"message": "Failed to create block (check logs for authorization/pending transactions)."}).encode('utf-8'))
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

        elif self.path == '/blocks/new':
            block_data = data.get('block')
            if not block_data:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "No block data provided."}).encode('utf-8'))
                return

            new_block = Block.from_dict(block_data)

            if node_blockchain.add_block(new_block):
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "New block received and added."}).encode('utf-8'))
                NodeCommunication.resolve_conflicts(node_blockchain, PEERS)
            else:
                print(f"Block #{new_block.index} received but failed to add. Initiating conflict resolution.")
                NodeCommunication.resolve_conflicts(node_blockchain, PEERS)
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Invalid or conflicting block received. Attempting to resolve."}).encode('utf-8'))

        elif self.path == '/resolve_conflict':
            replaced = NodeCommunication.resolve_conflicts(node_blockchain, PEERS)
            if replaced:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Chain was replaced."}).encode('utf-8'))
            else:
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": "Our chain is authoritative."}).encode('utf-8'))

        elif self.path == '/policy/set':
            policy_name = data.get('name')
            policy_value = data.get('value')
            if policy_name is not None and policy_value is not None:
                node_blockchain.set_policy(policy_name, policy_value)
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": f"Policy '{policy_name}' set."}).encode('utf-8'))
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"message": "Policy name and value required."}).encode('utf-8'))
        
        elif self.path == '/miner/add':
            miner_id = data.get('miner_id')
            if miner_id:
                node_blockchain.add_authorized_miner(miner_id)
                self._set_headers(200)
                self.wfile.write(json.dumps({"message": f"Miner '{miner_id}' added to authorized list on this node."}).encode('utf-8'))
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

def background_synchronizer():
    """
    Periodically tries to resolve conflicts to keep the chain synchronized.
    """
    while True:
        time.sleep(30)
        print(f"\n{NODE_ID}: Running background chain synchronization...")
        NodeCommunication.resolve_conflicts(node_blockchain, PEERS)


if __name__ == "__main__":
    for peer in PEERS:
        node_blockchain.register_organization(peer['id'], peer['id'])

    server_thread = threading.Thread(target=run_node_server)
    server_thread.daemon = True
    server_thread.start()

    sync_thread = threading.Thread(target=background_synchronizer)
    sync_thread.daemon = True
    sync_thread.start()

    print(f"{NODE_ID} running... (Ctrl+C to stop)")
    print(f"{NODE_ID} blockchain chain length: {len(node_blockchain.chain)}")
    print(f"{NODE_ID} current policies: {node_blockchain.policies}")
    print(f"{NODE_ID} authorized miners: {node_blockchain.authorized_miners}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{NODE_ID} shutting down.")
