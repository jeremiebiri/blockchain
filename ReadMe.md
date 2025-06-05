Comprehensive Testing Instructions for Enhanced Blockchain

Follow these steps carefully to set up and test your multi-node consortium blockchain.

Step 0: Update Files

Ensure all files are saved: Make sure blockchain_core.py (from blockchain_core_enhanced), node1.py (from node1_next_level), node2.py (from node2_next_level), node3.py (from node3_next_level), node4.py (from node4_next_level), and docker-compose.yml (from docker_compose_updated in our previous conversation) are all in your consortium-blockchain-project directory.

Verify PEERS lists: Double-check that the PEERS list in all four node files (node1.py, node2.py, node3.py, node4.py) includes all other nodes in the network, as shown in the all_peers_config document previously:

PEERS = [
    {'id': 'Hospital_1', 'address': 'http://node1:5001'},
    {'id': 'Hospital_2', 'address': 'http://node2:5002'},
    {'id': 'Hospital_3', 'address': 'http://node3:5003'},
    {'id': 'Hospital_4', 'address': 'http://node4:5004'}
]


Step 1: Build and Run Docker Containers

Open your terminal in the consortium-blockchain-project directory.

Run the start.sh script:

./start.sh


This script (from start_sh immersive) will:

Stop and remove any old Docker containers and images.

Build new images using your updated code.

Start node1, node2, node3, and node4.

Observe the logs: In the terminal where docker-compose up is running, you should see:

All four nodes starting up.

Each node creating its Genesis block.

Each node registering itself and its peers as authorized_miners.

Hospital_1 (node1) proposing the initial network policies (restrict_sender_to_registered_orgs and min_ventilator_duration_hrs) as transactions. These will be broadcast but not immediately active.

Background consensus and synchronizer messages appearing every 15 seconds.

Step 2: Initial Status Checks

Open NEW terminal tabs/windows for testing (you'll likely want 4-5 tabs to observe different nodes and send commands).

Check each Node's Status:

curl http://localhost:5001/status
curl http://localhost:5002/status
curl http://localhost:5003/status
curl http://localhost:5004/status


Expected:

"message" should indicate the node is up.

"chain_length" should be 1 (only genesis block so far).

"pending_tx_count" on Node 1 should show 2 (for the initial policy transactions), and eventually all nodes will show 2 as they broadcast.

"authorized_miners" should list all four hospitals.

"current_policies" should initially be {} (empty) on all nodes, as policies are not active until mined into a block.

"proposed_blocks_count" should be 0.

Check Initial Chains:

curl http://localhost:5001/chain
curl http://localhost:5002/chain
curl http://localhost:5003/chain
curl http://localhost:5004/chain


Expected: All should show only the genesis block.

Check Initial World State:

curl http://localhost:5001/current_state


Expected: {"current_state": {}} (empty).

Step 3: Propose and Endorse a Block (Finalizing Initial Policies)

Now, let's get the initial policies into the blockchain. Since Hospital_1 proposed them, it can propose the first block.

Hospital_1 Proposes the First Block:

Go to your Node 1 terminal or open a new one.

curl http://localhost:5001/propose_block


Expected Logs:

Node 1: "Block #1 proposed by 'Hospital_1'...", then "Block proposed and broadcast for endorsement."

Node 2, 3, 4: "Block proposal received and added to pending proposals." and then "Block '...' endorsed by 'Hospital_X'." (as they automatically endorse).

All Nodes: Eventually, you will see messages like "Block #1 '...' received enough endorsements..." and "Block #1 successfully added after consensus."

Verify Policies are Active and Chain is Updated:

Give it a few seconds for propagation and background consensus to run.

curl http://localhost:5001/chain
curl http://localhost:5002/chain
curl http://localhost:5003/chain
curl http://localhost:5004/chain


Expected: All chains should now show two blocks: the genesis block and Block #1. Block #1 will contain the two PolicyUpdate transactions.

curl http://localhost:5001/status
curl http://localhost:5002/status
curl http://localhost:5003/status
curl http://localhost:5004/status


Expected: "current_policies" on all nodes should now reflect the policies:
{"restrict_sender_to_registered_orgs": true, "min_ventilator_duration_hrs": 1}.
This demonstrates on-chain governance successfully.

Step 4: Test Regular and Encrypted Transactions

Create a Regular Transaction (from Hospital 2):

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "Hospital_2",
    "recipient": "Hospital_1",
    "amount": 10,
    "data": {"type": "ventilator_log", "patient_id": "P001", "duration_hrs": 24},
    "signature": "signed_by_Hospital_2_somehash"
}' http://localhost:5002/transactions/new


Expected Logs: "Transaction added to pending..." and then "Broadcasting transaction..." on Node 2, and "Transaction added to pending..." on other nodes.

Create an ENCRYPTED Transaction (from Hospital 3):

IMPORTANT: Simulate encryption. You'd normally use simulate_encrypt in your application. For this curl, we'll manually encode the data.

Example: simulate_encrypt(json.dumps({"type": "patient_lab_results", "patient_id": "P004", "results": "Normal"}), "Hospital_3_ENC_Key") might yield:
ENC:Hospital_3_ENC_Key:eyJ0eXBlIjogInBhdGllbnRfbGFiX3Jlc3VsdHMiLCAicGF0aWVudF9pZCI6ICJQMDA0IiwgInJlc3VsdHMiOiAiTm9ybWFsIn0=

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "Hospital_3",
    "recipient": "Hospital_4",
    "amount": 5,
    "data": "ENC:Hospital_3_ENC_Key:eyJ0eXBlIjogInBhdGllbnRfbGFiX3Jlc3VsdHMiLCAicGF0aWVudF9pZCI6ICJQMDA0IiwgInJlc3VsdHMiOiAiTm9ybWFsIn0=",
    "is_encrypted": true,
    "signature": "signed_by_Hospital_3_someotherhash"
}' http://localhost:5003/transactions/new


Expected Logs: Similar transaction added and broadcast messages, but the data will show as "Encrypted".

Check Pending Transactions (all nodes):

curl http://localhost:5001/pending_transactions
curl http://localhost:5002/pending_transactions
curl http://localhost:5003/pending_transactions
curl http://localhost:5004/pending_transactions


Expected: All nodes should now have both transactions in their pending pool.

Step 5: Propose and Endorse Another Block (Updating World State)

Let's have Node 4 propose the next block.

Hospital_4 Proposes Block:

curl http://localhost:5004/propose_block


Expected Logs:

Node 4: "Block #2 proposed by 'Hospital_4'...", then broadcast.

Node 1, 2, 3: Receive proposal, add to proposed pool, automatically endorse, and broadcast endorsement.

All Nodes: Eventually, "Block #2 '...' received enough endorsements...", then "Block #2 successfully added after consensus."

Verify Chains and World State:

Give it a few seconds for consensus.

curl http://localhost:5001/chain
# ... check other nodes' chains


Expected: All chains should now have 3 blocks. Block #2 will contain the two transactions.

curl http://localhost:5001/current_state
# ... check other nodes' states


Expected: The current_state on all nodes should now reflect the changes from the ventilator_log transaction:
{"patient_P001_ventilator_total_hrs": 24, "patient_P001_last_ventilator_log": <timestamp_value>}
The encrypted transaction does not update the world state directly, as its content is not publicly decipherable by the blockchain logic.

Step 6: Test Data Decryption

Identify Encrypted Transaction Hash:

Use curl http://localhost:5003/chain to view the chain data on Node 3. Find Block #2 (index 2). Locate the transaction from Hospital_3 to Hospital_4 with is_encrypted: true. Copy its calculate_hash() value (this is the tx_hash).

Attempt Decryption from Node 3 (which has the key):

Replace TX_HASH_OF_ENCRYPTED_TX with the actual hash you copied.

curl "http://localhost:5003/transaction/decrypt?block_index=2&tx_hash=TX_HASH_OF_ENCRYPTED_TX"


Expected: {"message": "Decrypted data.", "data": {"type": "patient_lab_results", "patient_id": "P004", "results": "Normal"}, ...}. Successful decryption!

Attempt Decryption from Node 1 (which does NOT have Node 3's key):

Use the same TX_HASH_OF_ENCRYPTED_TX.

curl "http://localhost:5001/transaction/decrypt?block_index=2&tx_hash=TX_HASH_OF_ENCRYPTED_TX"


Expected: {"message": "Could not decrypt transaction data (incorrect key or malformed).", ...}. This demonstrates the restricted access.

Step 7: Test Policy Enforcement (On-Chain Governance)

Try to Send an Unauthorized Transaction (should fail due to policy):

The policy restrict_sender_to_registered_orgs: true is now active.

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "Unauthorized_Org",
    "recipient": "Hospital_1",
    "amount": 1,
    "data": {"type": "test_unauth"},
    "signature": "signed_by_Unauthorized_Org_somehash"
}' http://localhost:5001/transactions/new


Expected: Node 1 logs will show "Policy Violation: Sender 'Unauthorized_Org' is not a registered organization." The API response will be {"message": "Invalid transaction."}. This confirms the policy is enforced.

This complete setup demonstrates a functional consortium blockchain with a more advanced consensus model, on-chain policy management, and a basic world state, all built from scratch!