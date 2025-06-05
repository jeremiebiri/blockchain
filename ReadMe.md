ow to Run and Test This Updated Project:

Save the files: Ensure blockchain_core.py, node1.py, node2.py, Dockerfile, and docker-compose.yml are all in the consortium-blockchain-project directory.

Open your terminal in the consortium-blockchain-project directory.

Build and run the containers:

Bash

docker-compose up --build
You should see both nodes starting and printing "Genesis block created."

Open a NEW terminal tab/window for testing:

Check Node 1's chain:

Bash

curl http://localhost:5001/chain
Expected: A JSON object with chain (containing only the genesis block) and length: 1.

Check Node 2's chain:

Bash

curl http://localhost:5002/chain
Expected: Same as Node 1.

Create a Transaction from Hospital 1:

Bash

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "Hospital_1",
    "recipient": "Hospital_2",
    "amount": 10,
    "data": {"type": "ventilator_log", "patient_id": "P001", "duration_hrs": 24},
    "signature": "signed_by_Hospital_1_somehash"
}' http://localhost:5001/transactions/new
(You'll see "Transaction added to pending..." in the node1 logs.)

Create another Transaction from Hospital 2:

Bash

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "Hospital_2",
    "recipient": "Hospital_3",
    "amount": 5,
    "data": {"type": "patient_transfer", "patient_id": "P002", "from_unit": "ICU"},
    "signature": "signed_by_Hospital_2_someotherhash"
}' http://localhost:5002/transactions/new
(You'll see "Transaction added to pending..." in the node2 logs.)

Check Pending Transactions on Node 1:

Bash

curl http://localhost:5001/pending_transactions
Expected: The transaction sent to Node 1 (if you ran the previous command to node1). Crucially, it will NOT include the transaction sent to Node 2 yet. We need broadcasting for that.

Mine a Block on Node 1: (Simulating Hospital 1 being the designated validator for this round)

Bash

curl http://localhost:5001/mine_block
You should see "Block #1 created by Hospital_1..." in the node1 logs. The output will also include the block data.

Check Node 1's chain again:

Bash

curl http://localhost:5001/chain
Now it should show two blocks (genesis + new block).

Check Node 2's chain:

Bash

curl http://localhost:5002/chain
It will still only show the genesis block! This is because we haven't implemented automatic broadcasting of newly mined blocks or chain synchronization (the resolve_conflict endpoint). This is our next crucial step.

Manually Trigger Chain Synchronization on Node 2:

Bash

curl http://localhost:5002/resolve_conflict# blockchain
