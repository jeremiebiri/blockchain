# blockchain_node.py
import os
import sys

# Add the directory containing common_node_logic.py and blockchain_core.py to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import the common logic
from common_node_logic import start_node

if __name__ == "__main__":
    # Get the config file path from command line arguments
    # Expected: python blockchain_node.py config/nodeX_config.json
    if len(sys.argv) < 2:
        print("Usage: python blockchain_node.py <path_to_config_file.json>")
        sys.exit(1)
    
    config_file_path = sys.argv[1]
    start_node(config_file_path)

