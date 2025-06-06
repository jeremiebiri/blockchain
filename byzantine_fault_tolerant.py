# byzantine_fault_tolerant.py
import math

def get_bft_endorsement_threshold(num_authorized_miners):
    """
    Calculates the minimum number of endorsements required for a block to achieve
    Byzantine Fault Tolerance (BFT).

    This implementation follows the common (2f + 1) rule, where 'f' is the
    maximum number of Byzantine (malicious or faulty) nodes the system can tolerate.
    For N total nodes (num_authorized_miners), a system can tolerate up to f Byzantine nodes
    if N >= 3f + 1.

    Rearranging, f = (N - 1) / 3.
    So, the number of required honest nodes (endorsements) is (2 * f) + 1.

    Args:
        num_authorized_miners (int): The total number of authorized miners (validators) in the network.

    Returns:
        int: The minimum number of endorsements needed to achieve BFT consensus.
             Ensures at least 1 endorsement is always required.
    """
    if num_authorized_miners <= 0:
        return 1 # Should not happen in a functional network, but handle edge case

    # Maximum 'f' (Byzantine nodes) we can tolerate for the given N
    # Since N >= 3f + 1, then (N - 1) / 3 >= f. We take the floor as f must be an integer.
    f_max = math.floor((num_authorized_miners - 1) / 3)

    # Required endorsements = 2f + 1
    # This ensures that even if 'f' nodes are malicious, the remaining (N - f) nodes,
    # of which at least (2f + 1) are honest, can form a supermajority.
    bft_threshold = (2 * f_max) + 1

    # Ensure the threshold is at least 1 and not more than total miners
    return max(1, min(bft_threshold, num_authorized_miners))

