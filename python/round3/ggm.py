"""
GGM tree for SDitH v2.

Binary tree of seeds used for VOLE pair generation. The prover holds
the full tree; the verifier reconstructs all but the hidden leaves
from a sibling path.

Tree indexing: node 1 is the root. Node i has children 2i and 2i+1,
parent i//2, and sibling i^1.
"""

from utils import extract_bits


def _walk_hidden_path(hidden_node_indices, on_unpaired, on_paired=None):
    """Walk up the tree from hidden leaves, merging paired siblings.

    Calls on_unpaired(node_index) for each node whose sibling is NOT
    also hidden (i.e. the sibling seed must be revealed).
    Optionally calls on_paired(node_index, next_node) when two
    adjacent queue entries are siblings (both hidden).
    """
    queue = list(reversed(hidden_node_indices))
    read_pos = 0
    while len(queue) - read_pos >= 2:
        current = queue[read_pos]
        read_pos += 1
        if (current ^ queue[read_pos]) == 1:
            if on_paired:
                on_paired(current, queue[read_pos])
            read_pos += 1
        else:
            on_unpaired(current)
        queue.append(current // 2)
    while queue[read_pos] != 1:
        on_unpaired(queue[read_pos])
        queue[read_pos] = queue[read_pos] // 2


class GGMTree:
    """Prover's full GGM seed tree with lazy expansion."""

    def __init__(self, params, salt, root_seed):
        self.params = params
        self.salt = salt
        self.num_leaves = params.num_leaves
        self._cache = {1: root_seed}

    def _get_node_seed(self, node_index):
        """Recursively expand and cache the seed for a tree node."""
        if node_index in self._cache:
            return self._cache[node_index]
        parent_seed = self._get_node_seed(node_index // 2)
        left_index = node_index & ~1  # even sibling
        left_right = self.params.ggm_seed_rng_lr(
            self.salt, parent_seed, left_index)
        seed_size = self.params.lambda_bytes
        self._cache[left_index] = left_right[:seed_size]
        self._cache[left_index | 1] = left_right[seed_size:2 * seed_size]
        return self._cache[node_index]

    def get_leaf_seed_commit(self, leaf_index):
        """Return (seed, commitment) for a leaf by its 0-based leaf index."""
        node_index = leaf_index + self.num_leaves
        seed = self._get_node_seed(node_index)
        commitment = self.params.ggm_commit_rng(
            self.salt, seed, node_index)
        return seed, commitment

    def open_sibling_path(self, hidden_node_indices):
        """Open the tree, revealing sibling seeds for all non-hidden paths.

        Args:
            hidden_node_indices: sorted list of hidden leaf node indices
                (already offset by num_leaves).

        Returns:
            (sibling_seeds, hidden_commitments)
        """
        hidden_commitments = []
        for node_index in hidden_node_indices:
            _, commitment = self.get_leaf_seed_commit(
                node_index - self.num_leaves)
            hidden_commitments.append(commitment)

        sibling_seeds = []

        def reveal_sibling(node_index):
            sibling_seeds.append(
                self._get_node_seed(node_index ^ 1))

        _walk_hidden_path(hidden_node_indices, reveal_sibling)
        return sibling_seeds, hidden_commitments


def estimate_topen(tau, kappa, target_topen, hidden_node_indices):
    """Count how many sibling seeds are needed for these hidden leaves."""
    count = [0]

    def increment(_node_index):
        count[0] += 1

    _walk_hidden_path(hidden_node_indices, increment)
    return count[0]


def decode_hidden_leaf_indices(kappa, tau, delta0):
    """Decode delta0 into sorted hidden leaf node indices."""
    num_leaves = tau * (1 << kappa)
    indices = []
    for k in range(tau):
        position = extract_bits(kappa, k * kappa, delta0)
        indices.append(position * tau + k + num_leaves)
    indices.sort()
    return indices


class GGMSiblingTree:
    """Verifier's partial tree, reconstructed from a sibling path."""

    NORMAL = 0
    SIBLING_ROOT = 1
    HIDDEN_NODE = 2
    HIDDEN_LEAF = 3

    def __init__(self, params, salt, hidden_node_indices,
                 sibling_seeds, hidden_commitments):
        self.params = params
        self.salt = salt
        self.num_leaves = params.num_leaves
        self.sibling_seeds = sibling_seeds
        self.hidden_commitments = hidden_commitments
        self.layout = {}

        for i, node_index in enumerate(hidden_node_indices):
            self.layout[node_index] = (self.HIDDEN_LEAF, i)

        sibling_count = 0

        def mark_sibling(node_index):
            nonlocal sibling_count
            self.layout[node_index ^ 1] = (
                self.SIBLING_ROOT, sibling_count)
            sibling_count += 1

        # Walk up the tree, building the layout
        queue = list(reversed(hidden_node_indices))
        read_pos = 0
        while len(queue) - read_pos >= 2:
            current = queue[read_pos]
            read_pos += 1
            parent = current // 2
            if (current ^ queue[read_pos]) == 1:
                read_pos += 1
            else:
                mark_sibling(current)
            self.layout[parent] = (self.HIDDEN_NODE, 0)
            queue.append(parent)
        while queue[read_pos] != 1:
            mark_sibling(queue[read_pos])
            queue[read_pos] = queue[read_pos] // 2
            self.layout[queue[read_pos]] = (self.HIDDEN_NODE, 0)

        self._cache = {}

    def _get_node_seed(self, node_index):
        """Expand a node, returning None for hidden subtrees."""
        if node_index in self._cache:
            return self._cache[node_index]
        entry = self.layout.get(node_index)
        if entry:
            node_type, address = entry
            if node_type == self.SIBLING_ROOT:
                self._cache[node_index] = self.sibling_seeds[address]
                return self._cache[node_index]
            if node_type in (self.HIDDEN_NODE, self.HIDDEN_LEAF):
                return None
        parent_seed = self._get_node_seed(node_index // 2)
        if parent_seed is None:
            return None
        left_index = node_index & ~1
        seed_size = self.params.lambda_bytes
        left_right = self.params.ggm_seed_rng_lr(
            self.salt, parent_seed, left_index)
        self._cache[left_index] = left_right[:seed_size]
        self._cache[left_index | 1] = left_right[seed_size:2 * seed_size]
        return self._cache[node_index]

    def get_leaf_seed_commit(self, leaf_index):
        """Return (seed, commitment) for a leaf.

        For hidden leaves, returns (None, stored_commitment).
        """
        node_index = leaf_index + self.num_leaves
        entry = self.layout.get(node_index)
        if entry and entry[0] == self.HIDDEN_LEAF:
            return None, self.hidden_commitments[entry[1]]
        seed = self._get_node_seed(node_index)
        if seed is None:
            return None, None
        commitment = self.params.ggm_commit_rng(
            self.salt, seed, node_index)
        return seed, commitment
