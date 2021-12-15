class Node:
    """Represents a node in our graph."""

    def __init__(self, name, obj):
        """Initializes a new node.

        Args:
            name (str): identifier of the node
            obj (dict): additional information for the node
        """    
        self.edges = []
        self.edges_map = {}
        self.name = name
        self.obj = obj

    def add_edge(self, e):
        self.edges.append(e)

        other = e.target if e.source == self.name else e.source
        self.edges_map[other] = e
