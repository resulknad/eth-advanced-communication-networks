import json
from node import Node
from edge import Edge


class Graph:
    edges = []
    nodes = {}

    def __init__(self, topo_file):
        """Initializes a graph using the given topo.json file

        Args:
            topo_file (str): json file describing the topology
        """
        self.edges = []
        self.edges_map = {}
        self.nodes = {}
        self._read_json(topo_file)

    def _read_json(self, topo_file):
        """Reads and parses the json file. Adds the edges and nodes."""

        with open(topo_file) as json_file:
            data = json.load(json_file)
            for n in data["nodes"]:
                self.add_node(n["id"], n)

            for l in data["links"]:
                source = l["node1"]
                target = l["node2"]
                delay = float(l.get("delay", "0ms")[:-2])
                bw = l.get("bw", 2 ** 32)
                self.add_undirected_edge(source, target, delay, bw)

    def add_undirected_edge(self, source, target, delay, bw):
        """Adds an undirected edge to source <--> target with cost (delay) and capacity (bw).

        Args:
            source (str): the source node
            target (str): the destination node
            delay (float): cost / delay
            bw (float): capacity / bandwidth

        Returns:
            bool: successful or not
        """
        if source not in self.nodes or target not in self.nodes:
            print(
                "WARNING: either source or target node does not exist, cannot add edge {} - {}".format(
                    source, target
                )
            )
            return False

        e = Edge(source, target, delay, bw)
        self.nodes[source].add_edge(e)
        self.nodes[target].add_edge(e)
        self.edges.append(e)
        self.edges_map[str(e)] = e

        # add reverse edge
        e = Edge(target, source, delay, bw)
        self.nodes[source].add_edge(e)
        self.nodes[target].add_edge(e)
        self.edges.append(e)
        self.edges_map[str(e)] = e
        return True

    def get_edge(self, n1, n2):
        """Returns the Edge from n1 -> n2 if it exists

        Args:
            n1 (str): string describing node 1
            n2 (str): string describing node 2

        Returns:
            Edge: instance of an edge or None
        """
        edge_str = str(Edge(n1, n2, 0, 0))
        return self.edges_map.get(edge_str, None)

    def set_edge_bw(self, n1, n2, bw):
        """Sets the capacity of the edge between n1 -> n2 to bw

        Args:
            n1 (str): node string id
            n2 (str): node string id
            bw (float): [description]

        Returns:
            bool: if successful or not
        """
        e = self.get_edge(n1, n2)
        if e is None:
            print("WARNING: cannot set edge bw because edge does not exist", n1, n2)
            return False

        e.bw = bw
        return True

    def subtract_path(self, path, weight):
        """Subtracts for each edge e in the path "weight" much from its capacity / bandwidth. Quits with a warning printed
        to stdout if an edge has less than weight bandwidth / capacity left.

        Args:
            path (list(str)): list of nodestrings
            weight (float): weight of the path

        Returns:
            bool: success
        """
        for (n1, n2) in zip(path, path[1:]):
            e = self.get_edge(n1, n2)
            if e is None:
                print(
                    "WARNIING: cannot subtract path because edge does not exist", n1, n2
                )
                return False
            if e.bw - weight < 0:
                print(
                    "WARNING: path has too large of a weight, cannot subtract it. something does not add up",
                    e,
                    weight,
                )
            e.bw = max(0, e.bw - weight)
        return True

    def add_node(self, name, n=None):
        """Inserts a new node in the graph. Fails if node already exists with that name.

        Args:
            name (string): node name / identifier
            n (dict, optional): Additional information regarding the node. Defaults to None.

        Returns:
            bool: success
        """
        if name in self.nodes:
            return False
        self.nodes[name] = Node(name, n)
        return True
