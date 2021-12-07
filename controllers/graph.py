import json
from node import Node
from edge import Edge


class Graph:
    edges = []
    nodes = {}

    def __init__(self, top_file):
        self.edges = []
        self.edges_map = {}
        self.nodes = {}
        self._read_json(top_file)

    def _read_json(self, top_file):
        with open(top_file) as json_file:
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
        edge_str = str(Edge(n1, n2, 0, 0))
        return self.edges_map.get(edge_str, None)

    def set_edge_bw(self, n1, n2, bw):
        e = self.get_edge(n1, n2)
        if e is None:
            print("WARNING: cannot set edge bw because edge does not exist", n1, n2)
            return False

        e.bw = bw
        return True

    def subtract_path(self, path, weight):
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
        if name in self.nodes:
            # print("WARNING: cannot add duplicate node with name {}".format(name))
            return False
        self.nodes[name] = Node(name, n)
        return True
