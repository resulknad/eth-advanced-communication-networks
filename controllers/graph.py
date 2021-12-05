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

    def add_node(self, name, n=None):
        if name in self.nodes:
            # print("WARNING: cannot add duplicate node with name {}".format(name))
            return False
        self.nodes[name] = Node(name, n)
        return True
