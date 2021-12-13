class Node:
    def __init__(self, name, obj):
        self.edges = []
        self.edges_map = {}
        self.name = name
        self.obj = obj

    def add_edge(self, e):
        self.edges.append(e)

        other = e.target if e.source == self.name else e.source
        self.edges_map[other] = e
