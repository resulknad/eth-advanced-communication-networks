class Edge:
    target = ""
    source = ""
    delay = ""
    bw = ""
    def __init__(self, source, target, delay, bw):
        self.source = source
        self.target = target
        self.delay = delay
        self.bw = bw

    def __repr__(self):
        return self.source + "|" + self.target
