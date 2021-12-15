class Edge:
    """Representation of a single directed edge of our flow graph"""    

    target = ""
    """Target node string identifier"""

    source = ""
    """Source node string identifier"""

    delay = ""
    """Delay (cost) of the edge"""

    bw = ""
    """Bandwidth (capacity) of the edge"""

    def __init__(self, source, target, delay, bw):
        """Initializes a new instance of Edge

        Args:
            source (str): identifier of edge source
            target (str): identifier of edge sink
            delay (float): cost of edge
            bw (float): bandwidth (capacity) of edge
        """

        self.source = source
        self.target = target
        self.delay = delay
        self.bw = bw

    def __repr__(self):
        """Returns a string identifier of the edge"""

        return self.source + "|" + self.target