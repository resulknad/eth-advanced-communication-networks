from dataclasses import dataclass

@dataclass
class FlowEndpoint:
    """Represents an endpoint of a flow (so protocol, host and port)"""
    
    host: str
    """Hostname"""

    port: int
    """Port"""

    protocol: str
    """Protocol (TCP or UDP)"""

    def __repr__(self):
        """Returns as string representation of the FlowEndpoint"""
        return "{}:{}:{}".format(self.host, self.port, self.protocol)

    def __hash__(self):
        return hash(str(self))

    @staticmethod
    def fromString(repr):
        """Parses a string identifier into a FlowEndpoint"""
        splitted = repr.split(":")
        if len(splitted) != 3 or not splitted[1].isdigit():
            return None
        return FlowEndpoint(splitted[0], int(splitted[1]), splitted[2])

    def get_switch(self) -> str:
        """Returns the switch to which the host is attached (the first three characters of the hostname)"""
        # The switch name is the first three characters of the host name
        return self.host[:3]
