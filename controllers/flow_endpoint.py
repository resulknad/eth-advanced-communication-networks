from dataclasses import dataclass

@dataclass
class FlowEndpoint:
    host: str
    port: int
    protocol: str

    def __repr__(self):
        return "{}:{}:{}".format(self.host, self.port, self.protocol)

    def __hash__(self):
        return hash(str(self))

    @staticmethod
    def fromString(repr):
        splitted = repr.split(":")
        if len(splitted) != 3 or not splitted[1].isdigit():
            return None
        return FlowEndpoint(splitted[0], int(splitted[1]), splitted[2])

    def get_switch(self) -> str:
        # The switch name is the first three characters of the host name
        return self.host[:3]
