from typing import List
from dataclasses import dataclass

from flow_endpoint import FlowEndpoint


@dataclass
class Flow:
    """Represents a flow between two hosts in the network.
    If known, it may have an associated time interval.
    """

    src: str
    """Source host name"""
    sport: int
    """Source port"""
    dst: str
    """Destination host name"""
    dport: int
    """Destination port"""
    protocol: str
    """Either 'tcp' or 'udp'"""
    rate: float
    """Flow rate in Mbps"""
    start_time: float = -1
    """Start time relative to simulation start or -1"""
    end_time: float = -1
    """End time relative to simulation start or -1"""
    @staticmethod
    def from_df(df) -> List['Flow']:
        """Extracts a list of flows from a pandas DataFrame received from
        parsing a traffic CSV file.

        Args:
            df (pandas.DataFrame): Flows encoded as a dataflow

        Returns:
            list(Flow): The same flows encapsulated in the Flow class
        """
        res = []
        for (_, f) in df.iterrows():
            res.append(
                Flow(f["src"], int(f["sport"]), f["dst"], int(f["dport"]), f["protocol"], float(f["rate"][:-4]),
                     float(f["start_time"]), float(f["end_time"])))
        return res

    def to_source_endpoint(self) -> FlowEndpoint:
        return FlowEndpoint(host=self.src, port=self.sport, protocol=self.protocol)

    def to_dest_endpoint(self) -> FlowEndpoint:
        return FlowEndpoint(host=self.dst, port=self.dport, protocol=self.protocol)

    def is_tcp(self) -> bool:
        return self.protocol == "tcp"

    def is_udp(self) -> bool:
        return self.protocol == "udp"

    def duration(self) -> float:
        return self.end_time - self.start_time
