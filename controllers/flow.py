from dataclasses import dataclass
from flow_endpoint import FlowEndpoint

@dataclass
class Flow:
    src: str
    sport: int
    dst: str
    dport: int
    protocol: str
    rate: float
    start_time: float = -1
    end_time: float = -1

    @staticmethod
    def from_df(df):
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

