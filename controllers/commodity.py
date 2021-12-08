from dataclasses import dataclass
from flow_endpoint import FlowEndpoint


@dataclass
class Commodity:
    source: str
    target: str
    demand: float
    cost_multiplier: float

    def __repr__(self):
        return "{}:{}:{}:{}".format(
            self.source, self.target, self.demand, self.cost_multiplier
        )

    def is_empty(self):
        return self.source == "" or self.target == ""

    def target_as_fe(self):
        return FlowEndpoint.fromString(self.target)

    def source_as_fe(self):
        return FlowEndpoint.fromString(self.source)

    def __hash__(self):
        return hash(str(self))
