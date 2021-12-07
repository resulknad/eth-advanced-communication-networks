from dataclasses import dataclass


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

    def __hash__(self):
        return hash(str(self))
