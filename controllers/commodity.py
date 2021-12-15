from dataclasses import dataclass
from flow_endpoint import FlowEndpoint


@dataclass
class Commodity:
    """Represents a commodity (flow), with the two FlowEndpoints (nodes in the graph),
    the demand (bandwidth requirements) and the optional cost_multiplier"""    
    
    source: str
    """Commodity source as string"""    
    
    target: str
    """Commodty destination as string"""

    demand: float
    """Bandwidth demand of this flow / commodity"""

    cost_multiplier: float
    """Cost multiplier to set the priority of reducing cost of this flow relative to the other flows"""

    def __repr__(self):
        """Returns a unique string representation of the commodity"""        
        return "{}:{}:{}:{}".format(self.source, self.target, self.demand, self.cost_multiplier)

    def is_empty(self):
        """Checks whether source or target nodes are empty"""
        return self.source == "" or self.target == ""

    def target_as_fe(self):
        """Returns the target (sink) of the commodity as a FlowEndpoint"""
        return FlowEndpoint.fromString(self.target)

    def source_as_fe(self):
        """Returns the source of the commodity as a FlowEndpoint"""
        return FlowEndpoint.fromString(self.source)

    def __hash__(self):
        return hash(str(self))
