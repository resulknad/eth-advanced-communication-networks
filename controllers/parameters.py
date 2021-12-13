from dataclasses import dataclass

from typing import List

@dataclass
class Parameter:
    TOTAL_TIME: float # seconds
    MCF_INTERVAL_SIZE: float # seconds
    NORMALIZE_BW_ACROSS_TIME: bool
    TCP_DEFAULT_BW: float # Mbps
    UDP_COST_MULTIPLIER: float
    TCP_COST_MULTIPLIER: float
    UDP_BW_MULTIPLIER: float
    TCP_BW_MULTIPLIER: float
    TCP_ACK_BW_MULTIPLIER: float
    HEARTBEAT_FREQUENCY: float # seconds
    TCP_DURATION_MULTIPLIER: float
    ADDITIONAL_BW: float # Mbps
    CONTROLLER_FORWARD_MPLS: bool
    SLAS: List[str]
