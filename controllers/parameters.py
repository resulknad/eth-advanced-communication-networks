from dataclasses import dataclass

from typing import List


@dataclass
class Parameter:
    TOTAL_TIME: float
    """Number of seconds the simulation runs for (without warmup)"""
    MCF_INTERVAL_SIZE: float  # seconds
    """The total time is divided into intervals of this size for each of which paths are calculated."""
    NORMALIZE_BW_ACROSS_TIME: bool
    TCP_DEFAULT_BW: float
    """Bandwidth assigned to TCP base traffic in Mbps"""
    UDP_COST_MULTIPLIER: float
    """Cost multiplier for UDP base traffic. Traffic with higher cost multipliers will prefer shorter routes"""
    TCP_COST_MULTIPLIER: float
    """Cost multiplier for TCP base traffic. Traffic with higher cost multipliers will prefer shorter routes"""
    UDP_BW_MULTIPLIER: float
    """Multiplier for the bandwidth demand of UDP base traffic"""
    TCP_BW_MULTIPLIER: float
    """Multiplier for the bandwidth demand of TCP base traffic"""
    TCP_ACK_BW_MULTIPLIER: float
    """For TCP flows, the bandwidth demand is multiplied by this and a demand in the other direction for ACKs is made"""
    HEARTBEAT_FREQUENCY: float
    """Seconds between heartbeat messages"""
    TCP_DURATION_MULTIPLIER: float
    """Multiplier for the estimated duration of TCP base traffic"""
    ADDITIONAL_BW: float
    """Bandwidth demand for additional traffic in Mbps"""
    CONTROLLER_FORWARD_MPLS: bool
    """Whether controller should manually create MPLS packets for additional traffic sent to it (because the switch already dropped it)"""
    ADDITIONAL_TRAFFIC_PURGE_INTERVAL: float
    """Interval in seconds between purges of additional traffic routes."""
    ADDITIONAL_TRAFFIC_PURGE: bool
    """Whether additional routes should be purged periodically"""
    SLAS: List[str]
    """Names of SLAs the controller should try to install routes for"""
