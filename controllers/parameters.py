from dataclasses import dataclass

from typing import List


@dataclass(frozen=True)
class Parameter:
    total_time: float
    """Number of seconds the simulation runs for (without warmup)"""
    mcf_interval_size: float
    """The total time is divided into intervals of this size in seconds for each of which paths are calculated."""
    normalize_bw_across_time: bool
    tcp_default_bw: float
    """Bandwidth assigned to TCP base traffic in Mbps"""
    udp_cost_multiplier: float
    """Cost multiplier for UDP base traffic. Traffic with higher cost multipliers will prefer shorter routes"""
    tcp_cost_multiplier: float
    """Cost multiplier for TCP base traffic. Traffic with higher cost multipliers will prefer shorter routes"""
    udp_bw_multiplier: float
    """Multiplier for the bandwidth demand of UDP base traffic"""
    tcp_bw_multiplier: float
    """Multiplier for the bandwidth demand of TCP base traffic"""
    tcp_ack_bw_multiplier: float
    """For TCP flows, the bandwidth demand is multiplied by this and a demand in the other direction for ACKs is made"""
    heartbeat_frequency: float
    """Seconds between heartbeat messages"""
    tcp_duration_multiplier: float
    """Multiplier for the estimated duration of TCP base traffic"""
    additional_traffic_bw: float
    """Bandwidth demand for additional traffic in Mbps"""
    controller_forward_mpls: bool
    """Whether controller should manually create MPLS packets for additional traffic sent to it (because the switch already dropped it)"""
    additional_traffic_purge_interval: float
    """Interval in seconds between purges of additional traffic routes."""
    additional_traffic_purge: bool
    """Whether additional routes should be purged periodically"""
    slas: List[str]
    """Names of SLAs the controller should try to install routes for"""
