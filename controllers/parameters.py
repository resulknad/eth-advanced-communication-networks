from dataclasses import dataclass

from typing import List


@dataclass(frozen=True)
class Parameter:
    total_time: float
    """Number of seconds the simulation runs for (without warmup and closing time at the end)."""
    mcf_interval_size: float
    """The total time is divided into intervals of this size in seconds for each of which paths are calculated."""
    normalize_bw_across_time: bool
    """When enabled, the bandwidth of flows that do not span the entire interval is normalized as if they did
    (i.e., the bandwidth is reduced such that the size of the flow would remain unchanged if it spanned the entire interval)."""
    tcp_default_bw: float
    """Bandwidth assigned to TCP base traffic in Mbps."""
    udp_cost_multiplier: float
    """Cost multiplier for UDP base traffic. Traffic with higher cost multipliers will prefer shorter paths."""
    tcp_cost_multiplier: float
    """Cost multiplier for TCP base traffic. Traffic with higher cost multipliers will prefer shorter paths."""
    udp_bw_multiplier: float
    """Multiplier for the bandwidth demand of UDP base traffic."""
    tcp_bw_multiplier: float
    """Multiplier for the bandwidth demand of TCP base traffic."""
    tcp_ack_bw_multiplier: float
    """For TCP flows, a reverse flow is added for the ACKs.
    This reverse flow has bandwidth of the original flow multiplied by this parameter."""
    use_num_hops_cost: bool
    """Use number of hops instead of delay as the cost measure for the LP."""
    heartbeat_frequency: float
    """Seconds between heartbeat messages."""
    tcp_duration_multiplier: float
    """Multiplier for the estimated duration of TCP base traffic."""
    additional_traffic_bw: float
    """Bandwidth demand for additional traffic in Mbps."""
    controller_forward_mpls: bool
    """If enabled, the controller creates MPLS packets in the control plane for unknown additional traffic reported by the switch.
    The controller then sends the packet back to the switch (with MPLS headers added), to be forwarded to the next hop.
    If disabled, these packets will simply be dropped until the controller has installed appropriate paths on the switch."""
    additional_traffic_purge_interval: float
    """Interval in seconds between purges of additional traffic paths."""
    additional_traffic_purge: bool
    """Whether additional paths should be purged periodically."""
    slas: List[str]
    """Names of SLAs the controller should consider when computing paths."""
