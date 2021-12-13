from collections import defaultdict
from copy import deepcopy
import math
from typing import List, Dict, Tuple
import time

from graph import Graph
from parameters import Parameter
from mcf import MCF
from flow import Flow
from table_manager import Paths


class FlowManager:
    """Calculates per-interval paths for a given list of traffic and SLAs
    The simulation time is divided into discrete intervals. For each interval,
    paths for traffic within that interval are searched using a
    multi-commodity-flow problem."""
    def __init__(self, graph: Graph, params: Parameter, base_traffic: List[Flow], filtered_slas):
        self.g = deepcopy(graph)
        self.params = params
        self.filtered_slas = filtered_slas
        self._paths = {}
        self._path_weights = {}

        # Caches computed paths and path weights for each set of link failures
        self.failure_paths: Dict[frozenset, Paths] = {}
        self.failure_weights: Dict[frozenset, Dict] = {}

        # Flows from base_traffic that are accepted/rejected based on SLAs
        self.accepted_flows: List[Flow] = []
        self.rejected_flows: List[Flow] = []

        f: Flow
        for f in base_traffic:
            if (self._slas_for_flow(f)):
                self.accepted_flows.append(f)
            else:
                self.rejected_flows.append(f)

        # compute the time intervals for the MCF problems
        num_intervals = math.ceil(params.total_time / params.mcf_interval_size)
        # Stores the end-time of each interval
        self.intervals = [params.mcf_interval_size * i for i in range(1, num_intervals + 1)]

        # compute and store flows for each interval
        self.flows_for_interval: Dict[int, List[Flow]] = {}
        start_time = 0
        for end_time in self.intervals:
            flows = [f for f in self.accepted_flows if (f.start_time < end_time) and (f.end_time >= start_time)]

            self.flows_for_interval[end_time] = flows

            print("[{}, {}] {} flows".format(start_time, end_time, len(flows)))

            start_time = end_time

    @property
    def paths(self):
        return self._paths

    @property
    def path_weights(self):
        return self._path_weights

    def compute_paths_mcf(self, failures=None):
        """Computes paths by solving a multi-commodity flow problem for each time interval, taking into account a list of failed links.
        The paths are stored as an attribute.

        Args:
            failures (list(tuple(str, str)), optional): List of failed links, given as pairs of switch names.
        """
        st = time.time()

        if failures is None:
            failures = []

        failure_set = frozenset(failures)

        if failure_set in self.failure_paths:
            print("Was able to reuse cached paths")
            self._paths = self.failure_paths[failure_set]
            self._path_weights = self.failure_weights[failure_set]
            return

        flows_to_path = defaultdict(list)
        flows_to_path_weights = defaultdict(list)

        start_time = 0
        for end_time in self.intervals:
            print(f"Solving for interval [{start_time}, {end_time})")
            flows = self.flows_for_interval[end_time]
            m = MCF(self.g)

            # remove failed links
            for n1, n2 in failures:
                m.remove_failed_link(n1, n2)

            interval_length = end_time - start_time

            f: Flow
            for f in flows:
                src_fe = f.to_source_endpoint()
                dst_fe = f.to_dest_endpoint()

                if (src_fe, dst_fe) in flows_to_path:
                    # flow was already considered in previous timestep
                    # and we already have a path for it
                    m.subtract_paths(
                        flows_to_path[(src_fe, dst_fe)],
                        flows_to_path_weights[(src_fe, dst_fe)],
                    )

                    # for TCP flows, we also keep the reverse path for the ACKs
                    if f.is_tcp():
                        m.subtract_paths(
                            flows_to_path[(dst_fe, src_fe)],
                            flows_to_path_weights[(dst_fe, src_fe)],
                        )
                else:
                    # find path for that new flow
                    FlowManager.add_flow_to_mcf(m, f, interval_length, self.params)

            # add waypoints
            FlowManager.add_waypoints_to_mcf(m, self._get_waypoints())

            # solve the LP
            lp_st = time.time()
            excess = m.make_and_solve_lp()
            lp_et = time.time()
            print(f"Solving LP took {lp_et - lp_st}", flush=True)

            if excess > 0:
                print("WARNING: could not satisfy all of the LP constraints! (excess: {})".format(excess))
            m.print_paths_summary()

            paths, weights = m.get_paths_and_weights()
            for (src, dst) in paths:
                if src is None:
                    continue
                if (src, dst) in flows_to_path:
                    print(
                        "WARNING: got a duplicate flow pair when setting up MCF",
                        (src, dst),
                        start_time,
                        end_time,
                    )
                flows_to_path[(src, dst)].extend(paths[(src, dst)])
                flows_to_path_weights[(src, dst)].extend(weights[(src, dst)])
            print("[{}, {}] {} flows ({} new paths, {} saved)".format(start_time, end_time, len(flows), len(paths),
                                                                      len(flows_to_path)))
            start_time = end_time

        # For all SLA-rejected flows, add an empty path list
        for f in self.rejected_flows:
            src = f.to_source_endpoint()
            dst = f.to_dest_endpoint()
            flows_to_path[(src, dst)] = []
            flows_to_path_weights[(src, dst)] = []

        self._paths = flows_to_path
        self._path_weights = flows_to_path_weights

        self.failure_paths[failure_set] = self._paths
        self.failure_weights[failure_set] = self._path_weights

        et = time.time()
        print(f"Computing new paths took {et - st}", flush=True)

    @staticmethod
    def add_waypoints_to_mcf(mcf: MCF, wps: List[Tuple[str, str, str, str]]):
        """Enforce the given waypoints in the MCF.

        Args:
            mcf (MCF): The MCF problem instance
            wps (list(tuple(str, str, str, str))): The waypoint SLAs as a list of (src, target, wp, protocol) tuples
        """
        for (src, target, wp, protocol) in wps:
            mcf.add_waypoint_to_all(src, target, wp, protocol)

    @staticmethod
    def add_flow_to_mcf(mcf, flow, interval_length, params: Parameter):
        """Adds a flow to the given MCF problem. Cost and bandwidth are adjusted depending on tunable parameters.
        For TCP flows, an additional reverse flow is added to allow ACKs to be delivered.

        Args:
            mcf (MCF): The MCF problem instance
            flow (Flow)
            interval_length (float): The size of the current interval (where the flow should be added), in seconds
        """

        cost_multiplier = (params.udp_cost_multiplier if flow.is_udp() else params.tcp_cost_multiplier)
        bw_multiplier = (params.udp_bw_multiplier if flow.is_udp() else params.tcp_bw_multiplier)

        bw = flow.rate * bw_multiplier
        if params.normalize_bw_across_time:
            bw *= flow.duration() / interval_length

        src_fe = flow.to_source_endpoint()
        dst_fe = flow.to_dest_endpoint()

        mcf.add_flow(
            src_fe,
            dst_fe,
            bw,
            cost_multiplier=cost_multiplier,
            add_on_conflict=params.normalize_bw_across_time,
        )

        # for TCP flows, we also need a path from dst to src for the acks (with lower bw)
        if flow.is_tcp():
            mcf.add_flow(
                dst_fe,
                src_fe,
                bw * params.tcp_ack_bw_multiplier,
                add_on_conflict=params.normalize_bw_across_time,
            )

    def _slas_for_flow(self, flow):
        """Returns all SLAs that apply to a given flow.

        This does not include the waypoint SLAs.

        Args:
            flow (Flow)

        Returns:
            list(pandas.Series): The SLAs that apply to the given flow
        """

        from_host = flow.src
        from_port = flow.sport
        to_host = flow.dst
        to_port = flow.dport
        protocol = flow.protocol

        relevant_slas = []
        for (_, sla) in self.filtered_slas.iterrows():
            src_match = sla.src == "*" or sla.src == from_host
            src_port_match = sla.sport_start <= from_port <= sla.sport_end
            dst_match = sla.dst == "*" or sla.dst == to_host
            dst_port_match = sla.dport_start <= to_port <= sla.dport_end

            if (sla.type != "wp" and src_match and src_port_match and dst_match and dst_port_match
                    and sla.protocol == protocol):
                relevant_slas.append(sla)
        return relevant_slas

    def _get_waypoints(self) -> List[Tuple[str, str, str, str]]:
        """Returns the waypoint SLAs from the filtered SLAs

        Returns:
            list(tuple(str, str, str, str)): The waypoint SLAs as a list of (src, target, wp, protocol) tuples
        """
        df = self.filtered_slas

        wps = df[df["type"] == "wp"]
        return wps[["src", "dst", "target", "protocol"]].values.tolist()
