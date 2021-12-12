import argparse
from collections import defaultdict
import threading
import math
import time
from scapy.all import sniff, Ether, raw, UDP, IP
from scapy.contrib.mpls import MPLS
import pandas as pd
import struct
from dataclasses import dataclass
import random

import socket

from copy import deepcopy

from typing import Dict, List, Tuple

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.topology import NetworkGraph

from graph import Graph
from mcf import MCF
from flow_endpoint import FlowEndpoint
from heartbeat_generator import HeartBeatGenerator, TYPE_HEARTBEAT
from parameters import Parameter

TYPE_TCP = 0x6
TYPE_UDP = 0x11
TYPE_IPV4 = 0x800
TYPE_MPLS = 0x8847

# ============================== TUNABLE PARAMETERS ==============================
# These parameters allow to fine-tune our solution, obtaining different tradeoffs.
# The parameters are described in detail in the README.

params = Parameter(
    TOTAL_TIME=60,
    MCF_INTERVAL_SIZE=5,
    NORMALIZE_BW_ACROSS_TIME=False,
    TCP_DEFAULT_BW=10,
    UDP_COST_MULTIPLIER=1,
    TCP_COST_MULTIPLIER=1,
    UDP_BW_MULTIPLIER=1,
    TCP_BW_MULTIPLIER=1,
    TCP_ACK_BW_MULTIPLIER=0.5,
    HEARTBEAT_FREQUENCY=0.1,
    TCP_DURATION_MULTIPLIER=1.5,
    ADDITIONAL_BW=10,
    SLAS=[
        "fcr_1", # 1--100 TCP 1
        "prr_2", # 1--100 UDP 0.99
        "fct_3", # 1--100 TCP 20
        "fct_4", # 1--100 TCP 15
        "fct_5", # 1--100 TCP 10
        "delay_6", # 1--100 UDP 0.017
        "delay_7", # 1--100 UDP 0.015
        "delay_8", # 1--100 UDP 0.012
        "fcr_9", # 101--200 TCP 1
        "prr_10", # 101--200 UDP 0.99
        "fct_11", # 101--200 TCP 20
        "fct_12", # 101--200 TCP 15
        "fct_13", # 101--200 TCP 10
        "delay_14", # 101--200 UDP 0.03
        "delay_15", # 101--200 UDP 0.025
        "delay_16", # 101--200 UDP 0.02
        # "fcr_17", # 201--300 TCP 1
        # "prr_18", # 201--300 UDP 0.75
        # "prr_19", # 201--300 UDP 0.95
        # "prr_20", # 201--300 UDP 0.99
        # "fct_21", # 201--300 TCP 15
        # "fct_22", # 201--300 TCP 10
        # "delay_23", # 201--300 UDP 0.02
        # "delay_24", # 201--300 UDP 0.012
        # "fcr_25", # 301--400 TCP 1
        # "prr_26", # 301--400 UDP 0.75
        # "prr_27", # 301--400 UDP 0.95
        "prr_28", # 301--400 UDP 0.99
        # "delay_29", # 301--400 UDP 0.06
        # "delay_30", # 301--400 UDP 0.04
        "prr_31", # 60001--* UDP 0.75
        "prr_32", # 60001--* UDP 0.95
        "prr_33", # 60001--* UDP 0.99
        "wp_34", # LON_h0 -> BAR_h0 udp PAR
        "wp_35", # POR_h0 -> GLO_h0 udp PAR
        "wp_36", # BRI_h0 -> BAR_h0 udp PAR
        "wp_37", # BER_h0 -> LIS_h0 udp MAD
        "wp_38", # LIS_h0 -> BER_h0 udp MAD
    ])


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


def preprocess_slas(slas_file):
    """Reads the SLA file, makes some transformations (dealing with ranges and wildcards), and then filters
    out the SLAs that should not be considered. The remaining SLAs (to be considered) are stored as a DataFrame attribute.

    Args:
        slas_file (str): Path to the SLA csv file

    Returns:
        list(pandas.Series): The processed and filtered SLAs

    """
    # read SLAs
    df = pd.read_csv(slas_file)
    df = df.rename(columns=lambda x: x.strip())

    sport = df["sport"].str.split("--", n=1, expand=True)
    df["sport_start"] = sport[0].replace('*', '0').astype("int32")
    df["sport_end"] = sport[1].replace('*', '65535').astype("int32")

    dport = df["dport"].str.split("--", n=1, expand=True)
    df["dport_start"] = dport[0].replace('*', '0').astype("int32")
    df["dport_end"] = dport[1].replace('*', '65535').astype("int32")

    # select SLAs that should be considered
    df = df[df["id"].isin(params.SLAS)]

    return df


def preprocess_base_traffic(base_traffic_file):
    """Reads the base traffic file and transforms size-based (TCP) flows to bandwidth/duration-based flows.

    Args:
        slas_file (str): Path to the base traffic csv file

    Returns:
        List[Flow]: List of flows representing the base traffic
    """
    # read base traffic
    df = pd.read_csv(base_traffic_file)
    df = df.rename(columns=lambda x: x.strip())

    # map flows defined in terms of size to (bandwidth, duration) pairs
    rows = df[pd.isna(df["rate"])]
    for i, r in rows.iterrows():
        size = int(r["size"][:-2])
        df.loc[i, "rate"] = str(params.TCP_DEFAULT_BW) + "Mbps"
        df.loc[i, "duration"] = (size / params.TCP_DEFAULT_BW) * params.TCP_DURATION_MULTIPLIER

    # add end_time everywhere
    df["end_time"] = df["start_time"] + df["duration"]
    return Flow.from_df(df)


class FlowManager:
    def __init__(self, graph: Graph, params: Parameter, base_traffic: List[Flow], filtered_slas):
        # read topology
        self.g = deepcopy(graph)
        self.params = params
        self.filtered_slas = filtered_slas
        self._paths = {}
        self._path_weights = {}

        # compute the time intervals for the MCF problems
        num_intervals = math.ceil(params.TOTAL_TIME / params.MCF_INTERVAL_SIZE)
        # Stores the end-time of each interval
        self.intervals = [params.MCF_INTERVAL_SIZE * i for i in range(1, num_intervals + 1)]

        # compute and store flows for each interval
        self.flows_for_interval: Dict[int, List[Flow]] = {}
        start_time = 0
        for end_time in self.intervals:
            flows = [f for f in base_traffic if (f.start_time < end_time) and (f.end_time >= start_time)]

            self.flows_for_interval[end_time] = flows

            print("[{}, {}] {} flows".format(start_time, end_time, len(flows)))

            start_time = end_time

        # Calculate base paths using base traffic and without failures
        self.compute_paths_mcf()

    @property
    def paths(self):
        return self._paths

    @property
    def path_weights(self):
        return self._path_weights

    def compute_paths_mcf(self, failures=None):
        """Computes paths by solving a multi-commodity flow problem for each time interval, taking into account a list of failed links.
        The paths are stored as an attribute.
        Note: self.init_mcf() should have been called once beforehand.

        Args:
            failures (list(tuple(str, str)), optional): List of failed links, given as pairs of switch names.
        """
        st = time.time()

        if failures is None:
            failures = []

        flows_to_path = defaultdict(list)
        flows_to_path_weights = defaultdict(list)

        start_time = 0
        for end_time in self.intervals:
            flows = self.flows_for_interval[end_time]
            m = MCF(self.g)

            # remove failed links
            for n1, n2 in failures:
                m.remove_failed_link(n1, n2)

            interval_length = end_time - start_time

            f: Flow
            for f in flows:
                if self._slas_for_flow(f):
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
                        FlowManager.add_flow_to_mcf(m, f, interval_length)

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

        self._paths = flows_to_path
        self._path_weights = flows_to_path_weights

        et = time.time()
        print(f"Computing new paths took {et - st}", flush=True)

    @staticmethod
    def add_waypoints_to_mcf(mcf, wps):
        for (src, target, wp, protocol) in wps:
            mcf.add_waypoint_to_all(src, target, wp, protocol)

    @staticmethod
    def add_flow_to_mcf(mcf, flow, interval_length):
        """Adds a flow to the given MCF problem. Cost and bandwidth are adjusted depending on tunable parameters.
        For TCP flows, an additional reverse flow is added to allow ACKs to be delivered.

        Args:
            mcf (MCF): The MCF problem instance
            flow (Flow)
            interval_length (float): The size of the current interval (where the flow should be added), in seconds
        """

        cost_multiplier = (params.UDP_COST_MULTIPLIER if flow.is_udp() else params.TCP_COST_MULTIPLIER)
        bw_multiplier = (params.UDP_BW_MULTIPLIER if flow.is_udp() else params.TCP_BW_MULTIPLIER)

        bw = flow.rate * bw_multiplier
        if params.NORMALIZE_BW_ACROSS_TIME:
            bw *= flow.duration() / interval_length

        src_fe = flow.to_source_endpoint()
        dst_fe = flow.to_dest_endpoint()

        mcf.add_flow(
            src_fe,
            dst_fe,
            bw,
            cost_multiplier=cost_multiplier,
            add_on_conflict=params.NORMALIZE_BW_ACROSS_TIME,
        )

        # for TCP flows, we also need a path from dst to src for the acks (with lower bw)
        if flow.is_tcp():
            mcf.add_flow(
                dst_fe,
                src_fe,
                bw * params.TCP_ACK_BW_MULTIPLIER,
                add_on_conflict=params.NORMALIZE_BW_ACROSS_TIME,
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

    def _get_waypoints(self):
        """Returns the waypoint SLAs from the filtered SLAs

        Returns:
            list(tuple(str, str, str, str)): The waypoint SLAs as a list of (src, target, wp, protocol) tuples
        """
        df = self.filtered_slas

        wps = df[df["type"] == "wp"]
        return wps[["src", "dst", "target", "protocol"]].values.tolist()


# A collection of paths is a mapping from the two endpoints to all paths from
# the first to the second. The paths per endpoint-tuple are a list of lists,
# the inner lists contain the name of the switches on the path in order.
Paths = Dict[Tuple[FlowEndpoint, FlowEndpoint], List[List[str]]]


class PathManager:
    """Maintains virtual circuits on the switches."""
    def __init__(self, topo: NetworkGraph, controllers: Dict[str, SimpleSwitchThriftAPI]):
        self.topo = topo
        self.controllers = controllers

        # Monotonically incrementing counter for ECMP group IDs per switch
        self.ecmp_group_counters = defaultdict(int)

        # Currently installed paths
        self.current_paths: Paths = {}

        # Store different categories of paths. All paths in this dictionary
        # will be pushed onto the switch on a triggered update.
        # If the list of paths for an endpoint pair is empty, an explicit drop
        # action will be installed for those flows.
        self.paths: Dict[str, Paths] = defaultdict(lambda: defaultdict(list))

    def replace_base_paths(self, paths: Paths):
        self.paths["base"] = paths

    def replace_additional_traffic(self, paths: Paths):
        self.paths["additional"] = paths

    def get_additional_traffic(self) -> Paths:
        return self.paths["additional"]

    def trigger_update(self):
        """Updates all paths installed on the ingress switches to contain all registered ones.
        Each path is defined on the ingress switch as a stack of MPLS headers that determine the hops.

        Takes into account the previous paths (which are already installed on the switches) to minimize the number of table operations.
        """
        st = time.time()

        all_paths = {k: v for p in self.paths.values() for (k, v) in p.items()}
        previous_paths = self.current_paths

        to_set = lambda ps: set(map(lambda x: (x[0], str(x[1])), ps.items()))
        set_all_paths = to_set(all_paths)
        set_previous_paths = to_set(previous_paths)

        same = set_all_paths & set_previous_paths
        added = set_all_paths - set_previous_paths
        removed = set_previous_paths - set_all_paths

        # remove paths
        for key, _ in removed:
            paths = previous_paths[key]
            (src_fe, dst_fe) = key

            sw_name = src_fe.get_switch()

            src_ip = self.topo.get_host_ip(src_fe.host)
            dst_ip = self.topo.get_host_ip(dst_fe.host)

            # TODO: We do not remove the paths from table virtual_circuit_paths.
            # This may not be a big problem, but the tables do grow in size (and might overflow if there are many failures).

            # delete entry from virtual_circuit table
            print(f"table_delete at {sw_name}")
            self.controllers[sw_name].table_delete_match(
                "virtual_circuit",
                [
                    str(src_ip),
                    str(dst_ip),
                    str(src_fe.port),
                    str(dst_fe.port),
                    str(TYPE_TCP if src_fe.protocol == "tcp" else TYPE_UDP),
                ],
            )

        print("done removing circuits")

        # add paths
        for key, _ in added:
            paths = all_paths[key]
            (src_fe, dst_fe) = key

            sw_name = src_fe.get_switch()
            src_ip = self.topo.get_host_ip(src_fe.host)
            dst_ip = self.topo.get_host_ip(dst_fe.host)

            if paths:
                ecmp_group = self.ecmp_group_counters[sw_name]
                self.ecmp_group_counters[sw_name] += 1

                # install entry in virtual_circuit_path table
                for idx, path in enumerate(paths):
                    path_wo_hosts = path[1:-1]
                    print(path, path_wo_hosts)
                    labels = self._get_mpls_stack(path_wo_hosts)
                    print(labels)
                    num_hops = len(labels)
                    action_name = f"mpls_ingress_{num_hops}_hop"
                    action_args = list(map(str, labels[::-1]))

                    # add rule
                    print(f"table_add at {sw_name}")
                    self.controllers[sw_name].table_add(
                        "virtual_circuit_path",
                        action_name,
                        [str(ecmp_group), str(idx)],
                        action_args,
                    )

                # install entry in virtual_circuit table
                self.controllers[sw_name].table_add(
                    "virtual_circuit",
                    "ecmp_group",
                    [
                        str(src_ip),
                        str(dst_ip),
                        str(src_fe.port),
                        str(dst_fe.port),
                        str(TYPE_TCP if src_fe.protocol == "tcp" else TYPE_UDP),
                    ],
                    [str(ecmp_group), str(len(paths))],
                )
            else:
                # For empty paths, install a drop action
                self.controllers[sw_name].table_add("virtual_circuit", "drop", [
                    str(src_ip),
                    str(dst_ip),
                    str(src_fe.port),
                    str(dst_fe.port),
                    str(TYPE_TCP if src_fe.protocol == "tcp" else TYPE_UDP),
                ])

        print("done adding circuits")

        self.current_paths = all_paths

        et = time.time()
        print(f"same: {len(same)}, removed: {len(removed)}, added: {len(added)}")
        print(f"Installing paths took {et - st}", flush=True)

    def _get_mpls_stack(self, path):
        """
        Converts the given path into a list of MPLS labels

        Args:
            path (list(str)): The path as a list of node names

        Returns:
            list(int): MPLS labels, the first element is the top of the stack
        """
        stack = []
        prev = path[0]
        for node in path[1:]:
            port_num = self.topo.node_to_node_port_num(prev, node)
            stack.append(port_num)
            prev = node

        return stack


class Controller(object):
    def __init__(self, base_traffic_file, slas_file):
        """Initializes a new controller instance and performs some setup tasks.

        Args:
            base_traffic_file (str): path to the base traffic file
            slas_file (str): path to the SLA file
        """
        topo_file = "topology.json"
        # read topology
        self.topo = load_topo(topo_file)
        self.g = Graph(topo_file)
        self.controllers: Dict[str, SimpleSwitchThriftAPI] = {}

        self.additional_udp: List[Flow] = []

        self.filtered_slas = preprocess_slas(slas_file)
        self.base_traffic = preprocess_base_traffic(base_traffic_file)
        self.flow_manager = FlowManager(self.g, params, self.base_traffic, self.filtered_slas)
        self.paths_manager = PathManager(self.topo, self.controllers)

        self._prepare_additional_traffic()
        self.init_controllers()
        self.init_heartbeats()

    def _prepare_additional_traffic(self):
        self.additional_traffic_params = deepcopy(params)
        self.additional_traffic_params.NORMALIZE_BW_ACROSS_TIME = True
        additional_manager = FlowManager(self.g, self.additional_traffic_params, self.base_traffic, self.filtered_slas)
        additional_manager.compute_paths_mcf()
        # For the flow computations for the additional traffic, we don't want to normalize and we only want a single interval
        self.additional_traffic_params.NORMALIZE_BW_ACROSS_TIME = False
        self.additional_traffic_params.MCF_INTERVAL_SIZE = self.additional_traffic_params.TOTAL_TIME

        # Residual graph after removing all the traffic allocated to the base traffic (normalized over the entire time range)
        self.additional_traffic_graph = deepcopy(self.g)

        for path, weight in zip(*additional_manager.paths.values(), *additional_manager.path_weights.values()):
            self.additional_traffic_graph.subtract_path(path, weight)

    def init_controllers(self):
        """Basic initialization. Connects to switches and resets state."""
        self._connect_to_switches()
        [controller.reset_state() for controller in self.controllers.values()]

    def _connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def init_heartbeats(self):
        """Initiates the heartbeat messages and starts listening for failure/recovery notifications (both in a new thread).
        Note: Must be called AFTER self.init_controllers().
        """
        self.failed_links = set()

        # configure mirroring session to cpu port for failure notifications
        self._set_mirroring_sessions()

        # initiate the heartbeat messages
        self._heartbeat(params.HEARTBEAT_FREQUENCY)
        print("started sending heartbeats")

        # Sniff the traffic coming from switches
        t = threading.Thread(target=self._sniff_cpu_ports)
        t.start()
        print("started listening for link state notifications")

    def _set_mirroring_sessions(self):
        """Sets up mirroring sessions for communication with switches."""
        for p4switch in self.topo.get_p4switches():
            cpu_port = self.topo.get_cpu_port_index(p4switch)
            self.controllers[p4switch].mirroring_add(100, cpu_port)

    def _heartbeat(self, frequency):
        """Runs heartbeat threads"""
        heartbeat = HeartBeatGenerator(frequency)
        heartbeat.run()

    def _sniff_cpu_ports(self):
        """Sniffs traffic coming from switches"""
        cpu_interfaces = [
            str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers
        ]
        sniff(iface=cpu_interfaces, prn=self._process_packet)

    def _process_packet(self, pkt):
        """Parses packets sent by the switches to detect failure and recovery notifications.

        Args:
            pkt (scapy packet): The packet to process
        """

        interface = pkt.sniffed_on
        switch_name = interface.split("-")[0]
        packet = Ether(raw(pkt))

        # check if it is a heartbeat packet
        if packet.type == TYPE_HEARTBEAT:
            # parse the heartbeat header
            payload = struct.unpack("!H", packet.payload.load)[0]
            from_switch_to_cpu_flag = (payload & 0x0020) >> 5

            # only if it is a packet sent from switch to cpu
            if from_switch_to_cpu_flag == 1:

                # get link status flag
                link_status_flag = (payload & 0x0010) >> 4

                # get port
                port = (payload & 0xFF80) >> 7
                # get other side of the link using port
                neighbor = self.topo.port_to_node(switch_name, port)
                # detect the affected link
                affected_link = tuple(sorted([switch_name, neighbor]))

                if link_status_flag == 1:
                    # link is down

                    # ignore duplicated notifications (both switches will notify the controller)
                    if affected_link not in self.failed_links:
                        print(f"Link failure detected: {affected_link}", flush=True)
                        self.failed_links.add(affected_link)
                        self.link_state_changed(list(self.failed_links))

                else:
                    # link is up

                    # ignore duplicated notifications (both switches will notify the controller)
                    if affected_link in self.failed_links:
                        print(f"Link recovery detected: {affected_link}", flush=True)
                        self.failed_links.remove(affected_link)
                        self.link_state_changed(list(self.failed_links))
        elif UDP in packet and packet[UDP].sport >= 60000:
            ip = packet[IP]
            udp = packet[UDP]

            src = self.topo.get_host_name(str(ip.src))
            sport = udp.sport
            dst = self.topo.get_host_name(str(ip.dst))
            dport = udp.dport

            # TODO use actual time values (also add option to set default length of additional traffic)
            flow = Flow(src, sport, dst, dport, "udp", params.ADDITIONAL_BW, 0, 1)

            # TODO properly handle empty paths for a flow (install drop action)
            # this is needed because if an additional flow is rejected, we don't want to constantly get packets sent to the controller.

            src_fe = flow.to_source_endpoint()
            dst_fe = flow.to_dest_endpoint()

            paths = self.paths_manager.get_additional_traffic()[(src_fe, dst_fe)]
            num_paths = len(paths)

            # Manually create the correct MPLS stack and forward the packet
            if num_paths > 0:
                chosen = paths[random.randrange(num_paths)]
                labels = self.paths_manager._get_mpls_stack(chosen)

                next_hop = labels[0]
                labels = labels[1:]

                out = packet.copy()
                for (i, label) in enumerate(labels):
                    s = 0 if i < len(labels) - 1 else 1

                    out /= MPLS(label=label, s=s, ttl=ip.ttl - 1)

                out /= ip
                out /= udp

                out[Ether].type = TYPE_MPLS if labels else TYPE_IPV4

                out[Ether].src = self.topo.node_to_node_mac(switch_name,
                                                            self.topo.port_to_node(switch_name, next_hop + 1))
                out[Ether].dst = self.topo.node_to_node_mac(self.topo.port_to_node(switch_name, next_hop + 1),
                                                            switch_name)

                out_bytes = raw(out)

                send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                send_socket.bind((self.topo.get_interfaces(switch_name)[next_hop], 0))
                send_socket.send(out_bytes)

            if flow in self.additional_udp:
                return

            print(f"Detected additional traffic from {src}:{sport} to {dst}:{dport}")

            self.additional_udp.append(flow)

            manager = FlowManager(self.g, self.additional_traffic_params, self.additional_udp, self.filtered_slas)
            manager.compute_paths_mcf()

            self.paths_manager.replace_additional_traffic(manager.paths)
            self.paths_manager.trigger_update()

            # TODO install paths
            # TODO install drop actions for rejected flows

            # TODO handle packet indicating an additional flow
            # Create initial MCF with base traffic averaged over entire runtime
            # Create new MCF from residual graph with only additional traffic as commodities
            # Solve MCF and install new paths as usual (don't delete base traffic paths)
            # We need to somehow be able to tell if an additional path is actually new or just belongs to a flow that the MCF decided to drop
            # Every X seconds, purge all additional traffic paths (next packet will force controller to compute again)
            # Re-emit this packet to switch so that it doesn't get lost
            pass

    def link_state_changed(self, failures):
        """Callback function that is invoked whenever a link failure or recovery is detected.
        Recomputes the MCF solutions (taking into account the link failures) and installs the new paths.

        Args:
            failures (list(tuple(str, str)), optional): List of failed links, given as pairs of switch names.
        """

        print(f"Got a link state change notification! Failures: {failures}", flush=True)

        print("Recomputing MCF solution")
        self.flow_manager.compute_paths_mcf(failures)

        print("Installing new paths")
        self.paths_manager.replace_base_paths(self.flow_manager.paths)
        self.paths_manager.trigger_update()

    def run(self):
        """Run function"""
        self.install_base_table_entries()
        self.paths_manager.replace_base_paths(self.flow_manager.paths)
        self.paths_manager.trigger_update()

    def install_base_table_entries(self):
        """Installs the table entries for basic forwarding operations, namely for forwarding to directly connected hosts
        and for MPLS forwarding.
        """
        for sw_name in self.topo.get_p4switches():

            # install table entry for the directly connected hosts
            # (there should only be one host, but let's keep it generic)
            for host in self.topo.get_hosts_connected_to(sw_name):
                port_num = self.topo.node_to_node_port_num(sw_name, host)
                host_ip = self.topo.get_host_ip(host) + "/32"
                host_mac = self.topo.get_host_mac(host)

                # add rule
                print(f"table_add at {sw_name}")
                self.controllers[sw_name].table_add(
                    "ipv4_lpm",
                    "set_nhop",
                    [str(host_ip)],
                    [str(host_mac), str(port_num)],
                )

            # install table entries for MPLS forwarding
            for neighbor in self.topo.get_switches_connected_to(sw_name):
                port_num = self.topo.node_to_node_port_num(sw_name, neighbor)
                neighbor_mac = self.topo.node_to_node_mac(neighbor, sw_name)

                print(f"iface for {sw_name}: port_num: {port_num}, neighbor: {neighbor}, neighbor_mac: {neighbor_mac}")

                # add rule
                print(f"table_add at {sw_name}")
                self.controllers[sw_name].table_add(
                    "mpls_tbl",
                    "mpls_forward",
                    [str(port_num), str(0)],
                    [neighbor_mac, str(port_num)],
                )
                self.controllers[sw_name].table_add(
                    "mpls_tbl",
                    "penultimate",
                    [str(port_num), str(1)],
                    [neighbor_mac, str(port_num)],
                )

    def main(self):
        """Main function"""
        self.run()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-traffic",
        help="Path to scenario.base-traffic",
        type=str,
        required=False,
        default="",
    )
    parser.add_argument("--slas", help="Path to scenario.slas", type=str, required=False, default="")
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    controller = Controller(args.base_traffic, args.slas).main()
