import argparse
from collections import defaultdict
import threading
import math
import time
from scapy.all import sniff, Ether, raw, UDP, IP
import pandas as pd
import struct

from typing import Dict

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

from graph import Graph
from mcf import MCF
from flow_endpoint import FlowEndpoint
from heartbeat_generator import HeartBeatGenerator, TYPE_HEARTBEAT

TYPE_TCP = 0x6
TYPE_UDP = 0x11
TOTAL_TIME = 60  # seconds

# ============================== TUNABLE PARAMETERS ==============================
# These parameters allow to fine-tune our solution, obtaining different tradeoffs.
# The parameters are described in detail in the README.

MCF_INTERVAL_SIZE = 5  # seconds
NORMALIZE_BW_ACROSS_TIME = False
TCP_DEFAULT_BW = 10 # Mbps
UDP_COST_MULTIPLIER = 1
TCP_COST_MULTIPLIER = 1
UDP_BW_MULTIPLIER = 1
TCP_BW_MULTIPLIER = 1
TCP_ACK_BW_MULTIPLIER = 0.5
HEARTBEAT_FREQUENCY = 0.1   # seconds
TCP_DURATION_MULTIPLIER = 1.5

# ============================== SLA SELECTION ===================================
# These parameters allow to select the SLAs that should be considered.
# They are described in more detail in tehe README.
FILTER_INCLUDE_SLA_BY_NAME = [
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
        # "prr_31", # 60001--* UDP 0.75
        # "prr_32", # 60001--* UDP 0.95
        # "prr_33", # 60001--* UDP 0.99
        "wp_34", # LON_h0 -> BAR_h0 udp PAR
        "wp_35", # POR_h0 -> GLO_h0 udp PAR
        "wp_36", # BRI_h0 -> BAR_h0 udp PAR
        "wp_37", # BER_h0 -> LIS_h0 udp MAD
        "wp_38", # LIS_h0 -> BER_h0 udp MAD
        ]


class Controller(object):
    def __init__(self, base_traffic, slas):
        """Initializes a new controller instance and performs some setup tasks.

        Args:
            base_traffic (str): path to the base traffic file
            slas (str): path to the SLA file
        """
        self.base_traffic_file = base_traffic
        self.slas_file = slas
        self.topo_file = "topology.json"
        self.topo = load_topo(self.topo_file)
        self.controllers : Dict[str, SimpleSwitchThriftAPI] = {}
        self.ecmp_group_counters = defaultdict(int)

        self.init_mcf()
        self.init_controllers()
        self.init_heartbeats()

    def init_mcf(self):
        """Performs some initialization work for computing paths using multi-commodity flow problems. In particular,
        preprocesses SLAs and base traffic, creates a topology graph, computes intervals, and stores a map from intervals to flows.
        It then computes paths for all intervals for the initial topology (no failures).
        """
        # read topology
        self.g = Graph(self.topo_file)

        self._preprocess_slas()
        df = self._preprocess_base_traffic()

        # compute the time intervals for the MCF problems
        num_intervals = math.ceil(TOTAL_TIME / MCF_INTERVAL_SIZE)
        # Stores the end-time of each interval
        self.intervals = [MCF_INTERVAL_SIZE * i for i in range(1, num_intervals + 1)]

        # compute and store flows for each interval
        self.flows_for_interval = {}
        start_time = 0
        for end_time in self.intervals:
            flows = df[
                (df["start_time"] < end_time) & (df["end_time"] >= start_time)
            ]

            self.flows_for_interval[end_time] = flows

            print(
                "Have {} flows from {} to {}".format(
                    flows.shape[0], start_time, end_time
                )
            )

            start_time = end_time

        self._compute_paths_mcf()

    def _preprocess_base_traffic(self):
        """Reads the base traffic file and transforms size-based (TCP) flows to bandwidth/duration-based flows.

        Returns:
            pandas.DataFrame: a DataFrame containing the transformed base traffic
        """
        # read base traffic
        df = pd.read_csv(self.base_traffic_file)
        df = df.rename(columns=lambda x: x.strip())

        # map flows defined in terms of size to (bandwidth, duration) pairs
        rows = df[pd.isna(df["rate"])]
        for i, r in rows.iterrows():
            size = int(r["size"][:-2])
            df.loc[i, "rate"] = str(TCP_DEFAULT_BW) + "Mbps"
            df.loc[i, "duration"] = (size / TCP_DEFAULT_BW) * TCP_DURATION_MULTIPLIER

        # add end_time everywhere
        df["end_time"] = df["start_time"] + df["duration"]
        return df

    def _preprocess_slas(self):
        """Reads the SLA file, makes some transformations (dealing with ranges and wildcards), and then filters
        out the SLAs that should not be considered. The remaining SLAs (to be considered) are stored as a DataFrame attribute.
        """
        # read SLAs
        df = pd.read_csv(self.slas_file)
        df = df.rename(columns=lambda x: x.strip())

        sport = df["sport"].str.split("--", n=1, expand=True)
        df["sport_start"] = sport[0].replace('*', '0').astype("int32")
        df["sport_end"] = sport[1].replace('*', '65535').astype("int32")

        dport = df["dport"].str.split("--", n=1, expand=True)
        df["dport_start"] = dport[0].replace('*', '0').astype("int32")
        df["dport_end"] = dport[1].replace('*', '65535').astype("int32")

        # select SLAs that should be considered
        df = df[df["id"].isin(FILTER_INCLUDE_SLA_BY_NAME)]
        self.filtered_slas = df

    def _compute_paths_mcf(self, failures=None):
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

            for (_, f) in flows.iterrows():
                if self._slas_for_flow(
                    f["src"], f["sport"], f["dst"], f["dport"], f["protocol"]
                ):
                    src_fe = FlowEndpoint(
                        host=f["src"], port=f["sport"], protocol=f["protocol"]
                    )
                    dst_fe = FlowEndpoint(
                        host=f["dst"], port=f["dport"], protocol=f["protocol"]
                    )

                    if (src_fe, dst_fe) in flows_to_path:
                        # flow was already considered in previous timestep
                        # and we already have a path for it
                        m.subtract_paths(
                            flows_to_path[(src_fe, dst_fe)],
                            flows_to_path_weights[(src_fe, dst_fe)],
                        )

                        # for TCP flows, we also keep the reverse path for the ACKs
                        if f["protocol"] == "tcp":
                            m.subtract_paths(
                                flows_to_path[(dst_fe, src_fe)],
                                flows_to_path_weights[(dst_fe, src_fe)],
                            )
                    else:
                        # find path for that new flow
                        self._add_flow_to_mcf(m, src_fe, dst_fe, f, interval_length)

            # add waypoints
            wps = self._get_waypoints()
            for (src, target, wp, protocol) in wps:
                m.add_waypoint_to_all(src, target, wp, protocol)

            # solve the LP
            excess = m.make_and_solve_lp()

            if excess > 0:
                print(
                    "WARNING: could not satisfy all of the LP constraints! (excess: {})".format(
                        excess
                    )
                )
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
            print(
                "Have {} flows from {} to {} ({} new paths, {} saved)".format(
                    flows.shape[0], start_time, end_time, len(paths), len(flows_to_path)
                )
            )
            start_time = end_time

        self.paths = flows_to_path

        et = time.time()
        print(f"Computing new paths took {et - st}", flush=True)

    def _slas_for_flow(self, from_host, from_port, to_host, to_port, protocol):
        """Returns all SLAs that apply to a given flow.

        This does not include the waypoint SLAs.

        Args:
            from_host (str): The src host of the flow
            from_port (str): The src port of the flow
            to_host (str): The dst host of the flow
            to_port (str): The dst port of the flow
            protocol (str): The protocol of the flow

        Returns:
            list(pandas.Series): The SLAs that apply to the given flow
        """
        relevant_slas = []
        for (_, sla) in self.filtered_slas.iterrows():
            src_match = sla.src == "*" or sla.src == from_host
            src_port_match = sla.sport_start <= from_port <= sla.sport_end
            dst_match = sla.dst == "*" or sla.dst == to_host
            dst_port_match = sla.dport_start <= to_port <= sla.dport_end

            if (
                sla.type != "wp"
                and src_match
                and src_port_match
                and dst_match
                and dst_port_match
                and sla.protocol == protocol
            ):
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

    def _add_flow_to_mcf(self, mcf, src_fe, dst_fe, flow, interval_length):
        """Adds a flow to the given MCF problem. Cost and bandwidth are adjusted depending on tunable parameters.
        For TCP flows, an additional reverse flow is added to allow ACKs to be delivered.

        Args:
            mcf (MCF): The MCF problem instance
            src_fe (FlowEndpoint): The src flow endpoint
            dst_fe (FlowEndpoint): The dst flow endpoint
            flow (pandas.Series): The row in the traffic DataFrame corresponding to the flow
            interval_length (float): The size of the current interval (where the flow should be added), in seconds
        """

        cost_multiplier = (
            UDP_COST_MULTIPLIER if flow["protocol"] == "udp" else TCP_COST_MULTIPLIER
        )
        bw_multiplier = (
            UDP_BW_MULTIPLIER if flow["protocol"] == "udp" else TCP_BW_MULTIPLIER
        )

        bw = float(flow["rate"][:-4]) * bw_multiplier
        if NORMALIZE_BW_ACROSS_TIME:
            bw *= (flow["end_time"] - flow["start_time"]) / interval_length

        mcf.add_flow(
            src_fe,
            dst_fe,
            bw,
            cost_multiplier=cost_multiplier,
            add_on_conflict=NORMALIZE_BW_ACROSS_TIME,
        )

        # for TCP flows, we also need a path from dst to src for the acks (with lower bw)
        if flow["protocol"] == "tcp":
            mcf.add_flow(
                dst_fe,
                src_fe,
                bw * TCP_ACK_BW_MULTIPLIER,
                add_on_conflict=NORMALIZE_BW_ACROSS_TIME,
            )

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
        self._heartbeat(HEARTBEAT_FREQUENCY)
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
            str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1"))
            for sw_name in self.controllers
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

            src = str(ip.src)
            sport = udp.sport
            dst = str(ip.dst)
            dport = udp.dport

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
        previous_paths = self.paths
        self._compute_paths_mcf(failures)

        print("Installing new paths")
        # install new paths
        self.install_paths(self.paths, previous_paths)

    def run(self):
        """Run function"""
        self.install_base_table_entries()
        self.install_paths(self.paths)

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

                print(
                    f"iface for {sw_name}: port_num: {port_num}, neighbor: {neighbor}, neighbor_mac: {neighbor_mac}"
                )

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

    def install_paths(self, all_paths, previous_paths={}):
        """Installs paths on the ingress switches such that they add the correct MPLS header stacks to packets.
        Takes into account the previous paths (which are already installed on the switches) to minimize the number of table operations.

        Args:
            all_paths (dict): (All) paths that should be installed on the switches
            previous_paths (dict): The paths that are already installed on the switches
        """
        st = time.time()

        to_set = lambda ps: set(map(lambda x: (x[0], str(x[1])), ps.items()))
        set_all_paths = to_set(all_paths)
        set_previous_paths = to_set(previous_paths)

        same = set_all_paths & set_previous_paths
        added = set_all_paths - set_previous_paths
        removed = set_previous_paths - set_all_paths

        # remove paths
        for key, _ in removed:
            paths = previous_paths[key]

            if len(paths) == 0:
                print("WARNING: empty list of paths passed, skipping")
                continue

            sw_name = paths[0][1]

            (src_fe, dst_fe) = key
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

            if len(paths) == 0:
                print("WARNING: empty list of paths passed, skipping")
                continue

            sw_name = paths[0][1]

            (src_fe, dst_fe) = key
            src_ip = self.topo.get_host_ip(src_fe.host)
            dst_ip = self.topo.get_host_ip(dst_fe.host)

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
                    [str(self.ecmp_group_counters[sw_name]), str(idx)],
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
                [str(self.ecmp_group_counters[sw_name]), str(len(paths))],
            )
            self.ecmp_group_counters[sw_name] += 1

        print("done adding circuits")

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
    parser.add_argument(
        "--slas", help="Path to scenario.slas", type=str, required=False, default=""
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    controller = Controller(args.base_traffic, args.slas).main()
