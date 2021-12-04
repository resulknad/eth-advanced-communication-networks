"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from typing import Dict, List

from itertools import product

from heartbeat_generator import HeartBeatGenerator
from scapy.all import *

from graph import Graph
from mcf import MCF
import pandas as pd
import collections
import time
import threading

TYPE_HEARTBEAT = 0x1234

WARMUP = -1000
TOTAL_TIME = 60

# parameters
NORMALIZE_BW_ACROSS_TIME = False
UDP_COST_MULTIPLIER = 1
TCP_COST_MULTIPLIER = 1
UDP_BW_MULTIPLIER = 1
TCP_BW_MULTIPLIER = 1
TCP_ACK_BW_MULTIPLIER = 0.5

HEARTBEAT_FREQUENCY = 0.5


class Controller(object):
    def __init__(self, base_traffic, slas):
        self.base_traffic_file = base_traffic
        self.slas_file = slas
        self.start_time = 0
        self.topo = load_topo("topology.json")
        self.controllers = {}  # type: Dict[str, SimpleSwitchThriftAPI]

        self.init_mcf(base_traffic, "topology.json", slas)
        self.init_controllers()
        self.init_heartbeats()

    def _preprocess_base_traffic(self, base_traffic):
        # read base traffic
        df = pd.read_csv(base_traffic)
        df = df.rename(columns=lambda x: x.strip())

        curr_time = 0

        # map flows defined in terms of size to bandwidth + time pairs
        default_bw = 10
        rows = df[pd.isna(df["rate"])]
        for i, r in rows.iterrows():
            # TODO: parse megabytes and Mbps etc.
            size = int(r["size"][:-2])

            rate = default_bw
            df.loc[i, "rate"] = str(rate) + "Mbps"
            df.loc[i, "duration"] = size / rate

        # add end_time everywhere
        df["end_time"] = df["start_time"] + df["duration"]
        return df

    def _preprocess_slas(self, slas):
        # read SLAs
        df = pd.read_csv(slas)
        df = df.rename(columns=lambda x: x.strip())

        # -1 will be value for wildcard

        df["sport"] = df["sport"].str.replace("*", "-1")
        sport = df["sport"].str.split("--", n=1, expand=True)
        df["sport_start"], df["sport_end"] = sport[0].astype("int32"), sport[1].astype(
            "int32"
        )

        df["dport"] = df["dport"].str.replace("*", "-1")
        dport = df["dport"].str.split("--", n=1, expand=True)
        df["dport_start"], df["dport_end"] = dport[0].astype("int32"), dport[1].astype(
            "int32"
        )

        # select SLAs that should be considered
        df = df[
            (df["type"] == "wp")
            | (
                (df["sport_start"] <= 200)
                & (df["sport_end"] <= 200)
                & (df["dport_start"] <= 200)
                & (df["dport_end"] <= 200)
            )
        ]
        self.filtered_slas = df

    def _sla_applies(self, from_host, from_port, to_host, to_port):
        relevant_slas = []
        for (indx, sla) in self.filtered_slas.iterrows():
            src_match = sla.src == "*" or sla.src == from_host
            src_port_match = (sla.sport_start <= from_port) and (
                sla.sport_end == -1 or sla.sport_end >= from_port
            )
            dst_match = sla.dst == "*" or sla.dst == to_host
            dst_port_match = (sla.dport_start <= to_port) and (
                sla.dport_end == -1 or sla.dport_end >= to_port
            )

            if src_match and src_port_match and dst_match and dst_port_match:
                relevant_slas.append(sla)
        return relevant_slas

    def _get_waypoints(self, slas):
        df = pd.read_csv(slas)
        df = df.rename(columns=lambda x: x.strip())

        wps = df[df["type"] == "wp"]
        return wps[["src", "dst", "target"]].values.tolist()

    def init_heartbeats(self):
        """
        Initiates the heartbeat messages and starts listening for failure/recovery notifications.
        Must be called AFTER self.init_controllers().
        """

        self.failed_links = set()

        # configure mirroring session to cpu port for failure notifications
        self._set_mirroring_sessions()
        print("set mirroring sessions")

        # initiate the heartbeat messages
        self._heartbeat(HEARTBEAT_FREQUENCY)
        print("started sending heartbeats")

        # Sniff the traffic coming from switches
        t = threading.Thread(target=self._sniff_cpu_ports)
        t.start()
        print("started listening for link state notifications")


    def init_mcf(self, base_traffic, topology, slas):
        self._preprocess_slas(slas)

        # read topology
        g = Graph(topology)

        df = self._preprocess_base_traffic(base_traffic)

        # find points in time where either 1. a flow starts or 2. a flow ends
        # intervals = list(set(list(df["end_time"]) + list(df["start_time"])))

        # append scenario end time
        # intervals.append(60)

        # sort
        # intervals = sorted(intervals)

        # for now, we use only one interval
        intervals = [60]

        self.time_path_pairs = collections.deque()
        start_time = 0

        for end_time in intervals:
            flows = df[(df["start_time"] <= end_time) & (df["end_time"] >= start_time)]
            interval_length = end_time - start_time
            print(
                "Have {} flows from {} to {}".format(
                    flows.shape[0], start_time, end_time
                )
            )

            m = MCF(g)

            # for which pairs are we going to establish a virtual circuit?
            pairs = {}
            for (i, f) in flows.iterrows():
                if self._sla_applies(f["src"], f["sport"], f["dst"], f["dport"]):
                    pairs[(f["src"], f["dst"])] = True

            # make sure to consider all of the flows inbetween the two endpoints
            # since we do not differentiate based on protocol / port atm for virtual circuits
            for (i, f) in flows.iterrows():
                if (f["src"], f["dst"]) in pairs or (
                    (f["dst"], f["src"]) in pairs and f["protocol"] == "tcp"
                ):
                    cost_multiplier = (
                        UDP_COST_MULTIPLIER
                        if f["protocol"] == "udp"
                        else TCP_COST_MULTIPLIER
                    )
                    bw_multiplier = (
                        UDP_BW_MULTIPLIER
                        if f["protocol"] == "udp"
                        else TCP_BW_MULTIPLIER
                    )

                    # TODO: properly parse Mbps for rate
                    bw = float(f["rate"][:-4]) * bw_multiplier
                    if NORMALIZE_BW_ACROSS_TIME:
                        bw *= (f["end_time"] - f["start_time"]) / interval_length
                    m.add_commodity(
                        f["src"],
                        f["dst"],
                        bw,
                        cost_multiplier=cost_multiplier,
                        add_on_conflict=NORMALIZE_BW_ACROSS_TIME,
                        # * ,
                    )

                    # for TCP flows, we also need a path from dst to src for the acks (with lower bw)
                    if f["protocol"] == "tcp":
                        m.add_commodity(
                            f["dst"],
                            f["src"],
                            bw * TCP_ACK_BW_MULTIPLIER,
                            add_on_conflict=NORMALIZE_BW_ACROSS_TIME,
                        )

            # add wps
            wps = self._get_waypoints(slas)
            for (src, target, wp) in wps:
                m.add_waypoint(src, target, wp)

            # solve the LP
            m.make_and_solve_lp()
            m.print_paths_summary()
            self.time_path_pairs.append((start_time, m.get_paths()))
            start_time = end_time

        print("time_path_pairs", self.time_path_pairs)

    def init_controllers(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def _set_mirroring_sessions(self):
        for p4switch in self.topo.get_p4switches():
            cpu_port = self.topo.get_cpu_port_index(p4switch)
            self.controllers[p4switch].mirroring_add(100, cpu_port)

    def link_state_changed(self, failures):
        """Called if a link fails or recovers.

        Args:
            failures (list(tuple(str, str))): List of failed links.
        """
        print(f"Got a link state change notification! Failures: {failures}", flush=True)

    def _heartbeat(self, frequency):
        """Runs heartbeat threads"""
        heartbeat = HeartBeatGenerator(frequency)
        heartbeat.run()

    def process_packet(self, pkt):
        """Processes received packets to detect failure and recovery notifications"""

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
                port = (payload & 0xff80) >> 7
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

    def _sniff_cpu_ports(self):
        """Sniffs traffic coming from switches"""
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        sniff(iface=cpu_interfaces, prn=self.process_packet)

    def run(self):
        """Run function"""
        self.start_time = time.time()
        for (sw_name, controller), dst_sw_name in product(
            self.controllers.items(), self.topo.get_p4switches()
        ):

            # do the following only once per switch (i.e., when the destination is ourselves)
            if sw_name == dst_sw_name:

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

        print("done installing basic table entries", flush=True)

        self.ecmp_group_counters = collections.defaultdict(int)
        previous_circuits = {}
        while True:
            # TODO: remove before handin, might slow down the controller
            # make sure the log is flushed
            print("", end="", flush=True)

            if len(self.time_path_pairs) == 0:
                print("WARNING: no more paths to install, nop")
                time.sleep(10)
                continue

            start_time, circuits = self.time_path_pairs[0]
            curr_time = time.time() - self.start_time - WARMUP

            if curr_time >= start_time:
                self.time_path_pairs.popleft()
                print(
                    "installing new virtual circuits",
                    time.time(),
                    "start time",
                    self.start_time,
                )
                st = time.time()
                self.install_paths(circuits, previous_circuits)
                et = time.time()
                previous_circuits = circuits
                print("which took ", et - st, " and started at", curr_time)
            else:
                time.sleep(start_time - curr_time)

    def install_paths(self, all_paths, previous_paths):
        to_set = lambda ps: set(map(lambda x: (x[0], str(x[1])), ps.items()))
        set_all_paths = to_set(all_paths)
        set_previous_paths = to_set(previous_paths)

        same = set_all_paths & set_previous_paths
        added = set_all_paths - set_previous_paths
        removed = set_previous_paths - set_all_paths

        print("same", len(same))
        print("added", len(added))
        print("removed", len(removed))
        for (sw_name, controller) in self.controllers.items():
            for (key, _) in removed:
                (src_host, dst_host) = key
                paths = previous_paths[key]

                if len(paths) == 0:
                    print("WARNING: empty list of paths passed, skipping")
                    continue

                if paths[0][-2] == sw_name:
                    continue

                src_ip = self.topo.get_host_ip(src_host)  # + '/32'
                dst_ip = self.topo.get_host_ip(dst_host)  # + '/32'

                self.controllers[sw_name].table_delete_match(
                    "virtual_circuit", [str(src_ip), str(dst_ip)]
                )

            print(f"done removing circuits at {sw_name}")

            for (key, _) in added:
                (src_host, dst_host) = key
                paths = all_paths[key]
                if len(paths) == 0:
                    print("WARNING: empty list of paths passed, skipping")
                    continue

                # on the destination switch we want a miss in the virtual_circuit table
                # in order for ipv4_lpm to apply and generate a hit...
                if paths[0][-2] == sw_name:
                    continue

                # TODO: install reverse p[ath]
                src_ip = self.topo.get_host_ip(src_host)  # + '/32'
                dst_ip = self.topo.get_host_ip(dst_host)  # + '/32'

                print(src_ip, dst_ip)
                # install entry in ecmp_FEC_tbl
                for idx, path in enumerate(paths):
                    path_wo_hosts = path[1:-1]
                    print(path_wo_hosts)
                    labels = self.get_mpls_stack(path_wo_hosts)
                    print(labels)
                    num_hops = len(path_wo_hosts) - 1
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

                self.controllers[sw_name].table_add(
                    "virtual_circuit",
                    "ecmp_group",
                    [str(src_ip), str(dst_ip)],
                    [str(self.ecmp_group_counters[sw_name]), str(len(paths))],
                )
                self.ecmp_group_counters[sw_name] += 1

            print(f"done adding circuits at {sw_name}")

    def get_mpls_stack(self, path) -> List[int]:
        """
        Converts the given path into a list of MPLS labels

        Returns
            list[int]: MPLS labels, the first element is the top of the stack
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
