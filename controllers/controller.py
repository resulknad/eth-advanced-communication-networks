"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from typing import Dict, List

from itertools import product

from pulp.apis import cplex_api

from graph import Graph
from mcf import MCF
import pandas as pd
import collections
import time

WARMUP = -1000
TOTAL_TIME = 60


class Controller(object):
    def __init__(self, base_traffic, slas):
        self.base_traffic_file = base_traffic
        self.slas_file = slas
        self.start_time = 0
        self.topo = load_topo("topology.json")
        self.controllers = {}  # type: Dict[str, SimpleSwitchThriftAPI]
        self.init_mcf(base_traffic, "topology.json", slas)
        self.init()

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

        df = df[
            (df["type"] == "wp")
            | (
                (df["sport_start"] <= 100)
                & (df["sport_end"] <= 100)
                & (df["dport_start"] <= 100)
                & (df["dport_end"] <= 100)
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

    def init_mcf(self, base_traffic, topology, slas):
        self._preprocess_slas(slas)

        # read topology
        g = Graph(topology)

        df = self._preprocess_base_traffic(base_traffic)
        # find points in time where either 1. a flow starts or 2. a flow end
        intervals = list(set(list(df["end_time"]) + list(df["start_time"])))

        # append scenario end time
        intervals.append(60)

        # sort
        intervals = sorted(intervals)

        self.time_path_pairs = collections.deque()
        start_time = 0
        intervals = [10.0 * i for i in range(6, 7)]

        for end_time in intervals:
            flows = df[(df["start_time"] <= end_time) & (df["end_time"] >= start_time)]
            interval_length = end_time - start_time
            print(
                "Have {} flows from {} to {}".format(
                    flows.shape[0], start_time, end_time
                )
            )
            m = MCF(g)

            # for which pairs are we going to establish a virtual circuti?
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
                    cost_multiplier = 1 if f["protocol"] == "udp" else 1
                    bw_multiplier = 1 if f["protocol"] == "udp" else 1
                    # TOOD: properly parse Mbps for rate
                    bw = float(f["rate"][:-4]) * bw_multiplier
                    m.add_commodity(
                        f["src"],
                        f["dst"],
                        bw,
                        cost_multiplier=cost_multiplier
                        # * ((f["end_time"] - f["start_time"]) / interval_length),
                    )

                    # acks dont need much bw
                    if f["protocol"] == "tcp":
                        m.add_commodity(
                            f["dst"],
                            f["src"],
                            bw / 5,
                        )

            # adding wps
            wps = self._get_waypoints(slas)
            for (src, target, wp) in wps:
                m.add_waypoint(src, target, wp)

            m.make_and_solve_lp()
            m.print_paths_summary()
            self.time_path_pairs.append((start_time, m.get_paths()))
            start_time = end_time

        print("time_path_pairs", self.time_path_pairs)

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        # self.reset_states()
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

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
                    pass

        self.ecmp_group_counters = collections.defaultdict(int)
        # self.install_paths(self.time_path_pairs[4][1])
        previous_circuits = {}
        while True:
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

            for (key, _) in added:
                (src_host, dst_host) = key
                paths = all_paths[key]
                # on the destination switch we want a miss in the virtual_circuit table
                # in order for ipv4_lpm to apply and generate a hit...
                if len(paths) == 0:
                    print("WARNING: empty list of paths passed, skipping")
                    continue

                if paths[0][-2] == sw_name:
                    continue

                # TODO: install reverse p[ath]
                src_ip = self.topo.get_host_ip(src_host)  # + '/32'
                dst_ip = self.topo.get_host_ip(dst_host)  # + '/32'

                print(src_ip, dst_ip)
                # install entry in ecmp_FEC_tbl
                for idx, path in enumerate(paths):
                    path_wo_host = path[1:-1]
                    print(path_wo_host)
                    labels = self.get_mpls_stack(path_wo_host)
                    print(labels)
                    num_hops = len(path_wo_host) - 1
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
