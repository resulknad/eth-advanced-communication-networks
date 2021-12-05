"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from typing import Dict, List

from itertools import product
from collections import defaultdict

from pulp.apis import cplex_api

from graph import Graph
from mcf import MCF, FlowEndpoint
import pandas as pd
import collections
import time
import math

TOTAL_TIME = 60 # seconds

# parameters
MCF_INTERVAL_SIZE = 5 # seconds
NORMALIZE_BW_ACROSS_TIME = False
UDP_COST_MULTIPLIER = 1
TCP_COST_MULTIPLIER = 1
UDP_BW_MULTIPLIER = 1
TCP_BW_MULTIPLIER = 1
TCP_ACK_BW_MULTIPLIER = 0.5

# tcp flows rarely finish on time, so we can consider that for our model
TCP_END_TIME_MULTIPLIER = 1.5

# SLA selection
FILTER_SLA_MAX_PORT = 200
FILTER_INCLUDE_SLA_BY_NAME = ["prr_28"] # this basically means include UDP flows from 200-300


class Controller(object):
    def __init__(self, base_traffic, slas):
        self.base_traffic_file = base_traffic
        self.slas_file = slas
        self.topo = load_topo("topology.json")
        self.controllers = {}  # type: Dict[str, SimpleSwitchThriftAPI]
        self.init_mcf(base_traffic, "topology.json", slas)
        self.init()

    def _preprocess_base_traffic(self, base_traffic):
        # read base traffic
        df = pd.read_csv(base_traffic)
        df = df.rename(columns=lambda x: x.strip())

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
            (
                (df["type"] != "wp")
                & (
                    (df["sport_start"] <= FILTER_SLA_MAX_PORT)
                    & (df["sport_end"] <= FILTER_SLA_MAX_PORT)
                    & (df["dport_start"] <= FILTER_SLA_MAX_PORT)
                    & (df["dport_end"] <= FILTER_SLA_MAX_PORT)
                )
            )
            | df["id"].isin(FILTER_INCLUDE_SLA_BY_NAME)
        ]
        self.filtered_slas = df

    def _sla_applies(self, from_host, from_port, to_host, to_port, protocol):
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

            if (
                src_match
                and src_port_match
                and dst_match
                and dst_port_match
                and sla.protocol == protocol
            ):
                relevant_slas.append(sla)
        return relevant_slas

    def _get_waypoints(self, slas):
        df = pd.read_csv(slas)
        df = df.rename(columns=lambda x: x.strip())

        wps = df[df["type"] == "wp"]

        return wps[["src", "dst", "target", "protocol"]].values.tolist()

    def _add_flow_to_mcf(self, mcf, src_fe, dst_fe, flow, interval_length):

        cost_multiplier = (
            UDP_COST_MULTIPLIER if flow["protocol"] == "udp" else TCP_COST_MULTIPLIER
        )
        bw_multiplier = (
            UDP_BW_MULTIPLIER if flow["protocol"] == "udp" else TCP_BW_MULTIPLIER
        )

        # TODO: properly parse Mbps for rate
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

    def init_mcf(self, base_traffic, topology, slas):
        self._preprocess_slas(slas)

        # read topology
        g = Graph(topology)

        df = self._preprocess_base_traffic(base_traffic)

        # compute the time intervals for the MCF problems
        num_intervals = math.ceil(TOTAL_TIME / MCF_INTERVAL_SIZE)
        intervals = [MCF_INTERVAL_SIZE * i for i in range(1, num_intervals + 1)]

        start_time = 0

        flows_to_path = defaultdict(list)
        flows_to_path_weights = defaultdict(list)

        for end_time in intervals:
            flows = df[
                (df["start_time"] <= end_time)
                & (
                    (df["end_time"] >= start_time)
                    | (
                        (df["end_time"] * TCP_END_TIME_MULTIPLIER >= start_time)
                        & (df["protocol"] == "tcp")
                    )
                )
            ]
            print(
                "Have {} flows from {} to {}".format(
                    flows.shape[0], start_time, end_time
                )
            )
            m = MCF(g)
            interval_length = end_time - start_time

            for (i, f) in flows.iterrows():
                if self._sla_applies(
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

            # add wps
            wps = self._get_waypoints(slas)
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
                if src.host == "":
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

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def run(self):
        """Run function"""

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

        self.install_paths(self.paths)

    def install_paths(self, all_paths):
        self.ecmp_group_counters = collections.defaultdict(int)

        for (sw_name, controller) in self.controllers.items():

            print(f"done removing circuits at {sw_name}")

            for key in all_paths:
                (src_fe, dst_fe) = key
                paths = all_paths[key]
                if len(paths) == 0:
                    print("WARNING: empty list of paths passed, skipping")
                    continue

                # on the destination switch we want a miss in the virtual_circuit table
                # in order for ipv4_lpm to apply and generate a hit...
                if paths[0][-2] == sw_name:
                    continue

                src_ip = self.topo.get_host_ip(src_fe.host)  # + '/32'
                dst_ip = self.topo.get_host_ip(dst_fe.host)  # + '/32'

                print(src_ip, dst_ip)
                # install entry in ecmp_FEC_tbl
                for idx, path in enumerate(paths):
                    path_wo_hosts = path[1:-1]
                    print(path, path_wo_hosts)
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
                    [
                        str(src_ip),
                        str(dst_ip),
                        str(src_fe.port),
                        str(dst_fe.port),
                        str(6 if src_fe.protocol == "tcp" else 17),
                    ],
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
