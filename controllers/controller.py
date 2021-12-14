import argparse
import threading
import time
import struct
import dataclasses
import random
import socket
from copy import deepcopy
from typing import Dict, List

from scapy.all import sniff, Ether, raw, UDP, IP
from scapy.contrib.mpls import MPLS

import pandas as pd

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

from graph import Graph
from heartbeat_generator import HeartBeatGenerator, TYPE_HEARTBEAT
from parameters import Parameter
from flow import Flow
from table_manager import TableManager
from flow_manager import FlowManager

# Ethernet protocol field values
TYPE_IPV4 = 0x800
TYPE_MPLS = 0x8847

# ============================== TUNABLE PARAMETERS ==============================
# These parameters allow to fine-tune our solution, obtaining different tradeoffs.
# The parameters are described in detail in parameters.py

DEFAULT_PARAMS = Parameter(
    total_time=60,
    mcf_interval_size=5,
    normalize_bw_across_time=False,
    tcp_default_bw=10,
    udp_cost_multiplier=1,
    tcp_cost_multiplier=1,
    udp_bw_multiplier=1,
    tcp_bw_multiplier=1,
    tcp_ack_bw_multiplier=0.5,
    heartbeat_frequency=0.1,
    tcp_duration_multiplier=1.5,
    additional_traffic_bw=10,
    controller_forward_mpls=True,
    additional_traffic_purge_interval=1000,
    additional_traffic_purge=False,
    slas=[
        "fcr_1", # 1--100 TCP 1
        # "prr_2", # 1--100 UDP 0.99
        "fct_3", # 1--100 TCP 20
        "fct_4", # 1--100 TCP 15
        "fct_5", # 1--100 TCP 10
        # "delay_6", # 1--100 UDP 0.017
        # "delay_7", # 1--100 UDP 0.015
        # "delay_8", # 1--100 UDP 0.012
        "fcr_9", # 101--200 TCP 1
        # "prr_10", # 101--200 UDP 0.99
        "fct_11", # 101--200 TCP 20
        "fct_12", # 101--200 TCP 15
        "fct_13", # 101--200 TCP 10
        # "delay_14", # 101--200 UDP 0.03
        # "delay_15", # 101--200 UDP 0.025
        # "delay_16", # 101--200 UDP 0.02
        "fcr_17", # 201--300 TCP 1
        # "prr_18", # 201--300 UDP 0.75
        # "prr_19", # 201--300 UDP 0.95
        # "prr_20", # 201--300 UDP 0.99
        "fct_21", # 201--300 TCP 15
        "fct_22", # 201--300 TCP 10
        # "delay_23", # 201--300 UDP 0.02
        # "delay_24", # 201--300 UDP 0.012
        "fcr_25", # 301--400 TCP 1
        "prr_26", # 301--400 UDP 0.75
        "prr_27", # 301--400 UDP 0.95
        "prr_28", # 301--400 UDP 0.99
        # "delay_29", # 301--400 UDP 0.06
        # "delay_30", # 301--400 UDP 0.04
        # "prr_31", # 60001--* UDP 0.75
        # "prr_32", # 60001--* UDP 0.95
        # "prr_33", # 60001--* UDP 0.99
        # "wp_34", # LON_h0 -> BAR_h0 udp PAR
        "wp_35", # POR_h0 -> GLO_h0 udp PAR
        "wp_36", # BRI_h0 -> BAR_h0 udp PAR
        "wp_37", # BER_h0 -> LIS_h0 udp MAD
        "wp_38", # LIS_h0 -> BER_h0 udp MAD
    ])


def preprocess_slas(slas_file, params: Parameter):
    """Reads the SLA file, makes some transformations (dealing with ranges and wildcards), and then filters
    out the SLAs that should not be considered. Returns the remaining SLAs (to be considered) as a DataFrame.

    Args:
        slas_file (str): Path to the SLA csv file
        params (Parameter): Tunable parameter object

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
    df = df[df["id"].isin(params.slas)]

    return df


def preprocess_base_traffic(base_traffic_file, params: Parameter):
    """Reads the base traffic file and transforms size-based (TCP) flows to bandwidth/duration-based flows.

    Args:
        slas_file (str): Path to the base traffic csv file
        params (Parameter): Tunable parameter object

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
        df.loc[i, "rate"] = str(params.tcp_default_bw) + "Mbps"
        df.loc[i, "duration"] = (size / params.tcp_default_bw) * params.tcp_duration_multiplier

    # add end_time everywhere
    df["end_time"] = df["start_time"] + df["duration"]
    return Flow.from_df(df)


class Controller(object):
    def __init__(self, base_traffic_file, slas_file, params=DEFAULT_PARAMS):
        """Initializes a new controller instance and performs some setup tasks.

        Args:
            base_traffic_file (str): path to the base traffic file
            slas_file (str): path to the SLA file
            params (Parameter): Tunable parameter object
        """
        topo_file = "topology.json"
        self.topo = load_topo(topo_file)
        self.g = Graph(topo_file)
        self.controllers: Dict[str, SimpleSwitchThriftAPI] = {}
        self.params = params

        self.additional_udp: List[Flow] = []

        self.filtered_slas = preprocess_slas(slas_file, self.params)
        self.base_traffic = preprocess_base_traffic(base_traffic_file, self.params)
        self.flow_manager = FlowManager(self.g, self.params, self.base_traffic, self.filtered_slas)
        self.additional_manager: FlowManager = None # FlowManager for additional traffic
        self.table_manager = TableManager(self.topo, self.controllers)

        self.flow_manager.compute_paths_mcf()
        self._prepare_additional_traffic()
        self.init_controllers()
        self.init_heartbeats()

    def _prepare_additional_traffic(self):
        """Initial computation for dynamically handling additional traffic.
        
        To accommodate additional traffic, we first (approximately) estimate how much bandwidth is still available.
        For this approximation, we normalize the bandwidth of the installed (base traffic) paths over the entire time interval.
        Using these normalized bandwidths, we create the (bandwidth) residual graph, which serves as the basis for
        computing paths for the additional traffic.
        """
        # Compute normalized bandwidths
        additional_manager = FlowManager(self.g, dataclasses.replace(self.params, normalize_bw_across_time=True),
                                         self.base_traffic, self.filtered_slas)
        additional_manager.compute_paths_mcf()

        # For the flow computations for the additional traffic, we do not normalize and we only want a single interval
        self.additional_traffic_params = dataclasses.replace(self.params,
                                                             normalize_bw_across_time=False,
                                                             mcf_interval_size=self.params.total_time)

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
        self._heartbeat(self.params.heartbeat_frequency)
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
        """Parses packets sent by the switches to detect failure and recovery notifications as well as additional traffic.

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

        elif UDP in packet and packet[UDP].sport > 60000:
            # This is an additional traffic packet
            ip = packet[IP]
            udp = packet[UDP]

            src = self.topo.get_host_name(str(ip.src))
            sport = udp.sport
            dst = self.topo.get_host_name(str(ip.dst))
            dport = udp.dport

            # TODO use actual time values (also add option to set default length of additional traffic)
            flow = Flow(src, sport, dst, dport, "udp", self.params.additional_traffic_bw, 0, 1)

            if flow not in self.additional_udp:
                print(f"Detected additional traffic from {src}:{sport} to {dst}:{dport}")

                self.additional_udp.append(flow)

                self.additional_manager = FlowManager(self.additional_traffic_graph, self.additional_traffic_params,
                                                      self.additional_udp, self.filtered_slas)
                self.additional_manager.compute_paths_mcf(list(self.failed_links))

                self.table_manager.replace_additional_traffic_paths(self.additional_manager.paths)
                self.table_manager.trigger_update()

            # While creating the paths for additional traffic, the switch will
            # have sent a bunch of packets for the same additional traffic to
            # the controller. We can choose to manually create the MPLS header
            # stack, select the ECMP group in the controller and send it out
            # to the next hop on the correct interface of the current switch
            # (essentially doing the work of the forwarding plane in the
            # controller for the time until a path is installed on the switch).
            if self.params.controller_forward_mpls:
                src_fe = flow.to_source_endpoint()
                dst_fe = flow.to_dest_endpoint()

                paths = self.table_manager.get_additional_traffic_paths()[(src_fe, dst_fe)]
                num_paths = len(paths)

                # Manually create the correct MPLS stack and forward the packet
                if num_paths > 0:
                    chosen = paths[random.randrange(num_paths)]
                    labels = self.table_manager._get_mpls_stack(chosen)

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
        self.table_manager.replace_base_traffic_paths(self.flow_manager.paths)

        if self.additional_manager:
            self.additional_manager.compute_paths_mcf(failures)
            self.table_manager.replace_additional_traffic_paths(self.additional_manager.paths)

        self.table_manager.trigger_update()

    def run(self):
        """Run function"""
        if self.params.additional_traffic_purge:
            threading.Thread(target=Controller.reset_thread, args=[self]).start()
        self.install_base_table_entries()
        self.table_manager.replace_base_traffic_paths(self.flow_manager.paths)
        self.table_manager.trigger_update()

    def reset_thread(self):
        """Thread to periodically reset additional traffic paths"""
        while True:
            time.sleep(self.params.additional_traffic_purge_interval)
            print("Resetting all additional traffic")
            self.additional_udp = []
            self.table_manager.replace_additional_traffic_paths({})
            self.table_manager.trigger_update()

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
    controller = Controller(args.base_traffic, args.slas, DEFAULT_PARAMS).main()
