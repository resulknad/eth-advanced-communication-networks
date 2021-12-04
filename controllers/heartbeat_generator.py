# Copied from Exercise 7
# https://gitlab.ethz.ch/nsg/public/adv-net-2021/-/blob/main/07-Fast-Reroute/solution/heartbeat_generator.py

"""Heartbeat generator that periodically sends probes to all switches. One probe
per port connected to a switch. 
"""

#!/usr/bin/env python3

import os
import socket
import struct
import time
import threading
import codecs

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


def build_packet(src_mac, dst_mac, heartbeat_port):
    """Builds raw heart beat packet to send to switches"""

    # ethernet
    src_bytes = b"".join([codecs.decode(x,'hex') for x in src_mac.split(":")])
    dst_bytes = b"".join([codecs.decode(x,'hex') for x in dst_mac.split(":")])
    eth = src_bytes + dst_bytes + struct.pack("!H", 0x1234)

    # heart beat
    heartbeat = heartbeat_port << 7 | (1 << 6) # port | cpu_bit
    heartbeat = struct.pack("!H", heartbeat)
    return eth + heartbeat

def send_thread(intf_name, src_mac, dst_mac, port, time_interval):
    """Periodically sends one packet to `intf_name` every `time_interval`"""

    # build packet
    pkt = build_packet(src_mac, dst_mac, port)
    # prepare raw socket
    send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    send_socket.bind((intf_name, 0))

    # send packet loop
    while True:
        send_socket.send(pkt)
        time.sleep(time_interval)


class HeartBeatGenerator(object):
    """Heart beat Generator."""

    def __init__(self, time_interval):
        """Initializes the topology and data structures."""

        if not os.path.exists('topology.json'):
            print("Could not find topology object!\n")
            raise Exception

        self.topo = load_topo('topology.json')
        self.traffic_threads = []
        self.time_interval = time_interval

    def run(self):
        """Main runner"""
        # for each switch
        for switch in self.topo.get_p4switches():
            # gets the ethernet interface name of the cpu port of a given switch.
            # this can be used to either receive from or send packets to the switch. 
            cpu_intf = self.topo.get_cpu_port_intf(switch)

            # get all direct hosts and add direct entry
            for neighbor_switch in self.topo.get_p4switches_connected_to(switch):
                # get port to specific neighbor
                sw_port = self.topo.node_to_node_port_num(switch, neighbor_switch)
                src_mac = self.topo.node_to_node_mac(switch, neighbor_switch)
                dst_mac = self.topo.node_to_node_mac(neighbor_switch, switch)
                # starts threads
                t = threading.Thread(target=send_thread, args=(cpu_intf, src_mac, dst_mac, sw_port, self.time_interval), daemon=True)
                t.start()
                # save all threads (currently not used)
                self.traffic_threads.append(t)