"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from typing import Dict, List

from itertools import product

class Controller(object):

    def __init__(self, base_traffic, slas):
        self.base_traffic_file = base_traffic
        self.topo = load_topo('topology.json')
        self.controllers = {} # type: Dict[str, SimpleSwitchThriftAPI]
        self.init()

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()

    def reset_states(self):
        """Resets switches state"""
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def run(self):
        """Run function"""

        for (sw_name, controller), dst_sw_name in product(self.controllers.items(), self.topo.get_p4switches()):
            # if it's ourselves, install table entry for the directly connected host and for MPLS forwarding
            if sw_name == dst_sw_name:
                # there should only be one host, but let's keep it generic
                for host in self.topo.get_hosts_connected_to(sw_name):
                    port_num = self.topo.node_to_node_port_num(sw_name, host)
                    host_ip = self.topo.get_host_ip(host) + '/32'
                    host_mac = self.topo.get_host_mac(host)

                    # add rule
                    print(f'table_add at {sw_name}')
                    self.controllers[sw_name].table_add('FEC_tbl', 'set_nhop', [str(host_ip)], [str(host_mac), str(port_num)])

                for neighbor in self.topo.get_switches_connected_to(sw_name):
                    port_num = self.topo.node_to_node_port_num(sw_name, neighbor)
                    neighbor_mac = self.topo.node_to_node_mac(neighbor, sw_name)

                    print(f'iface for {sw_name}: port_num: {port_num}, neighbor: {neighbor}, neighbor_mac: {neighbor_mac}')

                    # add rule
                    print(f'table_add at {sw_name}')
                    self.controllers[sw_name].table_add('mpls_tbl', 'mpls_forward', [str(port_num), str(0)], [neighbor_mac, str(port_num)])
                    self.controllers[sw_name].table_add('mpls_tbl', 'penultimate', [str(port_num), str(1)], [neighbor_mac, str(port_num)])
                    pass

            # check if there are directly connected hosts
            # (we know there is one for each switch, but let's keep it generic)
            elif self.topo.get_hosts_connected_to(dst_sw_name):
                shortest_path = self.topo.get_shortest_paths_between_nodes(sw_name, dst_sw_name)[0]
                labels = self.get_mpls_stack(shortest_path)
                num_hops = len(labels)

                action_name = f'mpls_ingress_{num_hops}_hop'
                action_args = list(map(str, labels[::-1]))

                for host in self.topo.get_hosts_connected_to(dst_sw_name):
                    host_ip = self.topo.get_host_ip(host) + '/32'

                    # add rule
                    print(f'table_add at {sw_name}')
                    self.controllers[sw_name].table_add('FEC_tbl', action_name, [str(host_ip)], action_args)

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
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic',
    type=str, required=False, default='')
    parser.add_argument('--slas', help='Path to scenario.slas',
    type=str, required=False, default='')
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    controller = Controller(args.base_traffic, args.slas).main()
