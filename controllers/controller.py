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

        ecmp_group_counters = {}

        # initialize the counters
        for sw_name in self.topo.get_p4switches():
            ecmp_group_counters[sw_name] = 0

        for (sw_name, controller), dst_sw_name in product(self.controllers.items(), self.topo.get_p4switches()):

            # do the following only once per switch (i.e., when the destination is ourselves)
            if sw_name == dst_sw_name:

                # install table entry for the directly connected hosts
                # (there should only be one host, but let's keep it generic)
                for host in self.topo.get_hosts_connected_to(sw_name):
                    port_num = self.topo.node_to_node_port_num(sw_name, host)
                    host_ip = self.topo.get_host_ip(host) + '/32'
                    host_mac = self.topo.get_host_mac(host)

                    # add rule
                    print(f'table_add at {sw_name}')
                    self.controllers[sw_name].table_add('ipv4_lpm', 'set_nhop', [str(host_ip)], [str(host_mac), str(port_num)])

                # install table entries for MPLS forwarding
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
                shortest_paths = self.topo.get_shortest_paths_between_nodes(sw_name, dst_sw_name)

                print(f'shortest paths: {shortest_paths}')

                num_shortest_paths = len(shortest_paths)
                num_hops = len(shortest_paths[0]) - 1

                for host in self.topo.get_hosts_connected_to(dst_sw_name):
                    host_ip = self.topo.get_host_ip(host) + '/32'

                    # install entry in ipv4_lpm table
                    print(f'table_add at {sw_name}')
                    self.controllers[sw_name].table_add('ipv4_lpm', 'ecmp_group', [str(host_ip)], [str(ecmp_group_counters[sw_name]), str(num_shortest_paths)])

                    # install entry in ecmp_FEC_tbl
                    for idx, path in enumerate(shortest_paths):

                        labels = self.get_mpls_stack(path)
                        assert len(labels) == num_hops, 'shortest paths of different lengths!'

                        action_name = f'mpls_ingress_{num_hops}_hop'
                        action_args = list(map(str, labels[::-1]))

                        # add rule
                        print(f'table_add at {sw_name}')
                        self.controllers[sw_name].table_add('ecmp_FEC_tbl', action_name, [str(ecmp_group_counters[sw_name]), str(idx)], action_args)

                    ecmp_group_counters[sw_name] += 1

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
