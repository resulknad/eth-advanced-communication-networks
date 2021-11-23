"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

class Controller(object):

    def __init__(self, base_traffic, slas):
        self.base_traffic_file = base_traffic
        self.topo = load_topo('topology.json')
        self.controllers = {}
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

        for sw_name, controller in self.controllers.items():
            for dst_sw_name in self.topo.get_p4switches():

                # if it's ourselves, install table entry for the directly connected host
                if sw_name == dst_sw_name:
                    # there should only be one host, but let's keep it generic
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        port_num = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.topo.get_host_ip(host) + '/32'
                        host_mac = self.topo.get_host_mac(host)

                        # add rule
                        print(f'table_add at {sw_name}')
                        self.controllers[sw_name].table_add('ipv4_lpm', 'set_nhop', [str(host_ip)], [str(host_mac), str(port_num)])

                # check if there are directly connected hosts
                # (we know there is one for each switch, but let's keep it generic)
                else:
                    if self.topo.get_hosts_connected_to(dst_sw_name):
                        shortest_path = self.topo.get_shortest_paths_between_nodes(sw_name, dst_sw_name)[0]
                        nhop_name = shortest_path[1]
                        nhop_mac = self.topo.node_to_node_mac(nhop_name, sw_name)
                        port_num = self.topo.node_to_node_port_num(sw_name, nhop_name)
                        
                        for host in self.topo.get_hosts_connected_to(dst_sw_name):
                            host_ip = self.topo.get_host_ip(host) + '/32'

                            # add rule
                            print(f'table_add at {sw_name}')
                            self.controllers[sw_name].table_add('ipv4_lpm', 'set_nhop', [str(host_ip)], [str(nhop_mac), str(port_num)])


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
