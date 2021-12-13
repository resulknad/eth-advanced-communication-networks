from collections import defaultdict
import time
from typing import Dict, Tuple, List

from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.topology import NetworkGraph

from flow_endpoint import FlowEndpoint

# IP protocol field values
TYPE_TCP = 0x6
TYPE_UDP = 0x11

# A collection of paths is a mapping from the two endpoints to all paths from
# the first to the second. The paths per endpoint-tuple are a list of lists,
# the inner lists contain the name of the switches on the path in order.
Paths = Dict[Tuple[FlowEndpoint, FlowEndpoint], List[List[str]]]


class TableManager:
    """Keeps track and maintains virtual circuits on the switches."""
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
        """Replace the paths for the base traffic with the given paths

        Args:
            paths (Paths): Paths for the flows in the base traffic
        """
        self.paths["base"] = paths

    def replace_additional_traffic(self, paths: Paths):
        """Replace the paths for the additional traffic with the given paths

        Args:
            paths (Paths): Paths for the flows in detected additional traffic
        """
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

        # These don't have to be touched
        same = set_all_paths & set_previous_paths
        # These need to new newly installed
        added = set_all_paths - set_previous_paths
        # These must be removed
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

                # install MPLS labels in virtual_circuit_path table
                # One entry for each possible path
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
