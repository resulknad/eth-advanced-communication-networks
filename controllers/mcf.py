from collections import defaultdict
from pulp import LpProblem, LpMinimize, LpVariable, lpSum, PULP_CBC_CMD, LpStatus, value
from copy import deepcopy
from collections import defaultdict
from flow_endpoint import FlowEndpoint
from commodity import Commodity


class MCF:
    def __init__(self, graph):
        """Initializes a new MCF (Multi Commodity Flow) problem on the graph given in the constructor

        Args:
            graph (graph.Graph): Graph on which the multi commodity flow problem should be solved.
        """
        # copy because we will modify graph in here
        self.graph = deepcopy(graph)
        self.commodities = []
        self.paths = {}
        self.waypoints = {}

    def _extend_graph_with_flow_endpoint(self, fe):
        """Takes a FlowEndpoint (host, port, protocol) and extends the graph by adding a new node
         for the endpoint and connecting it with an infinite capacity edge to the existing node host (so host:node:port <---> host)

        Args:
            fe (FlowEndpoint): A FlowEndpoint describing host:port:protocol

        Returns:
            str: A string representation of the newly added node
        """
        self.graph.add_node(str(fe))

        # add infinite capacity edges from the copies of the node to the actual node
        self.graph.add_undirected_edge(str(fe), fe.host, delay=0, bw=(2 ** 32))
        return str(fe)

    def subtract_paths(self, paths, weights):
        """Subtracts the given weighted paths from the local graph. Meaning the bandwidth is decreased along each edge
        on the path by the weight.

        Args:
            paths (list of paths): list of list of nodes describing multiple paths
            weights (list of floats): one weight per path
        """
        for path, weight in zip(paths, weights):
            self.graph.subtract_path(path, weight)

    def remove_failed_link(self, n1, n2):
        """Removes a filed link from the local graph representation by setting its bandwidth (capacity) to 0
        in both directions

        Args:
            n1 (str): first node
            n2 (str): second node
        """
        self.graph.set_edge_bw(n1, n2, 0)

        # same for other direction
        self.graph.set_edge_bw(n2, n1, 0)

    def add_flow(
        self,
        src,
        dst,
        demand,
        allow_dup_commodity=False,
        cost_multiplier=1,
        add_on_conflict=False,
    ):
        """Adds a new commodity in our MCF. This function first adds two new nodes in the local graph for the specific flow endpoints.
        Recall that a single commodity is per-flow so the unique identifier is: (host1:port1:protocol) <-> (host2:port2:protocol).
        Those flow endpoint nodes are connected to the more general host nodes by an infinite capacity edge.

        A commodity describes the amount of traffic we would like to send from the source to the destination under minimal cost.
        Cost in our model is the link delay.

        Args:
            src (FlowEndpoint): A flow endpoint
            dst (FlowEndpoint): Second flow endpoint
            demand (float): How much bandwidth the flow requires.
            allow_dup_commodity (bool, optional): [description]. This is used internally for waypointing.
                        About how we handle duplicate commodities
            cost_multiplier (int, optional): [description]. Multiplies the commodities cost relative to the other commodities.
                        Encourages solutions which have a smaller delay for this specific flow.
            add_on_conflict (bool, optional): [description]. Should demands be added or the maximum taken out of the two,
                        if a commodity already exists and this function is called again.

        Returns:
            int: commodity id
        """
        src_node = self._extend_graph_with_flow_endpoint(src)
        dst_node = self._extend_graph_with_flow_endpoint(dst)

        # now we add the actual commodity
        commodity_id = self._add_commodity(
            src_node,
            dst_node,
            demand,
            allow_dup_commodity=allow_dup_commodity,
            cost_multiplier=cost_multiplier,
            add_on_conflict=add_on_conflict,
        )

        return (src_node, dst_node, commodity_id)

    def _get_commodity_by_src_and_dst(self, source, destination):
        """Returns the commodity for the given source destination pair. None if not found.

        Args:
            source (str): Source node in graph
            destination (str): Destination node in graph

        Returns:
            (int, Commodity): index and commodity
        """
        for i, commodity in enumerate(self.commodities):
            if (commodity.source, commodity.target) == (source, destination):
                return (i, commodity)
        return (None, None)

    def _add_commodity(
        self,
        source,
        target,
        demand,
        allow_dup_commodity=False,
        cost_multiplier=1,
        add_on_conflict=False,
    ):
        """Adds a commodity from source node to target node with given demand. Nodes must exist, used only internally.
        Add commodities via add_flow.

        Args:
            source (str): sourcenode
            target (str): targetnode
            demand (float): demand in bandwidth
            allow_dup_commodity (bool, optional): [description]. Defaults to False.
            cost_multiplier (int, optional): [description]. Defaults to 1.
            add_on_conflict (bool, optional): [description]. Defaults to False.

        Returns:
            int: commodity id
        """
        # if we do not want duplicate commodites (i.e. from same source to same target)
        # then we need to check whether a commodity exists and if so either add up the demands
        # or take the maximum (depending on the argument add_on_conflict)
        _, commodity = self._get_commodity_by_src_and_dst(source, target)
        if not allow_dup_commodity and commodity is not None:
            print(
                "WARNING: already have commodity for {} to {}. Will {} the demands {} and {}".format(
                    commodity.source,
                    commodity.target,
                    "add" if add_on_conflict else "take max out of",
                    demand,
                    commodity.demand,
                )
            )

            if add_on_conflict:
                commodity.demand += demand
            else:
                commodity.demand = max(demand, commodity.demand)

            commodity.cost_multiplier = max(commodity.cost_multiplier, cost_multiplier)
            return

        # can simply add a new commodity here
        self.commodities.append(Commodity(source, target, demand, cost_multiplier))
        return len(self.commodities) - 1

    def add_waypoint_to_all(self, source, target, waypoint, protocol):
        """Adds a waypointing requirement to all previously added flows (commodities) matching the given
        source, target and protocol. Does it by splitting the commodities into two distinct commodities
        so (source -> target) gets (source -> waypoint) and (waypoint -> target).

        Args:
            source (str): Source hostname
            target (str): Destination hostname
            waypoint (str): Waypoint hostname
            protocol (str): Protocol (tcp/udp)
        """
        wp = FlowEndpoint(host=waypoint, port=1, protocol=protocol)
        wps_to_add = []

        # first we make a list of all flows that match the waypoint
        # this is done in two steps because waypointing changes the commodities
        for commodity in self.commodities:
            if commodity.is_empty():
                continue

            s_fe = commodity.source_as_fe()
            t_fe = commodity.target_as_fe()
            if (
                s_fe.host == source
                and t_fe.host == target
                and s_fe.protocol == protocol
            ):
                wps_to_add.append([s_fe, t_fe, wp])

        # we now waypoint all of those flows
        for wp in wps_to_add:
            self.add_waypoint_to_flow(*wp)

    def add_waypoint_to_flow(self, source, target, waypoint):
        """Adds a waypoint to the given pair of FlowEndpoints. This inserts the given waypoint FlowEndpoint in the graph.
        Expects the source and target pair of FlowEndpoints to exist as nodes in the graph and as a part of a commodity
        which has been previously added.

        Args:
            source (FlowEndpoint): Source
            target (FlowEndpoint): Destination
            waypoint (FlowEndpoint): Waypoint

        Returns:
            str: string identifier of the waypoint node
        """
        if (str(source), str(target)) in self.waypoints:
            print(
                "WARNING: already have a waypoint for {} --- {} ----> {}. since a call to waypoints makes changes to the commodities"
                + ", it is of crucial importance to call add_waypoint after setting up all commodoties and only once. IGNORING".format(
                    source, waypoint, target
                )
            )
            return

        waypoint_str = self._extend_graph_with_flow_endpoint(waypoint)
        if not waypoint_str:
            print("WARNING: failed to add waypoint node. cannot add waypoint...")
            return False

        index, commodity = self._get_commodity_by_src_and_dst(str(source), str(target))
        if commodity is None:
            print(
                "WARNING: cannot add waypoint {} --- {} ----> {} for commodity/flow which has not been added yet. IGNORING.".format(
                    source, waypoint, target
                )
            )
            return

        # delete non-waypointed commodity, but since we are using indexes as ids
        # we add an empty commodity
        self.commodities[index] = Commodity("", "", 0, 0)

        assert commodity.source == str(source) and commodity.target == str(target)

        commodity1_id = self._add_commodity(
            commodity.source,
            waypoint_str,
            commodity.demand,
            True,
            cost_multiplier=commodity.cost_multiplier,
        )
        commodity2_id = self._add_commodity(
            waypoint_str,
            commodity.target,
            commodity.demand,
            True,
            cost_multiplier=commodity.cost_multiplier,
        )

        self.waypoints[(str(source), str(target))] = (
            waypoint_str,
            commodity1_id,
            commodity2_id,
        )

    def make_lp(self):
        """This creates a linear program out of the graph and commodities collected in this instance.
        Refer to the readme to see a thorough explanation of our LP.

        Returns:
            LpProblem: the linear program in all its glory
        """
        prob = LpProblem("Problem", LpMinimize)

        # creating one variable for each edge + commodity combination
        edges_str = list(map(str, self.graph.edges))
        edges_capacity = {str(e): e.bw for e in self.graph.edges}

        nodes_str = list(map(str, self.graph.nodes))

        commodities_str = list(map(str, range(len(self.commodities))))
        variables = LpVariable.dicts("Route", (edges_str, commodities_str), 0)
        cost = {
            edge: {
                commodity: self.graph.edges_map[edge].delay
                * self.commodities[int(commodity)].cost_multiplier
                for commodity in commodities_str
            }
            for edge in edges_str
        }
        edge_commodity = [(e, c) for e in edges_str for c in commodities_str]

        # add excess edges (as in PBR)
        # this ensure that LP is always feasible
        excess_edges_str = [
            "|".join([c.source, c.target]) + "_commodity" + str(i)
            for (i, c) in enumerate(self.commodities)
        ]

        excess_variables = LpVariable.dicts("Excess", excess_edges_str, 0, 2 ** 32)

        # objective: minimize cost over chosen capacity flows
        # minimize edge cost (number of hops basically)
        prob += (
            lpSum([variables[e][c] * cost[e][c] for (e, c) in edge_commodity])
            + lpSum([excess_variables[e] * (2 ** 16) for e in excess_edges_str]),
            "Sum_of_edge_commodity_cost",
        )

        # add capacity constaints
        for e in variables:
            prob += (
                lpSum([variables[e][c] for c in commodities_str]) <= edges_capacity[e],
                "%s_capacity" % e,
            )

        # add flow conservation
        # (except for supply / demand nodes)
        for c in range(len(self.commodities)):
            commodity = self.commodities[c]
            if commodity.source == "":
                continue
            for (name, node) in self.graph.nodes.items():
                outgoing = list(filter(lambda s: s.startswith(name + "|"), edges_str))
                incoming = list(filter(lambda s: s.endswith("|" + name), edges_str))

                # excess edges are handeled separately because they only allow for one commodity
                outgoing_excess = list(
                    filter(
                        lambda s: s.startswith(name + "|")
                        and s.endswith("_commodity" + str(c)),
                        excess_edges_str,
                    )
                )
                incoming_excess = list(
                    filter(
                        lambda s: s.endswith("|" + name + "_commodity" + str(c)),
                        excess_edges_str,
                    )
                )
                val = 0
                if commodity.source == name:
                    val = -commodity.demand
                    # print(outgoing_excess, incoming_excess)
                elif commodity.target == name:
                    val = commodity.demand

                prob += (
                    lpSum([variables[e][str(c)] for e in incoming])
                    + lpSum([excess_variables[e] for e in incoming_excess])
                ) + (
                    -lpSum([variables[e][str(c)] for e in outgoing])
                    - lpSum([excess_variables[e] for e in outgoing_excess])
                ) == val, "%s_%s_conservation" % (
                    node.name,
                    c,
                )
        # add waypoint constraints
        # basically we split a commodity into two commodities
        # and now require that either both are satisfied to the same degree
        # or not at all (by requiring that excess is equal)
        for (src, target), (_, c1_id, c2_id) in self.waypoints.items():
            c1 = self.commodities[c1_id]
            c2 = self.commodities[c2_id]
            prob += (
                excess_variables[
                    "{}|{}_commodity{}".format(c1.source, c1.target, c1_id)
                ]
                == excess_variables[
                    "{}|{}_commodity{}".format(c2.source, c2.target, c2_id)
                ],
                "%s_%s_%s_waypoint" % (c1.source, c1.target, c2.target),
            )
        return prob

    def make_and_solve_lp(self, verbose=False):
        """Calls make_lp and then the solver on the linear program. Extracts the paths out of the solution.

        Args:
            verbose (bool, optional): [description]. Defaults to False.

        Returns:
            float: Excess, so the amount of demanded bandwidth that could not be satisfied.
        """
        prob = self.make_lp()
        prob.solve(PULP_CBC_CMD(msg=0))

        if verbose:
            print("Status:", LpStatus[prob.status])

        # construct paths out of LP result
        result = [defaultdict(list) for _ in self.commodities]
        excess = 0
        for v in prob.variables():
            if v.varValue != 0.0:
                # do not consider excess edges
                if v.name.startswith("Route_"):
                    edge_name = v.name[6:]
                    from_to, commodity = (
                        edge_name[: edge_name.rindex("_")],
                        edge_name[edge_name.rindex("_") + 1 :],
                    )
                    nodes = from_to.split("|")
                    src, dst = nodes[0], nodes[1]

                    # do not use excess edges for actual paths...
                    result[int(commodity)][src].append((dst, v.varValue))
                    if verbose:
                        print("edge from", src, "to", dst, "commodity", commodity)
                if verbose:
                    print(v.name, "=", v.varValue)
                if v.name.startswith("Excess_"):
                    excess += v.varValue

        paths = defaultdict(list)

        # this is almost dfs, but it will visit some nodes twice
        # if they are shared on a path. graph is assumed to be a DAG
        # which should really be ok if the LP did not go horribly wrong
        def dfs(adj, path, weights):
            paths = []
            last_node = path[-1]

            # reached node of deg 0, so end of path
            if len(adj[last_node]) == 0:
                return [(path, min(weights))]

            # as long as we have not reached end, continue
            for n, weight in adj[last_node]:
                # print("moving from", last_node, " to ", n)
                # print(adj[last_node])
                paths.extend(dfs(adj, path + [n], weights + [weight]))

            return paths

        all_paths = defaultdict(list)
        path_weights = defaultdict(list)
        # reconstruct paths out of adjencency lists for paths
        for c_id in range(len(self.commodities)):
            commodity = self.commodities[c_id]

            n = commodity.source

            # adjacency list for commodity c
            adj = result[c_id]

            # decompose flow into paths
            paths = dfs(adj, [commodity.source], [2 ** 32])
            # remove length 1 paths
            paths = list(filter(lambda p: len(p[0]) != 1, paths))

            all_paths[(commodity.source, commodity.target, c_id)] = []
            path_weights[(commodity.source, commodity.target, c_id)] = []

            for p, weight in paths:
                all_paths[(commodity.source, commodity.target, c_id)].append(p)
                path_weights[(commodity.source, commodity.target, c_id)].append(weight)

        self.paths = {}
        self.paths_weights = {}

        # combine waypointed paths
        for (
            (src, target),
            (waypoint, commodity1, commodity2),
        ) in self.waypoints.items():
            if (src, waypoint, commodity1) not in all_paths:
                print(
                    "WARNING: could not satisfy waypoint {}-- {} -- > {}",
                    src,
                    target,
                    waypoint,
                )
                assert (waypoint, target, commodity2) not in all_paths
                continue

            # the two parts of the waypoints are removed
            # we do not want to use them on their own,
            # only together
            src_wp_paths = all_paths.pop((src, waypoint, commodity1))
            dst_wp_paths = all_paths.pop((waypoint, target, commodity2))

            self.paths[
                (FlowEndpoint.fromString(src), FlowEndpoint.fromString(target))
            ] = [
                (p1[:-1] + p2[2:])[1:-1] for (p1, p2) in zip(src_wp_paths, dst_wp_paths)
            ]

            self.paths_weights[
                (FlowEndpoint.fromString(src), FlowEndpoint.fromString(target))
            ] = min(
                path_weights[(src, waypoint, commodity1)],
                path_weights[(waypoint, target, commodity2)],
            )

        # add non-waypointed paths
        for (src, dst, cid), paths in all_paths.items():
            src_dst_tpl = (FlowEndpoint.fromString(src), FlowEndpoint.fromString(dst))
            self.paths[src_dst_tpl] = [p[1:-1] for p in paths]
            self.paths_weights[src_dst_tpl] = path_weights[src_dst_tpl]

        if verbose:
            print("Paths: ", self.paths)
            print("Total Cost of Transportation = ", value(prob.objective))

        return excess

    def get_paths(self):
        """Returns the paths extracted from the solved LP."""
        return self.paths

    def get_paths_and_weights(self):
        """Returns the paths extracted from the solved LP and the corresponding weights.

        Returns:
            (dict, list(float)): Paths and weights
        """
        return (self.paths, self.paths_weights)

    def print_paths_summary(self):
        """Prints the paths extracted from the solved LP for debugging purposes."""
        for ((src, dst), paths) in self.paths.items():
            if src is None:
                continue
            print(
                "From {}:{} to {}:{} have {} paths".format(
                    src.host, src.port, dst.host, dst.port, len(paths)
                )
            )
            print(paths)
