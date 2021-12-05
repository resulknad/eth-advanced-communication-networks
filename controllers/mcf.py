import json
import pandas as pd
from collections import defaultdict, deque
from pulp import *
from copy import deepcopy
from collections import namedtuple
from edge import Edge

FlowEndpoint = namedtuple("FlowEndpoint", ["host", "port", "protocol"])


class MCF:
    def __init__(self, graph):
        # copy because we will modify graph in here
        self.graph = deepcopy(graph)
        self.commodities = []
        self.paths = {}
        self.waypoints = {}

    def _extend_graph_with_flow_endpoint(self, fe):
        fe_str = self._flow_endpoint_to_string(fe)
        self.graph.add_node(fe_str)
        # add infinite capacity edges from the copies of the node to the actual node
        self.graph.add_undirected_edge(fe_str, fe.host, delay=0, bw=(2 ** 32))
        return fe_str

    def subtract_paths(self, paths, weights):
        for path, weight in zip(paths, weights):
            for (n1, n2) in zip(path, path[1:]):
                e = self.graph.edges_map[str(Edge(n1, n2, 0, 0))]
                if e.bw - weight < 0:
                    print(
                        "WARNING: path has too large of a weight, cannot subtract it. something does not add up",
                        e,
                        weight,
                    )
                e.bw = max(0, e.bw - weight)

    def add_flow(
        self,
        src,
        dst,
        demand,
        allow_dup_commodity=False,
        cost_multiplier=1,
        add_on_conflict=False,
    ):
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

    def _add_commodity(
        self,
        source,
        target,
        demand,
        allow_dup_commodity=False,
        cost_multiplier=1,
        add_on_conflict=False,
    ):
        if not allow_dup_commodity:
            for (indx, (s, t, d, cm)) in enumerate(self.commodities):
                if (s, t) == (source, target):
                    print(
                        "WARNING: already have commodity for ",
                        s,
                        t,
                        ". Will",
                        "add" if add_on_conflict else "take max out of",
                        "the demands",
                        demand,
                        "and",
                        d,
                    )
                    self.commodities[indx] = (
                        s,
                        t,
                        max(d, demand) if not add_on_conflict else d + demand,
                        max(cm, cost_multiplier),
                    )
                    return
        self.commodities.append((source, target, demand, cost_multiplier))
        return len(self.commodities) - 1

    def add_waypoint_to_all(self, source, target, waypoint, protocol):
        wp = FlowEndpoint(host=waypoint, port=1, protocol=protocol)
        wps_to_add = []

        # first we make a list of all flows that match the waypoint
        # this is done in two steps because waypointing changes the commodities
        for (indx, (s, t, d, cm)) in enumerate(self.commodities):
            # parse host:port:protocol
            s_fe = self._get_flow_endpoint(s)
            t_fe = self._get_flow_endpoint(t)
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
        source_str = self._flow_endpoint_to_string(source)
        target_str = self._flow_endpoint_to_string(target)

        if (source_str, target_str) in self.waypoints:
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

        index = list(
            filter(
                lambda tpl: tpl[1][0] == source_str and tpl[1][1] == target_str,
                enumerate(self.commodities),
            )
        )
        if len(index) == 0:
            print(
                "WARNING: cannot add waypoint {} --- {} ----> {} for commodity/flow which has not been added yet. IGNORING.".format(
                    source, waypoint, target
                )
            )
            return
        if len(index) > 1:
            raise Warning(
                "ERROR: cannot have multiple commodities for one src target pair. FAILING"
            )

        (s, t, d, cm) = self.commodities[index[0][0]]
        self.commodities[index[0][0]] = ("", "", 0, 0)
        assert s == self._flow_endpoint_to_string(
            source
        ) and t == self._flow_endpoint_to_string(target)

        commodity1 = self._add_commodity(
            s, self._flow_endpoint_to_string(waypoint), d, True, cost_multiplier=cm
        )
        commodity2 = self._add_commodity(
            self._flow_endpoint_to_string(waypoint), t, d, True, cost_multiplier=cm
        )

        self.waypoints[(source_str, target_str)] = (
            waypoint_str,
            commodity1,
            commodity2,
        )

        # print("waypointed {} to {} via {}".format(source_str, target_str, waypoint_str))

    def make_lp(self):
        prob = LpProblem("Problem", LpMinimize)

        # all_vars_str = list(map("_".join, itertools.product(edges_str, commodities_str)))
        # creating one variable for each edge + commodity combination
        edges_str = list(map(str, self.graph.edges))
        edges_capacity = {str(e): e.bw for e in self.graph.edges}

        nodes_str = list(map(str, self.graph.nodes))

        commodities_str = list(map(str, range(len(self.commodities))))
        variables = LpVariable.dicts("Route", (edges_str, commodities_str), 0)
        cost = {
            edge: {
                commodity: self.graph.edges_map[edge].delay
                * self.commodities[int(commodity)][3]
                for commodity in commodities_str
            }
            for edge in edges_str
        }
        edge_commodity = [(e, c) for e in edges_str for c in commodities_str]

        # add excess edges (as in PBR)
        # this ensure that LP is always feasible
        excess_edges_str = [
            "|".join([c[0], c[1]]) + "_commodity" + str(i)
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
        # + lpSum(
        #      [
        #          (
        #              excess_variables["LON|LIS_commodity0"]
        #              - excess_variables["LON|BER_commodity1"]
        #          )
        #          * (2 ** 32)
        #          for e in excess_edges_str
        #      ]
        # add capacity constaints
        for e in variables:
            prob += (
                lpSum([variables[e][c] for c in commodities_str]) <= edges_capacity[e],
                "%s_capacity" % e,
            )

        # add flow conservation
        # (except for supply / demand nodes)
        for c in range(len(self.commodities)):
            src, target, demand, cm = self.commodities[c]
            if src == "":
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
                if src == name:
                    val = -demand
                    # print(outgoing_excess, incoming_excess)
                elif target == name:
                    val = demand

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
        for (src, target), (_, c1, c2) in self.waypoints.items():
            c1_src, c1_target, _, _ = self.commodities[c1]
            c2_src, c2_target, _, _ = self.commodities[c2]
            prob += (
                excess_variables["{}|{}_commodity{}".format(c1_src, c1_target, c1)]
                == excess_variables["{}|{}_commodity{}".format(c2_src, c2_target, c2)],
                "%s_%s_%s_waypoint" % (c1_src, c1_target, c2_target),
            )
        return prob

    def make_and_solve_lp(self, verbose=False):
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

        paths = collections.defaultdict(list)

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
        for c in range(len(self.commodities)):
            src, dst, _, _ = self.commodities[c]

            n = src

            # adjacency list for commodity c
            adj = result[c]

            # decompose flow into paths
            paths = dfs(adj, [src], [2 ** 32])
            # remove length 1 paths
            paths = list(filter(lambda p: len(p[0]) != 1, paths))

            all_paths[(src, dst, c)] = []
            path_weights[(src, dst, c)] = []

            for p, weight in paths:
                all_paths[(src, dst, c)].append(p)
                path_weights[(src, dst, c)].append(weight)

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
                (self._get_flow_endpoint(src), self._get_flow_endpoint(target))
            ] = [
                (p1[:-1] + p2[2:])[1:-1] for (p1, p2) in zip(src_wp_paths, dst_wp_paths)
            ]

            self.paths_weights[
                (self._get_flow_endpoint(src), self._get_flow_endpoint(target))
            ] = min(
                path_weights[(src, waypoint, commodity1)],
                path_weights[(waypoint, target, commodity2)],
            )

        # add non-waypointed paths
        for (src, dst, cid), paths in all_paths.items():
            src_dst_tpl = (self._get_flow_endpoint(src), self._get_flow_endpoint(dst))
            self.paths[src_dst_tpl] = [p[1:-1] for p in paths]
            self.paths_weights[src_dst_tpl] = path_weights[src_dst_tpl]

        if verbose:
            print("Paths: ", self.paths)
            print("Total Cost of Transportation = ", value(prob.objective))

        return excess

    def _get_flow_endpoint(self, name):
        np = name.split(":")
        return (
            FlowEndpoint(name, 0, "")
            if len(np) == 1
            else FlowEndpoint(np[0], int(np[1]), np[2])
        )

    def _flow_endpoint_to_string(self, fe):
        return "{}:{}:{}".format(fe.host, fe.port, fe.protocol)

    def get_paths(self):
        return self.paths

    def get_paths_and_weights(self):
        return (self.paths, self.paths_weights)

    def print_paths_summary(self):
        for ((src, dst), paths) in self.paths.items():
            if src.host == "":
                continue
            print(
                "From {}:{} to {}:{} have {} paths".format(
                    src.host, src.port, dst.host, dst.port, len(paths)
                )
            )
            print(paths)
