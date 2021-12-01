import json
import pandas as pd
from collections import defaultdict, deque
from pulp import *


class MCF:
    def __init__(self, graph):
        self.graph = graph
        self.commodities = []
        self.paths = []

    def add_commodity(self, source, target, demand):
        # flow is independent of order
        if source < target:
            source, target = target, source
        for (indx, (s, t, d)) in enumerate(self.commodities):
            if (s, t) == (source, target):
                print(
                    "WARNING: already have commodity for ",
                    s,
                    t,
                    ". Will add requested demand to it ",
                    demand,
                    d + demand,
                )
                self.commodities[indx] = (s, t, d + demand)
                return
        self.commodities.append((source, target, demand))

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

        # add capacity constaints
        # if edge is bidirectional, capacity must hold for both
        for (n1, n2) in itertools.combinations(nodes_str, 2):
            e = n1 + "|" + n2
            reverse_e = n2 + "|" + n1

            terms = []
            if e in variables:
                terms += [variables[e][c] for c in commodities_str]
            if reverse_e in variables:
                terms += [variables[reverse_e][c] for c in commodities_str]

            if len(terms) > 0:
                e = e if e in variables else reverse_e
                capacity = edges_capacity[e]
                prob += lpSum(terms) <= capacity, "%s_capacity" % e

        # add flow conservation
        # (except for supply / demand nodes)
        for c in range(len(self.commodities)):
            src, target, demand = self.commodities[c]
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
                "%s_%s_conservation_ga" % (node.name, c)
        return prob

    def make_and_solve_lp(self, verbose=False):
        prob = self.make_lp()
        prob.writeLP("test.lp")
        prob.solve(PULP_CBC_CMD(msg=0))

        if verbose:
            print("Status:", LpStatus[prob.status])

        # construct paths out of LP result
        result = [defaultdict(list) for _ in self.commodities]
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
                    result[int(commodity)][src].append(dst)
                    if verbose:
                        print("edge from", src, "to", dst, "commodity", commodity)
                if verbose:
                    print(v.name, "=", v.varValue)

        paths = collections.defaultdict(list)

        # this is almost dfs, but it will visit some nodes twice
        # if they are shared on a path. graph is assumed to be a DAG
        # which should really be ok if the LP did not go horribly wrong
        def dfs(adj, path):
            paths = []
            last_node = path[-1]

            # reached node of deg 0, so end of path
            if len(adj[last_node]) == 0:
                return [path]

            # as long as we have not reached end, continue
            for n in adj[last_node]:
                # print("moving from", last_node, " to ", n)
                # print(adj[last_node])
                paths.extend(dfs(adj, path + [n]))

            return paths

        all_paths = defaultdict(list)
        # reconstruct paths out of adjencency lists for paths
        for c in range(len(self.commodities)):
            src, dst, _ = self.commodities[c]

            n = src

            # adjacency list for commodity c
            adj = result[c]

            # decompose flow into paths
            paths = dfs(adj, [src])

            # remove length 1 paths
            paths = list(filter(lambda p: len(p) != 1, paths))

            for p in paths:
                # print(adj["EIN_h0"])
                # print(adj["AMS_h0"])
                # print("commodity: ", c)
                assert p[0] == src and p[-1] == dst

            # and reverse paths
            paths_reversed = [p[::-1] for p in paths]

            all_paths[(src, dst)] = paths
            all_paths[(dst, src)] = paths_reversed
        self.paths = all_paths

        if verbose:
            print("Paths: ", self.paths)
            print("Total Cost of Transportation = ", value(prob.objective))

    def get_paths(self):
        return self.paths

    def print_paths_summary(self):
        for ((src, dst), paths) in self.paths.items():
            print("From {} to {} have {} paths".format(src, dst, len(paths)))
            print(paths)
