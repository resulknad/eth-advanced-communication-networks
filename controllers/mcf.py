import json
import pandas as pd
from collections import defaultdict
from pulp import *
import collections
class MCF:
    def __init__(self, graph):
        self.graph = graph
        self.commodities = []
        self.paths = []

    def add_commodity(self, source, target, demand):
        for (indx,(s,t,d)) in enumerate(self.commodities):
            if (s,t) == (source,target):
                print("WARNING: already have commodity for ",s,t, ". Will use max demand out of ",demand,d)
                self.commodities[indx] = (s,t,max(d,demand))
                return
        self.commodities.append((source, target, demand))

    def make_lp(self):
        prob = LpProblem("Problem",LpMinimize)

        
        #all_vars_str = list(map("_".join, itertools.product(edges_str, commodities_str)))
        # creating one variable for each edge + commodity combination
        edges_str = list(map(str, self.graph.edges))
        edges_capacity = {str(e): e.bw for e in self.graph.edges}
        
        # add excess edges (as in PBR)
        # this ensure that LP is always feasible
        edges_str += ["|".join([c[0], c[1]]) for c in self.commodities]
        edges_capacity.update({"|".join([c[0], c[1]]): 2**16 for c in self.commodities})

        nodes_str = list(map(str, self.graph.nodes))

        commodities_str = list(map(str, range(len(self.commodities))))
        variables = LpVariable.dicts("Route",(edges_str, commodities_str),0)
        cost = {edge: {commodity: 1 for commodity in commodities_str} for edge in edges_str}
        edge_commodity = [(e,c) for e in edges_str for c in commodities_str]

        # add high cost for excess links
        for i in range(len(self.commodities)):
            c = self.commodities[i]
            excess_link = "|".join([c[0], c[1]])
            for j in range(len(self.commodities)):
                cost[excess_link][str(j)] = 2**32
            print(excess_link, i)


 
        # objective: minimize cost over chosen capacity flows
        # minimize edge cost (number of hops basically)
        prob += lpSum([variables[e][c]*cost[e][c] for (e,c) in edge_commodity]), \
                "Sum_of_edge_commodity_cost"
        
        # add capacity constaints
        # if edge is bidirectional, capacity must hold for both
        for (n1,n2) in itertools.combinations(nodes_str, 2):
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
                prob += lpSum(terms)<=capacity, "%s_capacity"%e

        # make sure all variables are positive
        for e in edges_str:
            for c in commodities_str:
                prob += variables[e][c]>=0, "%s_%s_posiitve"%(e,c)

        # add flow conservation
        # (except for supply / demand nodes)
        for c in range(len(self.commodities)):
            src, target, demand = self.commodities[c]
            for (name, node) in self.graph.nodes.items():
                outgoing = list(filter(lambda s: s.startswith(name + "|"), edges_str))
                incoming = list(filter(lambda s: s.endswith("|" + name), edges_str))

                val = 0
                if src == name:
                    val = -demand
                elif target == name:
                    val = demand
                    
                prob += lpSum([variables[e][str(c)] for e in incoming]) - lpSum([variables[e][str(c)] for e in outgoing]) \
                                == val, "%s_%s_conservation"%(node.name, c)
                "%s_%s_conservation_ga"%(node.name, c)
        return prob

    def make_and_solve_lp(self, verbose=False):
        prob = self.make_lp()
        prob.solve(PULP_CBC_CMD(msg=0))

        if verbose:
            print("Status:", LpStatus[prob.status])

        # construct paths out of LP result
        result = [{} for _ in self.commodities]
        for v in prob.variables():
            if v.varValue != 0.0:
                if v.name.startswith("Route_"):
                    edge_name = v.name[6:]
                    from_to, commodity = edge_name[:edge_name.rindex("_")], edge_name[edge_name.rindex("_")+1:]
                    nodes = from_to.split("|")
                    src,dst = nodes[0],nodes[1]
                    result[int(commodity)][src] = dst
                if verbose:
                    print("edge from",src,"to",dst,"commodity",commodity)
                    print (v.name, "=", v.varValue)

        paths = collections.defaultdict(list)

        # reconstruct paths out of adjencency lists for paths
        for c in range(len(self.commodities)):
            src,dst,_ = self.commodities[c]

            n = src
            path = []
            # as long as we have not reached end, continue
            while n in result[c]:
                path.append(n)
                n = result[c][n]
            
            path.append(n)
            
            if len(path) > 2:
                src,dst = path[0],path[-1]
                paths[(src,dst)].append(path)
                # add reverse path
                paths[(dst,src)].append(path[::-1])
            else:
               print("WARNING: found path of length <=2, something is wrong with LP solution", path)

        self.paths = paths

        if verbose:
            print("Paths: ", self.paths)
            print ("Total Cost of Transportation = ", value(prob.objective))

    def get_paths(self):
        return self.paths