import json
import pandas as pd
from collections import defaultdict
class Node:

    def __init__(self, name, obj):
        self.edges = []
        self.edges_map = {}
        self.name = name
        self.obj = obj

    def add_edge(self, e):
        self.edges.append(e)

        other = e.target if e.source == self.name else e.source
        self.edges_map[other] = e

class Edge:
    target = ""
    source = ""
    delay = ""
    bw = ""
    def __init__(self, source, target, delay, bw):
        self.source = source
        self.target = target
        self.delay = delay
        self.bw = bw

    def __repr__(self):
        return self.source + "|" + self.target

class Graph:
    edges = []
    nodes = {}
    def __init__(self, top_file):
        self.edges = []
        self.edges_map = {}
        self.nodes = {}
        self._read_json(top_file)


    def _read_json(self, top_file):
        with open(top_file) as json_file:
            data = json.load(json_file)
            for n in data['nodes']:
                name = n['id']
                self.nodes[name] = Node(name, n)
            
            for l in data['links']:
                #print(l)
                source = l['node1']
                target = l['node2']
                delay = l.get('delay')
                bw = l['bw'] if 'bw' in l else 100

                e = Edge(source, target, delay, bw)
                self.nodes[source].add_edge(e)
                self.nodes[target].add_edge(e)
                self.edges.append(e)
                self.edges_map[str(e)] = e

                # add reverse edge
                e = Edge(target, source, delay, bw)
                self.nodes[source].add_edge(e)
                self.nodes[target].add_edge(e)
                self.edges.append(e)
                self.edges_map[str(e)] = e

from pulp import *

class MCF:
    def __init__(self, graph):
        self.graph = graph
        self.commodities = []

    def add_commodity(self, source, target, demand):
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

    def make_and_solve_lp(self):
        prob = self.make_lp()

        # prob.writeLP("MCF.lp")
        prob.solve(PULP_CBC_CMD(msg=0))

        # The status of the solution is printed to the screen
        print("Status:", LpStatus[prob.status])

        # Each of the variables is printed with it's resolved optimum value
        for v in prob.variables():
            if v.varValue != 0.0:
                print (v.name, "=", v.varValue)

        # The optimised objective function value is printed to the screen    
        print ("Total Cost of Transportation = ", value(prob.objective))

# read topology
g = Graph("topology.json")

# read base traffic
df = pd.read_csv("full.traffic-base")
df = df.rename(columns=lambda x: x.strip())

curr_time = 0

# map flows defined in terms of size to bandwidth + time pairs
default_bw = 2.5
rows = df[pd.isna(df['rate'])]
for i,r in rows.iterrows():
    # TODO: parse megabytes and Mbps etc.
    size = int(r['size'][:-2])

    rate = default_bw
    df.loc[i, 'rate'] = str(rate) + "Mbps"
    df.loc[i,'duration'] = size / rate

# add end_time everywhere
df['end_time'] = df['start_time'] + df['duration']

# find points in time where either 1. a flow starts or 2. a flow end
intervals = list(set(list(df['end_time']) + list(df['start_time'])))

# append scenario end time
intervals.append(60)

# sort
intervals = sorted(intervals)

start_time = 0
for end_time in intervals:
    flows = df[(df['start_time']<=start_time) &
                (df['end_time'] >= end_time)]

    print("Have {} flows from {} to {}".format(flows.shape[0], start_time, end_time))
    m = MCF(g)
    for (i,f) in flows.iterrows():
        #TOOD: properly parse Mbps for rate
        m.add_commodity(f['src'], f['dst'], float(f['rate'][:-4]))
    print(m.commodities)
    m.make_and_solve_lp()
    start_time = end_time




import sys
sys.exit(1)