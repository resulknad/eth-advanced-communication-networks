# Mandatory Information

## Group info

| Group name | 05_Dijkstra     |          |                          |
| ---------- | --------------- | -------- | ------------------------ |
| Member 1   | Lukas Heimes    | heimesl  | heimesl@student.ethz.ch  |
| Member 2   | Dan Kluser      | dkluser  | dkluser@student.ethz.ch  |
| Member 3   | Patrick Ziegler | zieglerp | zieglerp@student.ethz.ch |

## Overview

We use a centralized controller that computes paths through a series of **multi-commodity flow (MCF)** problems.
The user selects a subset of the SLAs, which give rise to a set of (base traffic) flows that must be considered.
The simulation is divided into fixed-size intervals of a few seconds length.
For each interval, the controller constructs an MCF problem consisting of the relevant base traffic flows.
This global view allows us to approximate an optimal solution.
The MCF problems are solved by means of Linear Programming (LP), the solutions are then converted into paths and installed on the switches.

In the forwarding plane, paths are added to the packets at the ingress switches in the form of an **MPLS header stack**.
Forwarding is based on these labels, except for the last hop, which is IPv4 based.
Packets that do not belong to an installed path are dropped at the ingress switch.

The above approach is complemented by the following techniques:
- **Failure detection**: Link state changes are detected using heartbeats and trigger a recomputation of the MCF solution.
- **Additional Traffic**: If enabled, the switches detect additional traffic and forward it to the controller, which can then decide to install an appropriate path on the switch if the residual graph has sufficient capacity.
- **Load balancing**: When the MCF solution distributes a flow among multiple paths, the ingress switch chooses a path uniformly at random at flowlet (TCP) or packet (UDP) granularity.

## Individual Contributions

### Lukas Heimes

Implemented failure detection/handling and flowlet-like load balancing. Contributed to the MCF approach and detected numerous bugs through careful code reviews.

### Dan Kluser

Devised the MCF approach, formulated the Linear Program and implemented the interval handling. Really, the heart of our solution.

### Patrick Ziegler

Implemented MPLS forwarding as well as the detection and integration of additional traffic flows. Refactored the controller for modularity and extensibility.

# Additional Information

## Linear Program Formulation
### Mutli-Commodity Flow Problem
We start by defining what a multi commodity flow problem on a directed graph $`G = (V,E)`$ is.

For each edge $`e \in E`$ we have some non-negative capacity $`c(e) = c(u,v)`$.

Furthermore we have $`k`$ commodities, each of them defined by the 4-tuple $`K_i = (s_i, t_i, d_i, p_i)`$ where $`s_i`$ is the source, $`t_i`$ the sink, $`d_i`$ the demand and $`p_i: E \rightarrow R`$ the Commodity's cost function describing the cost of sending some amount of flow over a specific edge. We will denote the actual flow of commodity $`i`$ on edge $`e=(u,v)`$ as $`f_i(u,v)`$.

So intuitively, having a commodity $`K_i`$ requires a flow of $`d_i`$ units from source $`s_i`$ to $`t_i`$, while for every link we need to obey the capacity constraints.

This intuiton translates to the following constrained optimization problem to minimize the total cost for all flows:

**Objective:**

```math
\min \sum_{i \in K} \sum_{(u,v) \in E} f_i(u,v) \cdot p_i(u,v)
```

**Constraints:**

1. **Link capacity:**
$`\forall (u,v) \in E: \left(\sum_{i}^k f_i(u,v)\right) \leq c(u,v)`$

2. **Flow conservation (transit nodes):**
$`\forall i \in K: \sum_{w\in V} f_i(u,w) - \sum_{w \in V} f_i(w,u) = 0 \text{ when } u \neq s_i, t_i`$

3. **Flow conservation (source node)**
$`\forall i \in K: \sum_{w\in V} f_i(s_i,w) - \sum_{w \in V} f_i(w,s_i) = 1`$

4. **Flow conservation (sink node)**
$`\forall i \in K: \sum_{w\in V} f_i(t_i,w) - \sum_{w \in V} f_i(w,t_i) = -1`$


If we require integer flows, so $`f_i: E \rightarrow N`$, then the MCF problem is NP-complete. For fractional flows, which means that the constraints of a single commodity might be satisfied by using multiple paths, the problem can be solve in polynomial time using linear programming.

### Linear Program
The above constraints transfer in a straightforward manner to a linear program. Simply introduce a variable for each $`f_i(u,v)`$ and allow it to be fractional.

The number of constraints and variables is in $`O(k\cdot m)`$ where $`m`$ is the number of edges and $`k`$ the number of commodities.

### Excess / Slack
Right now the LP is feasible only if all of the commodities demands can be satisfied. Since we are also interested in a solution satisfying only a part of our requirements, we introduce slack variables (edges) to our LP (as in [1]).

For every commodity we add an edge $`(s_i, t_i)`$, with cost $`p_i(s_i,t_i) = \infty`$. Now our LP is always feasible, but it will only use those excess edges as a last ressort due to the huge cost.

[1]: Suri S., Waldvogel M., Warkhede P.R. (2001) Profile-Based Routing: A New Framework for MPLS Traffic Engineering.


### Mapping flows to LPs
We start with the graph $`G`$ as defined in our network topology. The capacity of every edge is given by the bandwidth defined in the toplogy. Let us now show how some TCP flow `shost:sport -> dhost:dport` with demand $`d`$ is represented in our MCF:

For both flow endpoints (`shost:sport:TCP`) and (`dhost:dport:TCP`), we add a new node to our graph, each connected to the respective host node (`shost`) and (`dhost`) with infinite capacity and zero cost edges.

We then need two commodities:

```math
s_i = \text{shost:sport:TCP} \\
t_i = \text{dhost:dport:TCP} \\
d_i = d \\
p_i(u,v) = \textit{cost\_multiplier} \cdot \textit{delay(u,v)}
```

and

```math
s_{i+1} = \text{dhost:dport:TCP}\\
t_{i+1} = \text{shost:sport:TCP}\\
d_{i+1} = d\cdot \textit{TCP\_ack\_factor}\\
p_{i+1}(u,v) = \textit{cost\_multiplier} \cdot \textit{delay(u,v)}
```

Where we reduce the reverse flows bandwidth by the $`\textit{TCP\_ack\_factor} = 0.5`$ because most of our transfer is nothing but acks in one direction of the flow. 

The parameter $`\textit{cost\_multiplier}`$ allows to incentivize solutions which have smaller delays for certain flows. It may make sense to set the cost multiplier to some high value for flows which have associated delay SLAS which we are trying to fulfill.

Note that for UDP flows we do the same exact thing, but without the reverse channel commodity.

### Waypointing
We may directly add the waypointing as a further constraint to our LP. Let us asusme we want to waypoint some commodity $`(s_i,t_i,d_i,p_i)`$ to route via waypoint $`w`$.

The requirement is simple: every flow in our soluton for commodity $`i`$ must go through $`w`$.

For this we split the commodity $`i`$ in two commodities $`j`$ and $`j+1`$:

```math
K_j = (s_i, w, d_i, p_i) \text{ and } K_{j+1} = (w, t_i, d_i, p_i)
```

to prevent a situation where we have a flow from $`s_i`$ to the waypoint $`w`$ but cannot reach $`t_i`$ from there because $`K_{j+1}`$ could not be satisfied, we add a constraint on the excess variables:

```math
\textit{excess}_j = \textit{excess}_{j+1}
```

This ensures that in every feasible solution if we have a flow of $`x`$ units from $`s_i`$ to $`w`$, we also have a flow of $`x`$ units from $`w`$ to $`t_i`$.

### Fractional Flows
Our solution does return fractional flows. This means for some flow we have multiple paths each taking a different fraction of the flow.
We load balance across those paths using flowlet switching, or ECMP in the UDP case.

This might not respect the exact fractional solutions derived in our LP because paths are selected uniformly at random.
Experimental evidence suggests that this is not a problem. 

## Additional Traffic Detection

Switches will drop any packets for which no explicit path is installed, this
includes any flows from the additional traffic because they are not known
beforehand.

If detection of additional traffic is enabled, the switch will detect UDP
packets on ports above 60000 and send them to the controller.
The controller then solves an MCF problem on the residual capacity graph using
all known additional traffic flows and link failures.
The same as with the base traffic, solutions are converted into paths and
installed on the switches.

As soon as the paths are installed, the corresponding additional traffic
packets are treated as regular traffic and forwarded according to the installed
MPLS headers.

Any packets arriving in the interval between the controller receiving the
first packet and the new paths being installed are also sent to the controller.
The controller can additionally directly forward them using the appropriate
MPLS headers so that they don't get lost.

### Calculation of Paths

The MCF for all additional traffic flows is solved on an approximation of the
residual graph after subtracting the base-traffic bandwidth demands.
The residual graph is approximated as follows:

* The bandwidth of each base-traffic flow is normalized over the entire 60 seconds time interval.
* A single MCF for all normalized base-traffic flows is solved
* The bandwidth requirements of all resulting paths are subtracted from the edge capacities in the base graph.

Each detected additional traffic is assigned a bandwidth requirement of 10Mbps
(configurable) because the effective rate is not known and could be 10Mbps in
the worst case.

### Deletion of Stale Paths

Since we also don't know when an additional traffic flow ends, we periodically
purge all detected additional flows and their associated table entries in the
switch.

If some traffic is still active, the switch will again send it to the
controller and the controller will compute new paths.

Having table entries for stale paths isn't a big deal, however stale flows in
the MCF use up capacity and make it more difficult to solve, which could
disadvantage still active flows.

## Configurable Parameters

TODO

### Selecting SLAs

TODO

## Source Files

```
.
|-- controllers
|   |-- parameters.py           // Definition of configurable parameters
|   |-- controller.py           // Main file for the centralized controller
|   |-- flow_manager.py         // Computes paths using mcf.py, used by controller.py
|   |-- table_manager.py        // Installs paths on the switches, used by controller.py
|   |-- heartbeat_generator.py  // Generates heartbeats for failure detection; copied from Ex. 7
|   |-- mcf.py                  // Encodes the MCF problem as a LP, solves it and transforms it to paths
|   |-- commodity.py            // Class definition for a commodity, used by mcf.py
|   |-- flow_endpoint.py        // Class definition for a flow endpoint, used by mcf.py
|   |-- flow.py                 // Class definition for a flow in the network
|   |-- graph.py                // Data structure for representing a network graph
|   |-- edge.py                 // Edge class used in graph.py
|   |-- node.py                 // Node class used in graph.py
|   `-- test_mcf.py             // Testcases for mcf.py
|-- p4src
|   |-- include
|   |   |-- headers.p4          // Packet headers, metadata, and constant definitions
|   |   `-- parsers.p4          // Parser and deparser for supported headers
|   `-- switch.p4               // Main dataplane file, used by all switches
`-- README.md
```
