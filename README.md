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

## Linear Program Formulation
### Mutli-Commodity Flow Problem
We start by defining what a multi-commodity flow (MCF) problem on a directed graph $`G = (V,E)`$ is.

For each edge $`e \in E`$, we have some non-negative capacity $`c(e) = c(u,v)`$.

Furthermore, we have $`k`$ commodities, each of them defined by the 4-tuple $`K_i = (s_i, t_i, d_i, p_i)`$, where $`s_i`$ is the source, $`t_i`$ the sink, $`d_i`$ the demand and $`p_i: E \rightarrow R`$ the commodity's cost function describing the cost of sending some amount of flow over a specific edge. We will denote the actual flow of commodity $`i`$ on edge $`e=(u,v)`$ as $`f_i(u,v)`$.

So intuitively, having a commodity $`K_i`$ requires a flow of $`d_i`$ units from source $`s_i`$ to $`t_i`$, while for every link we need to obey the capacity constraints.

This intuition translates to the following constrained optimization problem to minimize the total cost for all flows:

**Objective:**

```math
\min \sum_{i \in K} \sum_{(u,v) \in E} f_i(u,v) \cdot p_i(u,v)
```
where $`K = \{1, \ldots, k\}`$.

**Constraints:**

1. **Link capacity:**
$`\forall (u,v) \in E: \sum_{i \in K} f_i(u,v) \leq c(u,v)`$

2. **Flow conservation (transit nodes):**
$`\forall i \in K: \sum_{w\in V} f_i(u,w) - \sum_{w \in V} f_i(w,u) = 0 \text{ when } u \neq s_i, t_i`$

3. **Flow conservation (source node)**
$`\forall i \in K: \sum_{w\in V} f_i(s_i,w) - \sum_{w \in V} f_i(w,s_i) = d_i`$

4. **Flow conservation (sink node)**
$`\forall i \in K: \sum_{w\in V} f_i(t_i,w) - \sum_{w \in V} f_i(w,t_i) = -d_i`$


If we constrain our solutions to have a single flow per commodity, i.e., $`f_i: E \rightarrow \{0,d_i\}`$, then the MCF problem is NP-complete. This is referred to as the decision version of the problem. If we allow fractional flows, i.e., $`f_i: E \rightarrow [0,d_i]`$, the constraints of a single commodity might be satisfied by using multiple paths, but the problem can then be solved in polynomial time using linear programming.

### Linear Program (LP)
The above constraints translate in a straightforward manner to a linear program. Simply introduce a variable for each $`f_i(u,v)`$ and allow it to be fractional. Note that for any feasible solution, for all commodities $`i`$ and all edges $`e`$ we have $`f_i(e) = f_i(u,v) \leq d_i`$ by constraint (2, 3 and 4). The intuition here is that if the flow was larger at any point, then it would also have to be larger everywhere in the flow (flow conservation) and thus also at the source and sink where it would violate both constraints 3 and 4.

The number of constraints and variables is in $`O(k\cdot m)`$ where $`m`$ is the number of edges and $`k`$ the number of commodities.

### Excess / Slack
So far, the LP is feasible only if all of the commodities' demands can be satisfied. Since we are also interested in a solution satisfying only a part of our requirements, we introduce slack variables (edges) to our LP (as in [1]).

For every commodity, we add an edge $`(s_i, t_i)`$ with infinite capacity and cost $`p_i(s_i,t_i) = \infty`$. Now our LP is always feasible, but it will only use those excess edges as a last resort due to the huge cost.

[1]: Suri S., Waldvogel M., Warkhede P.R. (2001) Profile-Based Routing: A New Framework for MPLS Traffic Engineering.


### Mapping flows to LPs
We start with the graph $`G`$ as defined in our network topology. The capacity of every edge is given by the bandwidth defined in the toplogy. Let us now show how some TCP flow `shost:sport -> dhost:dport` with demand $`d`$ is represented in our MCF problem:

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

Note that we reduce the bandwidth of the reverse flow by the $`\textit{TCP\_ack\_factor} = 0.5`$ because the acknowledgements require less bandwidth than the transfer flow itself. 

The parameter $`\textit{cost\_multiplier}`$ allows to incentivize solutions which have smaller delays for certain flows. It may make sense to set the cost multiplier to some high value for flows which have associated delay SLAs which we are trying to fulfill.

Note that for UDP flows we do the same exact thing, but without the reverse direction commodity.

### Waypointing
We may directly add waypointing as a further constraint to our LP. Let us assume we want to waypoint some commodity $`(s_i,t_i,d_i,p_i)`$ to route via waypoint $`w`$.

The requirement is simple: every flow in our solution for commodity $`i`$ must go through $`w`$.

For this we split the commodity $`i`$ into two commodities $`j`$ and $`j+1`$:

```math
K_j = (s_i, w, d_i, p_i) \text{ and } K_{j+1} = (w, t_i, d_i, p_i)
```

To prevent a situation where we have a flow from $`s_i`$ to the waypoint $`w`$ but cannot reach $`t_i`$ from there because $`K_{j+1}`$ could not be satisfied, we add a constraint on the excess variables. Excess variables correspond to the flows on the excess edges which were added to guarantee feasibility: $`\textit{excess}_i = f(s_i, t_i)`$.

**Waypointing Constraint**
```math
f_j(s_i, w) = \textit{excess}_j = \textit{excess}_{j+1} = f_{j+1}(w, t_i)
```

This ensures that in every feasible solution if we have a flow of $`x`$ units from $`s_i`$ to $`w`$, we also have a flow of $`x`$ units from $`w`$ to $`t_i`$.

### Fractional Flows
Our solution might return fractional flows. This means for some flow we might have multiple paths, each taking a different fraction of the flow.
We load balance across those paths by selecting one uniformly at random an the ingress switch. This selection is performed at a flowlet granularity for TCP flows and at a packet granularity for UDP flows.

While this might not respect the exact fractional solutions derived in our LP, experimental evidence suggests that this is not a big problem. 

## Additional Traffic Detection

Switches drop all packets for which no explicit paths are installed. This
includes any flows from the additional traffic because they are not known
beforehand.

If detection of additional traffic is enabled, the switch will detect UDP
packets on ports above 60000 and send them to the controller.
The controller then solves an MCF problem on an approximate residual capacity
graph (see section below) using all known additional traffic flows and link failures.
As with the base traffic, solutions are converted into paths and
installed on the switches.

As soon as the paths are installed, the corresponding additional traffic
packets are treated like any other traffic, i.e., the ingress switch adds the
installed MPLS header stack and the packet is forwarded according to these labels.

Any packets arriving in the interval between the controller receiving the
first packet and the new paths being installed are also sent to the controller.
The controller can optionally add the appropriate MPLS headers in the control
plane and send the packet back to the switch such that they are not lost.

### Calculation of Paths

The MCF for all additional traffic flows is solved on an approximation of the
residual graph after subtracting the base-traffic bandwidth demands.
The residual graph is approximated as follows:

* The bandwidth of each base-traffic flow is normalized over the entire 60 seconds time interval.
* A single MCF for all normalized base-traffic flows is solved.
* The bandwidth requirements of all resulting paths are subtracted from the edge capacities in the base graph.

Each detected additional traffic flow is assigned a bandwidth requirement of 10Mbps
(configurable) because the effective rate is not known and could be 10Mbps in
the worst case.

### Deletion of Stale Paths

Since we also don't know when an additional traffic flow ends, we periodically
purge all detected additional flows and their associated table entries in the
switch.

If some additional traffic flow is still active, the switch will send the next packet to the
controller again and the controller will compute new paths.

Having table entries for stale paths is no big deal, but stale flows in
the MCF use up capacity which could otherwise be used for flows that are still active.

### Enabling the feature
In the code version we hand in, additional traffic detection is disabled because we find this to be the more promising option for the leaderboard :-) To enable the feature, you need to do three things:
- In `controller.py`, select at least one of the SLAs for the additional traffic, e.g., `prr_31`.
- In the same file, enable purging (if desired), by setting the parameter `additional_traffic_purge=True`.
- In `switch.p4`, comment out the line `#define DO_ADDITIONAL 0`.

## Selecting SLAs

The user can select a set of SLAs that the controller should try to satisfy.
This is done by including the names of the selected SLAs in the `slas` parameter in `controller.py`.

The controller then includes all base-traffic flows to which a selected SLA applies in its MCF computation.
Note, however, the following limitations of SLA selection:
- The type of the SLA is not considered.
  For example, it does not matter whether it is a flow completion _time_ or flow completion _rate_ SLA.
- The type of the SLA is not considered (except for waypointing).
  For example, it does not matter whether it is a flow completion _time_ or flow completion _rate_ SLA.
  An SLA only determines which flows in the base-traffic are added to the MCF and the MCF will try its best to allocate bandwidth for that flow without any formal guarantees around delay or packet-reception-rate.
- As such, it is not possible to consider SLAs only up to a particular target value.
  For example, including the SLA `prr_26` is equivalent to including any other SLA with the same protocol and port ranges (like `prr_27` or `prr_28`).

## Configurable Parameters

Our controller exposes a multitude of configuration options. While we set sensible defaults, different choices lead to different tradeoffs, which may be preferred depending on the situation.

We give a brief overview of the parameters (and default values) here, with a focus on the tradeoffs. Please also refer to the description of the parameters in `controllers/parameters.py`.

```
p4src/switch.p4:
    FLOWLET_TIMEOUT=48w200000 (microseconds)
        Threshold when a new TCP flowlet starts. Lower value might allow for faster reaction to congestion,
        but also leads to more reordering within TCP flows.
    FAILURE_THRESHOLD=48w500000 (microseconds)
        Threshold after which a link is considered failed if no heartbeats are received. Lower value leads
        to faster detection of failures, but also to a higher false positive rate.
    DO_ADDITIONAL=0 (boolean, 0 or 1)
        Whether detected additional traffic should be reported to the controller.

controllers/controller.py:
    total_time=60 (seconds)
        The total duration of the simulation.
    mcf_interval_size=5 (seconds)
        The size of time intervals for which an MCF problem is solved. Lower value leads to a better
        approximation of the bandwidth demands at a particular point in time, but increases the
        computational cost at the beginning and for link state changes.
    normalize_bw_across_time=False
        Whether flows that are active only during a part of a time interval should be normalized as
        if they spanned the entire interval. Enabling this might lead to less wasted bandwidth, but
        may also increase congestion.
    tcp_default_bw=10 (Mbps)
        The bandwidth demand that is assumed for (size-based) TCP flows. Lower value might allow to
        accommodate more flows, but generally leads to more congestion.
    udp_cost_multiplier=1
        A multiplier for the cost of UDP flows. Higher value prioritizes short paths for UDP flows
        relative to TCP flows.
    tcp_cost_multiplier=1
        Same for TCP flows.
    udp_bw_multiplier=1
        A multiplier for the bandwidth demand of UDP flows. A value >1 means that some spare capacity
        will be allocated for UDP flows, which reduces congestion but might waste bandwidth.
    tcp_bw_multiplier=1
        Same for TCP flows.
    tcp_ack_bw_multiplier=0.5
        Determines the bandwidth demand for the reverse direction of a TCP flow. Lower value saves
        bandwidth but may lead to lost ACKs, which lead to unnecessary retransmissions.
    use_num_hops_cost=False
        Use the hop count instead of delay as the cost measure in the MCF problem. Enabling this generally
        leads to shorter paths in terms of hop count, which reduces the number of switches involved, but
        may increase the length of the path in terms of delay.
    heartbeat_frequency=0.1 (seconds)
        The time interval between heartbeat messages. Lower value (together with a lower value of
        FAILURE_THRESHOLD in switch.py) leads to faster failure detection, but increases the overhead in
        the network.
    tcp_duration_multiplier=1.5
        A multiplier on the estimated duration of (size-based) TCP flows. Note that the same effect could
        be achieved by changing the tcp_default_bw parameter.
    additional_traffic_bw=10 (Mbps)
        The assumed bandwidth demand of additional traffic flows. Lower value wastes less bandwidth for
        small additional traffic flows, but may lead to congestion if the true demand is higher.
    controller_forward_mpls=True
        Whether the controller should add MPLS headers in the control plane and forward the packet to the 
        appropriate output port during the period where there are no paths installed for an additional
        traffic flow. Disabling this decreases the load on the controller, but leads to more packet loss
        for additional traffic flows.
    additional_traffic_purge_interval=5 (seconds)
        The interval at which additional traffic flow paths are purge from the switches. Higher value
        decreases load on both the switches and controller, but leads to more wasted bandwidth.
    additional_traffic_purge=False
        Whether to purge installed additional traffic flows at a regular interval (specified by the
        additional_traffic_purge_interval parameter above).
    slas=[...] (list of strings)
        The names of the SLAs that the controller should try to satisfy (see above).
```
