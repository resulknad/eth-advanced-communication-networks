## Group info

| Group name | 05_Dijkstra |  |  |
| --- | --- | --- | --- |
| Member 1 | Lukas Heimes | heimesl | heimesl@student.ethz.ch |
| Member 2 | Dan Kluser | dkluser | dkluser@student.ethz.ch |
| Member 3 | Patrick Ziegler | zieglerp | zieglerp@student.ethz.ch |

## Overview

We use a centralized controller that computes paths through a series of **multi-commodity flow (MCF)** problems.
The user selects a subset of the SLAs, which give rise to a set of (base traffic) flows that must be considered.
The simulation is divided into fixed-size intervals of a few seconds length.
For each interval, the controller constructs an MCF problem consisting of the relevant base traffic flows.
This global view allows us to approximate an optimal solution.
The MCF problems are solved by means of Linear Programming, and the solutions are then converted into paths and installed on the switches.

In the forwarding plane, paths are added to the packets at the ingress switches in the form of an **MPLS header stack**.
Forwarding is based on these labels, except for the last hop, which is IPv4 based.
Packets that do not belong to an installed path are dropped at the ingress switch.

The above approach is complemented by the following techniques:
- **Failure detection**: Link state changes are detected using heartbeats and trigger a recomputation of the MCF solution.
- **Additional Traffic**: If enabled, the switches detect additional traffic and forward it to the controller, which can then decide to install an appropriate path on the switch if the residual graph has sufficient capacity.
- **Load balancing**: When the MCF solution distributes a flow among multiple paths, the ingress switch chooses a path uniformly at random at flowlet granularity. For UDP, every packet is considered its own flowlet.

## Individual Contributions

In this section, note down 1 or 2 sentences *per team member* outlining everyone's contribution to the project. We want to see that everybody contributed, but you don't need to get into fine details. For example, write who contributed to which feature of your solution, but do *not* write who implemented a particular function. 

### Lukas Heimes

Contribution(s) of <Full name 1>

### Dan Kluser

Contribution(s) of <Full name 2>

### Patrick Ziegler

Contribution(s) of <Full name 3>

## Additional Information

### Linear Program Formulation

### Configurable Parameters

### Source Files
