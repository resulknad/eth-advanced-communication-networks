import unittest

from graph import Graph
from mcf import MCF, FlowEndpoint


class MCFTestCase(unittest.TestCase):
    def setUp(self):
        self.graph = Graph("testdata/topology.json")

    def test_split_flow_for_max_bw(self):

        # setup LP with 3x max bw requirements
        # expect three distinct paths s.t. we can actually send 3x max bw
        mcf = MCF(self.graph)
        LIS = FlowEndpoint("LIS", 1, "tcp")
        BER = FlowEndpoint("BER", 1, "tcp")
        mcf.add_flow(LIS, BER, 30)
        mcf.make_and_solve_lp()

        paths = mcf.get_paths()
        lb_paths = paths[(LIS, BER)]

        self.assertEqual(len(lb_paths), 3)
        self.assertEqual(
            sorted(lb_paths, key=lambda l: len(l)),
            [
                ["LIS", "BER"],
                ["LIS", "LON", "AMS", "FRA", "BER"],
                ["LIS", "POR", "MAD", "BAR", "MUN", "BER"],
            ],
        )

        # no reverse paths
        self.assertNotIn(("BER", "LIS"), paths)

    def test_infeasible(self):
        # setup LP with infeasible constraints
        # expect that the longer of the two (more expensive one)
        # is dropped completly
        mcf = MCF(self.graph)
        LIL = FlowEndpoint("LIL_h0", 1, "tcp")
        REN = FlowEndpoint("REN_h0", 1, "tcp")
        REN_2 = FlowEndpoint("REN_h0", 2, "tcp")
        PAR = FlowEndpoint("PAR_h0", 1, "tcp")

        mcf.add_flow(LIL, REN, 10)
        mcf.add_flow(PAR, REN_2, 10)

        mcf.make_and_solve_lp()

        paths = mcf.get_paths()
        # 2 hops, dropped
        self.assertEqual(len(paths[(LIL, REN)]), 0)

        # this one exists
        self.assertEqual(len(paths[(PAR, REN_2)]), 1)

        # but not its reverse
        self.assertNotIn((REN_2, PAR), paths)

    def test_waypointing(self):
        # setup LP with waypoint constraint which is definitively
        # not part of the shortest path (a bit of a detour)

        LIS = FlowEndpoint("LIS_h0", 1, "tcp")
        BER = FlowEndpoint("BER_h0", 2, "tcp")
        MAN = FlowEndpoint("MAN", 3, "tcp")

        # first check that without waypoint we dont go via MAN
        mcf = MCF(self.graph)
        mcf.add_flow(LIS, BER, 5)
        mcf.make_and_solve_lp()

        paths = mcf.get_paths()
        # print(paths)
        self.assertNotIn("MAN", paths[(LIS, BER)][0])

        # now we add the waypoint and the path should contain MAN
        mcf = MCF(self.graph)
        mcf.add_flow(LIS, BER, 5)
        mcf.add_waypoint_to_flow(LIS, BER, MAN)
        mcf.make_and_solve_lp()
        paths = mcf.get_paths()

        self.assertIn("MAN", paths[(LIS, BER)][0])

    def test_waypointing_with_simple_paths(self):
        # test whether waypointing works if:
        # commodity1 with waypoint: LIS -- LON --> BER
        # commodity2 w/o  waypointL LIS -> LON

        # now we add the waypoint and the path should contain MAN
        mcf = MCF(self.graph)
        LIS = FlowEndpoint("LIS_h0", 1, "tcp")
        BER = FlowEndpoint("BER_h0", 2, "tcp")
        LON = FlowEndpoint("LON_h0", 3, "tcp")

        LIS_2 = FlowEndpoint("LIS_h0", 4, "tcp")
        LON_2 = FlowEndpoint("LON_h0", 5, "tcp")

        mcf.add_flow(LIS, BER, 10, cost_multiplier=100)
        mcf.add_flow(LIS_2, LON_2, 10)

        mcf.add_waypoint_to_flow(LIS, BER, LON)

        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertIn("LON", paths[(LIS, BER)][0])

        # this one needs to take a detour since link LIS -> LONDON is saturated...
        self.assertEqual(
            paths[(LIS_2, LON_2)],
            [["LIS_h0", "LIS", "POR", "MAD", "LON", "LON_h0"]],
        )

    def test_full_duplex(self):
        # links support in both directions 10Mbits
        # so we need to model it as such
        LIS = FlowEndpoint("LIS", 1, "tcp")
        LON = FlowEndpoint("LON", 2, "tcp")
        mcf = MCF(self.graph)

        mcf.add_flow(LIS, LON, 10)
        mcf.add_flow(LON, LIS, 10)

        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertEqual(paths[(LIS, LON)], [["LIS", "LON"]])
        self.assertEqual(paths[(LON, LIS)], [["LON", "LIS"]])

    def test_cost_multiplier(self):
        # example constructed s.t. it is cheaper for the LP
        # to take a detour for LIS -> LON without modifying the cost multiplier
        mcf = MCF(self.graph)
        POR = FlowEndpoint("POR", 1, "tcp")
        LON = FlowEndpoint("LON", 1, "tcp")
        LON_2 = FlowEndpoint("LON", 2, "tcp")
        LON_3 = FlowEndpoint("LON", 3, "tcp")
        BRI = FlowEndpoint("BRI", 1, "tcp")
        MAD = FlowEndpoint("MAD", 1, "tcp")
        LIS = FlowEndpoint("LIS", 1, "tcp")
        LIS_2 = FlowEndpoint("LIS", 2, "tcp")

        mcf.add_flow(POR, LON, 10)
        mcf.add_flow(LIS, BRI, 10)
        mcf.add_flow(MAD, LON_2, 10)
        mcf.add_flow(LIS_2, LON_3, 10, cost_multiplier=0)

        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertNotEqual(paths[(LIS_2, LON_3)], [["LIS", "LON"]])

        # now with cost multiplier
        # this forces the LP to choose the shortest path for this commodity
        # because its cheaper to extend the others
        mcf = MCF(self.graph)
        mcf.add_flow(POR, LON, 10)
        mcf.add_flow(LIS, BRI, 10)
        mcf.add_flow(MAD, LON_2, 10)
        mcf.add_flow(LIS_2, LON_3, 10, cost_multiplier=10)

        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertEqual(paths[(LIS_2, LON_3)], [["LIS", "LON"]])


if __name__ == "__main__":
    unittest.main()
