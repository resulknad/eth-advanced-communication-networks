import unittest

from graph import Graph
from mcf import MCF


class MCFTestCase(unittest.TestCase):
    def setUp(self):
        self.graph = Graph("testdata/topology.json")

    def test_split_flow_for_max_bw(self):

        # setup LP with 3x max bw requirements
        # expect three distinct paths s.t. we can actually send 3x max bw
        mcf = MCF(self.graph)
        mcf.add_commodity("LIS", "BER", 30)
        mcf.make_and_solve_lp()

        paths = mcf.get_paths()
        lb_paths = paths[("LIS", "BER")]

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
        mcf.add_commodity("LIL", "REN", 10)
        mcf.add_commodity("PAR", "REN", 10)

        mcf.make_and_solve_lp()

        paths = mcf.get_paths()
        # 2 hops, dropped
        self.assertEqual(len(paths[("LIL", "REN")]), 0)

        # this one exists
        self.assertEqual(len(paths[("PAR", "REN")]), 1)

        # but not its reverse
        self.assertNotIn(("REN", "PAR"), paths)

    def test_waypointing(self):
        # setup LP with waypoint constraint which is definitively
        # not part of the shortest path (a bit of a detour)

        # first check that without waypoint we dont go via MAN
        mcf = MCF(self.graph)
        mcf.add_commodity("LIS", "BER", 5)
        mcf.make_and_solve_lp()

        paths = mcf.get_paths()
        # print(paths)
        self.assertNotIn("MAN", paths[("LIS", "BER")][0])

        # now we add the waypoint and the path should contain MAN
        mcf = MCF(self.graph)
        mcf.add_commodity("LIS", "BER", 10)
        # mcf.add_commodity("LON", "BER", 10)
        mcf.add_waypoint("LIS", "BER", "MAN")
        mcf.make_and_solve_lp()
        paths = mcf.get_paths()

        self.assertIn("MAN", paths[("LIS", "BER")][0])

    def test_waypointing_with_simple_paths(self):
        # test whether waypointing works if:
        # commodity1 with waypoint: LIS -- LON --> BER
        # commodity2 w/o  waypointL LIS -> LON

        # now we add the waypoint and the path should contain MAN
        mcf = MCF(self.graph)

        mcf.add_commodity("LIS", "BER", 10)
        mcf.add_commodity("LIS", "LON", 10)

        mcf.add_waypoint("LIS", "BER", "LON")
        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertIn("LON", paths[("LIS", "BER")][0])

        # this one needs to take a detour since link LIS -> LONDON is saturated...
        self.assertEqual(paths[("LIS", "LON")], [["LIS", "POR", "MAD", "LON"]])

    def test_full_duplex(self):
        # links support in both directions 10Mbits
        # so we need to model it as such

        mcf = MCF(self.graph)
        mcf.add_commodity("LIS", "LON", 10)
        mcf.add_commodity("LON", "LIS", 10)
        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertEqual(paths[("LIS", "LON")], [["LIS", "LON"]])
        self.assertEqual(paths[("LON", "LIS")], [["LON", "LIS"]])

    def test_cost_multiplier(self):
        # example constructed s.t. it is cheaper for the LP
        # to take a detour for LIS -> LON without modifying the cost multiplier
        mcf = MCF(self.graph)
        mcf.add_commodity("POR", "LON", 10)
        mcf.add_commodity("LIS", "BRI", 10)
        mcf.add_commodity("MAD", "LON", 10)
        mcf.add_commodity("LIS", "LON", 10, cost_multiplier=1)

        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertNotEqual(paths[("LIS", "LON")], [["LIS", "LON"]])

        # now with cost multiplier
        # this forces the LP to choose the shortest path for this commodity
        # because its cheaper to extend the others
        mcf = MCF(self.graph)
        mcf.add_commodity("POR", "LON", 10)
        mcf.add_commodity("LIS", "BRI", 10)
        mcf.add_commodity("MAD", "LON", 10)
        mcf.add_commodity("LIS", "LON", 10, cost_multiplier=10)

        mcf.make_and_solve_lp()
        paths = mcf.get_paths()
        self.assertEqual(paths[("LIS", "LON")], [["LIS", "LON"]])


if __name__ == "__main__":
    unittest.main()
