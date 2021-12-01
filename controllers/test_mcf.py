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

    def test_waypointing(self):
        # setup LP with waypoint constraint which is definitively
        # not part of the shortest path (a bit of a detour)

        # first check that without waypoint we dont go via MAN
        mcf = MCF(self.graph)
        mcf.add_commodity("LIS", "BER", 10)
        paths = mcf.get_paths()
        self.assertNotIn("MAN", paths[("LIS", "BER")][0])

        # now we add the waypoint and the path should contain MAN
        mcf = MCF(self.graph)
        mcf.add_commodity("LIS", "BER", 10)
        mcf.add_waypoint("LIS", "BER", "MAN")
        paths = mcf.get_paths()
        self.assertIn("MAN", paths[("LIS", "BER")][0])


if __name__ == "__main__":
    unittest.main()
