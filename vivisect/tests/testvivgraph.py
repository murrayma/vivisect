import unittest
import visgraph.graphcore as vs_graphcore
import vivisect.tools.graphutil as viv_graph
from vivisect.tests.vivbins import getTestWorkspace, getAnsWorkspace


    def checkGetCodePaths(self, vw, fva):
        graph = viv_graph.buildFunctionGraph(vw, fva )
        paths = [ path for path in viv_graph.getCodePaths(graph) ]
        self.codepaths = paths
        self.assertGreater(len(self.codepaths), 150)

    def checkGetCodePathsThru(self, vw, fva, cbva):
        graph = viv_graph.buildFunctionGraph(vw, fva )
        paths = [ path for path in viv_graph.getCodePathsThru(graph, cbva) ]
        self.codepathsthru = paths
        self.assertGreater(len(self.codepaths), len(self.codepathsthru))

        paths = [ path for path in graph.getHierPathsThru((cbva,)) ]
        self.hiercodepathsthru = paths
        self.assertGreater(len(self.codepaths), len(self.hiercodepathsthru))

    def checkGetCodePathsFrom(self, vw, fva, cbva):
        graph = viv_graph.buildFunctionGraph(vw, fva )
        paths = [ path for path in viv_graph.getCodePathsFrom(graph, cbva) ]
        self.codepathsfrom = paths
        self.assertGreater(len(self.codepaths), 150)

        paths = [ path for path in graph.getHierPathsFrom,((cbva,)) ]
        self.hierpathsfrom = paths
        self.assertGreater(len(self.codepaths), len(self.hierpathsfrom))

    def checkGetCodePathsTo(self, vw, fva, cbva):
        graph = viv_graph.buildFunctionGraph(vw, fva )
        paths = [ path for path in viv_graph.getCodePathsTo(graph, cbva) ]
        self.codepathsto = paths
        self.assertGreater(len(self.codepaths), len(self.codepathsto))

        paths = [ path for path in graph.getHierPathsTo((cbva,)) ]
        self.hierpathsto = paths
        self.assertGreater(len(self.codepaths), len(self.hierpathsto))

    def checkGetLoopPaths(self, vw, fva):
        graph = viv_graph.buildFunctionGraph(vw, fva )
        paths = [ path for path in viv_graph.getLoopPaths(graph) ]
        self.looppaths = paths
        self.assertGreater(len(self.codepaths), 150)

    def checkGetLongPath(self, vw, fva):
        graph = viv_graph.buildFunctionGraph(vw, fva)
        paths = [ path for path in viv_graph.getLongPath(graph) ]
        self.codepaths = paths
        self.assertGreater(len(self.codepaths), 150)

    def checkPathGenGetCodePaths(self, vw, fva):
        graph = viv_graph.buildFunctionGraph(vw, fva)
        paths = [ path for path in viv_graph.getCodePathsThru(graph) ]
        self.codepaths = paths
        self.assertGreater(len(self.codepaths), 150)

    def checkCoveragePaths(self, vw, fva):
        graph = viv_graph.buildFunctionGraph(vw, fva)
        paths = [ path for path in viv_graph.getCoveragePaths(graph, 150) ]
        self.codepaths = paths
        self.assertEqual(len(self.codepaths), 22)

    @vivbins.require
    def test_viv_graph_paths(self):
        # one file
        fname = 'testexe_amd64.exe'
        fva = 0x1400060ac
        cbva = 0x1400061bf
        vw = getAnsWorkspace(fname)

        self.checkGetCodePaths(vw, fva)
        self.checkGetCodePathsThru(vw, fva, cbva)
        self.checkGetCodePathsFrom(vw, fva, cbva)
        self.checkGetCodePathsTo(vw, fva, cbva)
        self.checkGetLoopPaths(vw, fva)
        self.checkGetLongPath(vw, fva)
        self.checkCoveragePaths(vw, fva)

class VivGraphTest(unittest.TestCase):

    def setUp(self):
        g = vs_graphcore.HierGraph()
        g.addHierRootNode('Rooty')

        g.addNode('Righty')
        g.addNode('SonOfRighty')
        g.addNode('RightyStrikesBack')
        g.addNode('TheEnd')
        g.addNode('OrIsIt')
        g.addNode('TheReboot')
        g.addNode('Nobody')
        g.addNode('Wanted')

        g.addNode('Lefty')
        g.addNode('SonOfLefty')
        g.addNode('LeftysRevenge')
        g.addNode('LeftyTheReboot')

        g.addNode('Backtracker')
        g.addNode('LeftyClone')
        g.addNode('RightyClone')

        g.addEdgeByNids('Rooty', 'Lefty')
        g.addEdgeByNids('Rooty', 'Righty')

        g.addEdgeByNids('Lefty', 'SonOfLefty')
        g.addEdgeByNids('SonOfLefty', 'LeftysRevenge')
        g.addEdgeByNids('LeftysRevenge', 'LeftyTheReboot')
        g.addEdgeByNids('LeftyTheReboot', 'Backtracker')

        g.addEdgeByNids('Backtracker', 'LeftyClone')
        g.addEdgeByNids('Backtracker', 'RightyClone')
        g.addEdgeByNids('Backtracker', 'RightyStrikesBack')

        g.addEdgeByNids('Righty', 'SonOfRighty')
        g.addEdgeByNids('SonOfRighty', 'RightyStrikesBack')
        g.addEdgeByNids('RightyStrikesBack', 'TheEnd')
        g.addEdgeByNids('TheEnd', 'OrIsIt')
        g.addEdgeByNids('OrIsIt', 'Backtracker')
        g.addEdgeByNids('OrIsIt', 'TheReboot')
        g.addEdgeByNids('TheReboot', 'Nobody')
        g.addEdgeByNids('Nobody', 'Wanted')

        self.graph = g

    def SKIPtest_longpath_backedge(self):
        # TODO: We need to answer whether or not we support weird backedges in the
        # longpath stuff
        longpath = [
            'Rooty',
            'Lefty',
            'SonOfLefty',
            'LeftysRevenge',
            'LeftyTheReboot',
            'Backtracker',
            'RightyStrikesBack',
            'TheEnd',
            'OrIsIt',
            'TheReboot',
            'Nobody',
            'Wanted',
        ]
        pathgenr = viv_graph.getLongPath(self.graph)
        path = map(lambda k: k[0], pathgenr.next())
        self.assertEqual(longpath, path)

    def test_longpath_med(self):
        g = vs_graphcore.HierGraph()
        g.addHierRootNode('A')
        for i in range(ord('B'), ord('U')):
            g.addNode(chr(i))

        g.addEdgeByNids('A', 'B')
        g.addEdgeByNids('A', 'C')

        g.addEdgeByNids('B', 'D')
        g.addEdgeByNids('B', 'E')

        g.addEdgeByNids('D', 'F')
        g.addEdgeByNids('E', 'F')

        g.addEdgeByNids('C', 'G')
        g.addEdgeByNids('F', 'G')

        g.addEdgeByNids('G', 'H')
        g.addEdgeByNids('G', 'I')

        g.addEdgeByNids('H', 'J')
        g.addEdgeByNids('H', 'K')

        g.addEdgeByNids('J', 'L')
        g.addEdgeByNids('K', 'L')
        g.addEdgeByNids('I', 'L')

        g.addEdgeByNids('L', 'M')

        g.addEdgeByNids('L', 'Q')
        g.addEdgeByNids('Q', 'R')
        g.addEdgeByNids('Q', 'S')
        g.addEdgeByNids('R', 'T')
        g.addEdgeByNids('S', 'T')
        g.addEdgeByNids('T', 'G')

        g.addEdgeByNids('M', 'N')
        g.addEdgeByNids('M', 'O')

        g.addEdgeByNids('N', 'P')
        g.addEdgeByNids('O', 'P')

        pathgenr = viv_graph.getLongPath(g)
        longpath = pathgenr.next()
        self.assertEqual(len(longpath), 11)

    def test_longpath_basic(self):
        g = vs_graphcore.HierGraph()
        g.addHierRootNode('A')
        for i in range(ord('B'), ord('M')):
            g.addNode(chr(i))

        g.addEdgeByNids('A', 'B')
        g.addEdgeByNids('A', 'C')
        g.addEdgeByNids('B', 'D')
        g.addEdgeByNids('B', 'E')
        g.addEdgeByNids('C', 'F')
        g.addEdgeByNids('C', 'G')
        g.addEdgeByNids('D', 'H')
        g.addEdgeByNids('E', 'H')
        g.addEdgeByNids('F', 'I')
        g.addEdgeByNids('G', 'I')
        g.addEdgeByNids('H', 'J')
        g.addEdgeByNids('H', 'K')
        g.addEdgeByNids('I', 'L')
        g.addEdgeByNids('J', 'L')
        g.addEdgeByNids('K', 'L')

        pathgenr = viv_graph.getLongPath(g)
        longpath = pathgenr.next()
        self.assertEqual(len(longpath), 6)

    def test_weights(self):
        '''
        Note: Weights are defined as the maximum length of all the paths to a node from the rootnodes
        So if a node A is the child of rootnode B, but it's also 7 hops from rootnode C, it's weight
        is going to be 7
        '''
        weights = self.graph.getHierNodeWeights()
        self.assertEqual(weights['Rooty'], 0)
        self.assertEqual(weights['Lefty'], 1)
        self.assertEqual(weights['SonOfLefty'], 2)
        self.assertEqual(weights['LeftysRevenge'], 3)
        self.assertEqual(weights['LeftyTheReboot'], 4)
        self.assertEqual(weights['Backtracker'], 6)
        self.assertEqual(weights['LeftyClone'], 7)
        self.assertEqual(weights['RightyClone'], 7)

        self.assertEqual(weights['Righty'], 1)
        self.assertEqual(weights['SonOfRighty'], 2)
        self.assertEqual(weights['RightyStrikesBack'], 3)
        self.assertEqual(weights['TheEnd'], 4)
        self.assertEqual(weights['OrIsIt'], 5)
        self.assertEqual(weights['TheReboot'], 6)
        self.assertEqual(weights['Nobody'], 7)
        self.assertEqual(weights['Wanted'], 8)
