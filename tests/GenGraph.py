import Anomos
import math
import os
import random
import string
import sys
from M2Crypto import X509
from Anomos import NetworkModel
import pygraphviz as pgv

class GenGraph(object):
    def __init__(self, p_reach=1):
        self.root = os.path.split(os.path.abspath(sys.argv[0]))[0]
        Anomos.Crypto.init(self.root)
        self.nm = NetworkModel.NetworkModel({'allow_close_neighbors':0})
        self.cert = X509.load_cert(os.path.join(Anomos.Crypto.global_cryptodir,"fake-peer-cert.pem"))
        self.p_reach=p_reach
    def init_peer(self):
        peerid = ''.join(str(i) for i in random.sample(string.lowercase, 20))
        ip = '.'.join(str(i) for i in random.sample(range(256),4))
        numcon = math.ceil(len(self.nm.reachable)**(1.0/3))
        self.nm.init_peer(peerid, self.cert, ip, '5881', 'session', numcon)
        if random.uniform(0,1) <= self.p_reach:
            # Make the peer reachable
            self.nm.get(peerid).nat = False
            self.nm.reachable.add(peerid)
    def announce_all(self):
        numcon = math.ceil(len(self.nm.reachable)**(1.0/3))
        for s in self.nm.names.values():
            n = len(s.neighbors)
            if n < numcon:
                self.nm.rand_connect(s.name, numcon-n)

    def draw_graph(self, filename):
        G = pgv.AGraph()
        G.graph_attr.update(size="7")
        G.graph_attr.update(ratio="fill")
        G.graph_attr.update(ranksep=".5,1.0")
        G.graph_attr.update(root="center")

        G.node_attr.update(shape="circle")
        G.node_attr.update(fixedsize="True")
        G.node_attr.update(width="0.2")
        G.node_attr.update(height="0.2")
        G.node_attr.update(label="hax")
        G.node_attr.update(color="blue")
        G.add_nodes_from(self.nm.names, label="")
        for s in self.nm.names.values():
            if s.nat:
                G.get_node(s.name).attr['color']='orange'
            for n in s.neighbors:
                G.add_edge(s.name, n)

        # Create center node, and connect all reachable peers to it
        # This structures the output such that reachable peers appear
        # clustered together in the center of the image
        G.add_node("center", label="",style="invisible")
        for n in self.nm.reachable:
            G.add_edge("center",n,style="invisible")

        #G.add_subgraph(list(self.nm.reachable))
        #G.add_subgraph(list(set(self.nm.names)-self.nm.reachable))
        G.layout("twopi")
        G.draw(filename)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print "USAGE: python %s ratio node_count" % sys.argv[0]
        print "\tratio - float, % of network which is reachable"
        print "\tnode_count - Total number of nodes in network"
        print "\tprefix - file will be output to ./graphs/prefix-ratio-node_count.png"
        sys.exit()
    ratio = float(sys.argv[1])
    size = int(sys.argv[2])
    prefix = sys.argv[3]
    gg = GenGraph(ratio)
    for i in range(size):
        gg.init_peer()
    gg.announce_all()
    gg.announce_all()
    outdir = os.path.join(gg.root, "graphs")
    try:
        os.mkdir(outdir)
    except OSError:
        pass
    gg.draw_graph(os.path.join(outdir,"%s-%.2f-%d.png" % (prefix, ratio, size)))



