"""Custom topology example

Two directly connected switches plus a host for each switch:

   host1 --- switch1 --- switch2 --- host4
               |            |
            host2         host3

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
class MyTopo( Topo ):
  "Simple topology example."
  def __init__( self ):
    "Create custom topo."
    # Initialize topology
    Topo.__init__( self )
    # Add hosts and switches
    Host1 = self.addHost( 'h1' )
    Host2 = self.addHost( 'h2' )
    Host3 = self.addHost( 'h3' )
    Host4 = self.addHost( 'h4' )
    Switch1 = self.addSwitch( 's1' )
    Switch2 = self.addSwitch( 's2' )

    host1 = self.addHost( 'h1', ip="10.0.1.100/24", defaultRoute = "via 10.0.1.1" )
    host2 = self.addHost( 'h2', ip="10.0.1.200/24", defaultRoute = "via 10.0.1.1" )
    host3 = self.addHost( 'h3', ip="10.0.2.100/24", defaultRoute = "via 10.0.2.1" )
    host4 = self.addHost( 'h4', ip="10.0.2.200/24", defaultRoute = "via 10.0.2.1" )

    # Add links
    self.addLink( Host1, Switch1 )
    self.addLink( Host2, Switch1 )
    self.addLink( Host3, Switch2 )
    self.addLink( Host4, Switch2 )
    self.addLink( Switch1, Switch2 )

topos = { 'mytopo': ( lambda: MyTopo() ) }

