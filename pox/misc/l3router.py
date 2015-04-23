# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str

import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# since it is a small network, keep the routing table never expires 
def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class Entry (object):
  """
  datastructure to keep routing_table entry element 
  """
  def __init__ (self, port, mac):
    self.port = port
    self.mac = mac

class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    #self.mac_to_port = {}

    
    # (ip with network prefix, ip of host, interface name, interface address, switch port)
    # self.routing_table = {'10.0.1.0/24': ['10.0.1.100', 's1-eth1', '10.0.1.1', 1],
    #                      '10.0.2.0/24': ['10.0.2.100', 's1-eth2', '10.0.2.1', 2],
    #                      '10.0.3.0/24': ['10.0.3.100', 's1-eth3', '10.0.3.1', 3]}
    self.gatewayaddr = ["10.0.1.1", "10.0.2.1", "10.0.3.1"]
    self.routing_table = {}
    self.message_queue = {}


  def _send_message_queue (self, dpid, ipaddr, macaddr, port):
    if (dpid,ipaddr) in self.message_queue:
      ptr = self.message_queue[(dpid,ipaddr)]
      del self.message_queue[(dpid,ipaddr)]
      log.debug("Sending buffered packets to %s from switch %s" % (ipaddr,dpid))
      for buffer_id,in_port in ptr:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po) 

  def act_like_router (self, packet, packet_in, dpid):
    """
    Implement router-like behavior.
    """   
    inport = packet_in.in_port
    if isinstance(packet.payload, arp):
      a = packet.payload
      log.debug("ARP message from switch%i port %i, src address %s ask who is %s", dpid, inport, str(a.protosrc), str(a.protodst))
      
      log.debug("switch%i update routing_table for %s", dpid,str(a.protosrc))
      self.routing_table[dpid][a.protosrc] = Entry(inport, packet.src)

      self._send_message_queue(dpid, a.protosrc, packet.src, inport)
      if a.opcode == arp.REQUEST:
        if a.protodst in self.routing_table[dpid]:
          r = arp()
          r.opcode = arp.REPLY
          r.hwdst = a.hwsrc
          r.protodst = a.protosrc
          r.protosrc = a.protodst
          r.hwsrc = self.routing_table[dpid][a.protodst].mac
          e = ethernet(type=packet.type, src=dpid_to_mac(dpid), dst=a.hwsrc)
          e.set_payload(r)
          log.debug("switch%i answering: the mac address for %s is %s " % (dpid, str(r.protosrc), EthAddr(r.hwsrc)))
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
          msg.in_port = inport
          self.connection.send(msg)
          return
      log.debug("controller flooding ARP, who is %s" % str(a.protodst))

      msg = of.ofp_packet_out(in_port = inport, data = packet_in,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      self.connection.send(msg)
    elif isinstance(packet.payload, ipv4):
      log.debug("%s send ip packet to %s, from switch%i", packet.payload.srcip, packet.payload.dstip,dpid)

      # new packet come check if it will satisfy the message queue address
      self._send_message_queue(dpid, packet.payload.srcip, packet.src, inport)

      # everytime update port/Mac info
      log.debug("switch%i update routing_table for %s", dpid,str(packet.payload.srcip))
      self.routing_table[dpid][packet.payload.srcip] = Entry(inport, packet.src)
      dstaddr = packet.payload.dstip
      if dstaddr in self.routing_table[dpid]:
        prt = self.routing_table[dpid][dstaddr].port
        mac = self.routing_table[dpid][dstaddr].mac
        log.debug("siwtch%i installing flow packet from %s to %s  the out port is %i" % (dpid, packet.payload.srcip, dstaddr, prt))

        actions = []
        actions.append(of.ofp_action_dl_addr.set_dst(mac))
        actions.append(of.ofp_action_output(port = prt))
        msg = of.ofp_flow_mod(buffer_id=packet_in.buffer_id,
                              actions=actions,
                              match=of.ofp_match.from_packet(packet,inport))
        self.connection.send(msg.pack())
      # TODO: what if we dont know the destniation address
      else:
        if (dpid,dstaddr) not in self.message_queue:
          self.message_queue[(dpid,dstaddr)] = []
        ptr = self.message_queue[(dpid,dstaddr)]
        entry = (packet_in.buffer_id,inport)
        ptr.append(entry)

        r = arp()
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src 
        r.protosrc = packet.payload.srcip
        e = ethernet(type = ethernet.ARP_TYPE, src = packet.src, dst = ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("controller broadcast ARP_REQUEST who is %s" % str(r.protodst))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        self.connection.send(msg)   


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    dpid = event.connection.dpid 

    if dpid not in self.routing_table:
      self.routing_table[dpid] = {}
    # assign static IP to switch ports
      log.debug("update fake gateway to routing_table for switch%i ", dpid)
      for fake in self.gatewayaddr:
        self.routing_table[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE, dpid_to_mac(dpid))
    
    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    self.act_like_router(packet, packet_in, dpid)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
