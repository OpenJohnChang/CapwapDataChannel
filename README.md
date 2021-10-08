# CapwapTunnel
Kernel-space implementation of CAPWAP (RFC-5415) tunnel for Linux

CAPWAP --- Control And Provisioning of Wireless Access Points (RFC-5415)

Authors: John Chang (mofish@gmail.com)
 
[License]:
      This program is free software; you can redistribute it and/or
      modify it under the terms of the GNU General Public License
      as published by the Free Software Foundation; either version
      2 of the License, or (at your option) any later version.

 
[Usage]:

  Commands:
  
  // setup capwap tunnel
  ip capwap add tunnel tunnel_id 1000 peer_tunnel_id 2000 encap udp local 192.168.1.100 remote 192.168.1.200 udp_sport 5247 udp_dport 6000 
  
  // setup capwap session
  ip capwap add session tunnel_id 1000 session_id 5247 peer_session_id 6000
  
  // show capwap tunnel information
  ip capwap show tunnel 
  
  // show capwap session information
  ip capwap show session 
