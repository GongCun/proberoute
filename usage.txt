Copyright  (C) 2017 by Cun Gong <gong_cun@bocmacau.com>
BSD 3-clause "New" or "Revised" License

proberoute is a more powerful routing detection tool that provides multiple
protocols and detection methods.

Usage: proberoute [OPTION] DEST
  or : proberoute [OPTION] DEST PORT

Options
 -v, --verbose    Verbose output, multiple -v options increase the verbosity.
 -h, --help       Show this help.
 -P <protocol>    Send packets of specified IP protocol: UDP, TCP or ICMP.
     --tcp        Specify the TCP protocol.
     --udp        Specify the UDP protocol.
     --icmp       Specify the ICMP protocol.
 -p, --port <portnum>
                  Set the destination port number for TCP or UDP,
                  default is 33434.
 -g, --source-port <portnum>
                  For UDP, TCP, set the source port number used in probes,
                  default is random port.
 -S, --source-ip <IPaddr>
                  Set the source address for probes, must use -i to specify the
                  interface you wish to send.
 -i <iface>       Specify a network interface to obtain the source IP address
                  for outgoing probe packets.
 -q <nqueries>    Set the number of probes per hop, default is 3.
 -w <waittime>    Set the time (in seconds) to wait for a response to a probe,
                  default is 3 sec.
 -f <first_tll>   Set the initial time-to-live used in outgoing probe packets,
                  default is 1, i.e., start with the first hop.
 -m <max_ttl>     Set the max time-to-live (max number of hops) used in outgoing
                  probe packets.
 -F, --frag-size <frag_size>
                  Specify the IP fragment size (must be a multiple of 8),
                  default is "don't fragment".
 -s, --mtu=<MTU>  Using the specified MTU, default is auto detection.
 --conn           TCP connect probe, used to detect the path MTU.
 --syn/ack/push/null/fin/xmas
                  TCP SYN, ACK, PUSH, Null, FIN and Xmas probes.
 --badsum         Send packet with a bogus TCP/UDP/ICMP checksum.
 --badlen         Send packet with a bad IP option length.
 -e, --echo       Send ICMP echo request probes.
 --echo-reply     Send ICMP echo reply probes.
 -t, --tstamp     Send ICMP timestamp request probes.
 --tstamp-reply   Send ICMP timestamp reply probes.
 -j, --source-route <gateway>
                  Loose Source Route. Tell the network to route the packet
                  through the specified gateway (Unfortunately, most routers
                  have disabled source routing for security reasons).
