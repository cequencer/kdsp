# kdsp #

Python/Twisted protocol library for Kismet Drone-Server Protocol (KDSP), as used by `kismet_drone`.

Work in progress, contains dragons.

Supports passing 802.11 frames to [scapy](http://www.secdev.org/projects/scapy/) in order to decode them.

## Protocol Documentation ##

KDSP:
* [kis_droneframe.h](https://www.kismetwireless.net/gitweb/?p=kismet.git;a=blob;f=kis_droneframe.h;hb=HEAD)
* [kis_droneframe.cc](https://www.kismetwireless.net/gitweb/?p=kismet.git;a=blob;f=kis_droneframe.cc;hb=HEAD)

WPS:
* [packet_wps.c](http://code.wireshark.org/git/?p=wireshark;a=blob;f=epan/dissectors/packet-wps.c;hb=HEAD)

