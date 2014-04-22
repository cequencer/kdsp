****
kdsp
****

Python/Twisted protocol library for Kismet Drone-Server Protocol (KDSP), as used by `kismet_drone`.

Work in progress, contains dragons.

Supports passing 802.11 frames to `scapy <http://www.secdev.org/projects/scapy/>`_ in order to decode them.

Protocol Documentation
======================

KDSP:
* `kis_droneframe.h <https://www.kismetwireless.net/gitweb/?p=kismet.git;a=blob;f=kis_droneframe.h;hb=HEAD>`_
* `kis_droneframe.cc <https://www.kismetwireless.net/gitweb/?p=kismet.git;a=blob;f=kis_droneframe.cc;hb=HEAD>`_

WPS:
* `packet_wps.c <http://code.wireshark.org/git/?p=wireshark;a=blob;f=epan/dissectors/packet-wps.c;hb=HEAD>`_


Licensing and Copyright
=======================

Copyright 2013-2014 `Michael Farrell <http://micolous.id.au/>`_

This library is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this library.  If not, see http://www.gnu.org/licenses/

