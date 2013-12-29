"""
kdsp/protocol.py - Twisted protocol library for Kismet Drone-Server Protocol (KDSP)
Copyright 2013 Michael Farrell <micolous+git@gmail.com>

This library is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this library.  If not, see <http://www.gnu.org/licenses/>.

"""

# Kismet KDSP protocol reference (kis_droneframe.h):
# https://www.kismetwireless.net/gitweb/?p=kismet.git;a=blob;f=kis_droneframe.h;hb=HEAD

from twisted.internet.protocol import Protocol, Factory
from twisted.python import log
from twisted.internet import reactor
from decimal import Decimal
from struct import unpack
from datetime import datetime
from pytz import utc
try:
	from scapy.all import Dot11
except ImportError:
	Dot11 = None


# Constants for the protocol
KISMET_SENTINEL         = 0xDEADBEEF
DRONE_CMDNUM_NULL       = 0
DRONE_CMDNUM_HELO       = 1
DRONE_CMDNUM_STRING     = 2
DRONE_CMDNUM_CAPPACKET  = 3
DRONE_CMDNUM_CHANNELSET = 4
DRONE_CMDNUM_SOURCE     = 5
DRONE_CMDNUM_REPORT     = 6

DRONE_CONTENT_RADIO      = 0x00000001
DRONE_CONTENT_GPS        = 0x00000002
DRONE_CONTENT_FCS        = 0x00000004
DRONE_CONTENT_IEEEPACKET = 0x80000000

class KDSPacket(object):
	"""
	Base class for all KDSP packet deserialisers
	"""

class KDSNull(KDSPacket):
	def __init__(self, packet):
		# Null packets have no data...
		assert len(packet) == 0, 'Unexpected data in NULL packet'

class KDSHelo(KDSPacket):
	def __init__(self, packet):
		# drone_helo_packet
		#   uint32_t drone_version
		#   char[32] kismet_version
		#   char[32] host_name
		
		assert len(packet) == 68, 'Unexpected length in HELO packet'
		self.drone_version, self.kismet_version, self.host_name = \
			unpack('!L32s32s', packet)
		
		# done


class KDSCapSubRadio(object):
	def __init__(self, packet):
		# drone_capture_sub_radio
		#   uint16 radio_hdr_len        -- we can ignore this one
		#   uint32 radio_content_bitmap -- this isn't used
		#
		#   uint16 radio_accuracy
		#   uint16 radio_freq_mhz
		#    int16 radio_signal_dbm
		#    int16 radio_noise_dbm
		#   uint32 radio_carrier
		#   uint32 radio_encoding
		#   uint32 radio_datarate
		#    int16 radio_signal_rssi
		#    int16 radio_noise_rssi
		
		self.radio_hdr_len, self.radio_content_bitmap, self.radio_accuracy, \
			self.radio_freq_mhz, self.radio_signal_dbm, self.radio_noise_dbm, \
			self.radio_carrier, self.radio_encoding, self.radio_datarate, \
			self.radio_signal_rssi, self.radio_noise_rssi \
			= unpack('!HLHHhhLLLhh', packet)
	
	def __repr__(self):
		return '<KDSCapSubRadio: freq=%r MHz, signal=%r dBm, noise=%r dBm>' % (
			self.radio_freq_mhz, self.radio_signal_dbm, self.radio_noise_dbm
		)


class KDSCapPacket(KDSPacket):
	def __init__(self, packet):
		# drone_capture_packet
		#   uint32 cap_content_bitmap
		#   uint32 cap_packet_offset  -- offset until the "capture packet header"
		# ... other data depending on the bitmap
		
		self.cap_content_bitmap, cap_packet_offset = \
			unpack('!LL', packet[:8])
		
		packet = packet[8:]
		cap_packet = packet
		
		if self.cap_content_bitmap & DRONE_CONTENT_RADIO > 0:
			# read a drone_capture_sub_radio
			# find it's length (uint16), this is inclusive of the length value.
			length = unpack('!H', cap_packet[:2])[0]
			self.radio = KDSCapSubRadio(cap_packet[:length])
			
			# shift the packet
			cap_packet = cap_packet[length:]
		else:
			self.radio = None
			
		# in case we haven't parsed out everything (like FCS, GPS), skip ahead here
		del cap_packet
		packet = packet[cap_packet_offset:]
		
		# now parse the main part
		# drone_capture_sub_data
		#            uint16 data_header_len
		#            uint32 data_content_bitmap
		#          char[16] uuid
		#            uint16 packet_len
		#            uint64 tv_sec
		#            uint64 tv_usec
		#            uint32 dlt
		#  char[packet_len] packetdata
		
		data_header_len, data_content_bitmap, self.uuid, packet_len, self.tv_sec, \
			self.tv_usec, self.dlt = unpack('!HL16sHQQL', packet[:44])
		
		assert data_header_len == 44, 'Unexpected data header length, got %r.' % data_header_len
		
		# now parse the rest out as data... the rest is 802.11.
		self.packet = packet[44:44+packet_len]
	
	def scapy(self):
		# pass back an object parsed by scapy
		return Dot11(self.packet)
	
	def tv(self):
		"""
		Gets the datetime when this packet was captured.
		
		Ignores the 'tv_usec' value from the header (microseconds).
		"""
		
		return datetime.utcfromtimestamp(self.tv_sec).replace(tzinfo=utc)
		
	def __repr__(self):
		try:
			scapypacket = self.scapy()
		except:
			# don't worry if we can't get it
			scapypacket = None
		return '<KDSCapPacket: radio=%r, packet=%r bytes, scapy=%s>' % (self.radio, len(self.packet), repr(scapypacket))


class KDSProtocol(Protocol):
	def __init__(self):
		self._buf = ''

	
	def dataReceived(self, data):
		self._buf += data
		
		# drone_packets start out like this:
		#           uint32 sentinel       == 0xDEADBEEF
		#           uint32 drone_cmdnum
		#           uint32 data_len       (length of following data)
		#   char[data_len] data    (the body of the rest of the packet)
		
		# once we have the basic structure we can hand off parsing the rest of the packet to subclasses.
		
		# so we need at least 4 * 3 = 12 bytes to continue, drop
		# out now if we don't have that and we'll try on the next round.
		while len(self._buf) > 12:
			# lets search for a 0xDEADBEEF!
			sentinel, cmdnum, data_len = unpack('!LLL', self._buf[:12])
			
			if sentinel != KISMET_SENTINEL:
				# drop out now and clear the buffer so we can reset
				log.err('Expected sentinel header, got %08X instead.  Dropping buffer.' % sentinel)

				self._buf = ''
				return
			
			# lets see if we have enough data to pass off parsing now
			if len(self._buf) < data_len + 12:
				# we don't have the whole packet in the buffer yet, drop out and come back later.
				return
			
			# lets get the packet body, and shift the buffer (multiple commands may be in one packet
			body = self._buf[12:12+data_len]
			self._buf = self._buf[12+data_len:]
			
			# pass off parsing as appropriate
			packet = None
			
			if cmdnum == DRONE_CMDNUM_NULL:
				packet = KDSNull(body)
			elif cmdnum == DRONE_CMDNUM_HELO:
				packet = KDSHelo(body)
			elif cmdnum == DRONE_CMDNUM_CAPPACKET:
				packet = KDSCapPacket(body)
			else:
				log.msg('Cannot parse packet with command %r' % cmdnum)
				continue
				
			if packet != None:
				try:
					self.on_packet(packet)
				except:
					log.err()

	def on_packet(self, packet):
		log.msg('got %r' % packet)


class KDSProtocolHandlerFactory(Factory):
	def __init__(self, protocol):
		self.protocol = protocol
	
	def buildProtocol(self, addr):
		return self.protocol

if __name__ == '__main__':
	from twisted.internet.endpoints import TCP4ClientEndpoint
	from argparse import ArgumentParser
	import sys
	
	log.startLogging(sys.stdout)
	parser = ArgumentParser()
	parser.add_argument('-a', '--addr', dest='addr', default='', help='Address of Kismet drone to connect to')
	
	options = parser.parse_args()
	
	protocol = KDSProtocol()
	addr = options.addr.split(':', 2)
	point = TCP4ClientEndpoint(reactor, addr[0], int(addr[1]))
	d = point.connect(KDSProtocolHandlerFactory(protocol))
	reactor.run()
