/*
* The MIT License(MIT)
* Copyright(c) 2016 Lorenzo Delana, https://searchathing.com
*
* Permission is hereby granted, free of charge, to any person obtaining a
* copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation
* the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
* DEALINGS IN THE SOFTWARE.
*/

#ifndef _SEARCHATHING_ARDUINO_NET_PROTOCOL_H
#define _SEARCHATHING_ARDUINO_NET_PROTOCOL_H

#if defined(ARDUINO) && ARDUINO >= 100
#include "arduino.h"
#else
#include "WProgram.h"
#endif

#include <SearchAThing.Arduino.Utils\DebugMacros.h>
#include <SearchAThing.Arduino.Utils\BufferInfo.h>

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			class EthNet;
			class EthDriver;

			//----------------------------------------------------------
			// Utils
			//----------------------------------------------------------

			// Timeout to receive a respond after a request issued before to
			// try a new request again.
			// See also: DynamicTimeout
			const uint16_t REQUEST_TIMEOUT_MS = 500;

			// After each timeout reach the timeout value increase of the
			// initial timeout value until max value, then it will reset
			// to the initial timeout value.
			// See also: DynamicTimeout
			const uint32_t REQUEST_TIMEOUT_MAX = 1L * 1000;

			// Creates a private MAC address 00:00:6C:00:00:xx using xx=lsb.
			// See: https://en.wikipedia.org/wiki/MAC_address
			RamData PrivateMACAddress(byte lsb);

			const byte IPV4_TTL = 128;
			const byte IPV4_MACSIZE = 6;
			const byte IPV4_IPSIZE = 4;

			//----------------------------------------------------------
			// Eth2
			//----------------------------------------------------------

			// EthernetII header.
			// https://en.wikipedia.org/wiki/Ethernet_frame
			typedef struct Eth2Header
			{
				// Destination MAC address.
				byte dstMAC[IPV4_MACSIZE];

				// Source MAC address.
				byte srcMAC[IPV4_MACSIZE];

				// EtherType. Use Eth2Type enum to address the type.
				// http://www.cavebear.com/archive/cavebear/Ethernet/type.html
				byte type[2];
			};

			// EtherType enum.
			typedef enum
			{
				Eth2Type_UNK = -1,

				// ARP EtherType.
				Eth2Type_ARP = 0x0806,

				// IP EtherType.
				Eth2Type_IP = 0x0800
			} Eth2Type;

			// Retrieve EtherType from the given EthII header.
			Eth2Type Eth2GetType(Eth2Header *eth2);

			// Retrieve EthII header from the given packet buffer.
			Eth2Header *Eth2GetHeader(byte *pkt);

			// Prepare the current packet Eth2 header filling with
			// SourceMAC = network card MAC
			// EtherType = given `type'
			void Eth2Fill(const EthNet *net, Eth2Header *eth2, Eth2Type type);

			// Prints Eth2 Header fields.
			void Eth2Print(Eth2Header *eth2);

			//----------------------------------------------------------
			// ARP
			//----------------------------------------------------------

			// ARP Header.
			// http://www.networksorcery.com/enp/protocol/arp.htm
			typedef struct ARPHeader
			{
				// Hardware type. See: ARPType.
				byte hwType[2];

				// Protocol type. See: ARPProtocolType.
				byte protoType[2];

				// Hardware address length. Usually MAC 6 bytes.
				byte hwAddrLength;

				// Protocol address length. For IPv4 this value is 4.
				byte protoAddrLength;

				// ARP OpCode. See: ARPOpcodeType.
				byte opCode[2];
			};			

			// ARP Type enu.
			typedef enum
			{
				// ARP Type : Ethernet
				ARPType_Ethernet = 1
			} ARPType;

			// ARP Protocol type enum.
			typedef enum
			{
				// ARP Protocol type : IP
				ARPProtocolType_IP = 0x800
			} ARPProtocolType;

			// ARP Opcode type enum.
			typedef enum
			{
				// ARP Opcode : Request
				ARPOpCodeType_Request = 1,

				// ARP Opcode : Reply
				ARPOpCodeType_Reply = 2
			} ARPOpcodeType;

			// Retrieve the ARP Header from the given Eth2 header.
			ARPHeader *ARPGetHeader(Eth2Header *eth2);

			// Set the ARP opcode.
			void ARPSetOpCodeType(ARPHeader *arp, ARPOpcodeType type);

			// Retrieve the ARP data packet pointer to the source MAC.
			byte *ARPSourceHardwareAddress(ARPHeader *arp);

			// Retrieve the ARP data packet pointer to the source IP.
			byte *ARPSourceProtocolAddress(ARPHeader *arp);

			// Retrieve the ARP data packet pointer to the destination MAC.
			byte *ARPDestinationHardwareAddress(ARPHeader *arp);

			// Retrieve the ARP data packet pointer to the destination IP.
			byte *ARPDestinationProtocolAddress(ARPHeader *arp);

			// Retrieve the ARP Size ( Header + Data ).
			uint16_t ARPSize(ARPHeader *arp);

			// Fills out the ARP packet with the given opCode and following
			// settings:
			// - Hardware type : Ethernet
			// - Protocol type : IP
			// - Hardware length : 6 ( == IPV4_MACSIZE )
			// - Protocol length : 4 ( == IPV4_IPSIZE )
			// - Source MAC : ethernet card MAC
			// - Source IP : ethernet subsystem IP
			void ARPFill(const EthNet *net, ARPHeader *arp, ARPOpcodeType opCode);

			// Prints ARP Header fields.
			void ARPPrint(ARPHeader *arp);

			//----------------------------------------------------------
			// IPv4
			//----------------------------------------------------------

			// Internet Protocol Header.
			// http://www.networksorcery.com/enp/protocol/ip.htm
			typedef struct IPv4Header
			{
				// Internet Header Length.
				// Its express a length with a number which units is 4bytes
				// (eg. ihl=5 -> 5 x 4 = 20 bytes )
				// ( 4 bit lower )
				byte ihl : 4;

				// IP protocol version.
				// ( 4 bit higher )
				byte version : 4;

				// Services.
				byte services;

				// Total length of the packet including encapsulated
				// protocols and data. Excluded previous Eth2 header.
				byte totalLength[2];

				// Used for sequence identification.
				byte identification[2];

				// Flags.
				// ( 3 bit higher )
				byte flags : 3;

				// Fragment Offset 
				// ( 5 bits higher )
				byte fragmentOffsetH : 5;

				// Fragment Offset (Low)
				// ( 8 bits lower )
				byte fragmentOffsetL : 8;

				// Time to live.
				byte ttl;

				// Protocol type. See: IPv4Type.
				byte protocol;

				// IPv4 Checksum of the entire IPv4Header only without
				// subsequent encapsulated protocols. Note: the checksum
				// will be computed with the header values except the
				// dummy checksum zeroed.
				// See: IPv4WriteValidChecksum()
				byte chksum[2];

				// Source Ip address.
				byte srcip[4];

				// Destination Ip address.
				byte dstip[4];
			};			

			// IPv4Type enum.
			typedef enum
			{
				// IPv4 Protocol type ICMP
				IPv4Type_ICMP = 1,

				// IPv4 Protocol type UDP
				IPv4Type_UDP = 17
			} IPv4Type;

			// Retrieve IPv4Header from the Eth2.
			IPv4Header *IPv4GetHeader(Eth2Header *hdr);

			// Fills out the IPv4 packet with the given `ipv4Len' total len,
			// `type' ip protocol type and follow settings:
			// - Internet header length : 5 ( that is 5x4 = 20 bytes )
			// - Internet version : 4 ( ip v.4 )
			// - Services : 0
			// - Flags : 0
			// - Fragmented Offset : 0
			// - Ttl : 128 ( = IPV4_TTL )
			// - Source ip : ethernet card ip
			void IPv4Fill(const EthNet *net, IPv4Header *ipv4, uint16_t ipv4Len, IPv4Type type);

			// Compute the IPv4Header checksum and store the value into the
			// chksum field. See also: IPv4Header::chksum
			void IPv4WriteValidChecksum(IPv4Header *ipv4);

			// Prints IPv4 Header fields.
			void IPv4Print(IPv4Header *ipv4);

			//----------------------------------------------------------
			// ICMP
			//----------------------------------------------------------

			// Internet Control Message Protocol Header
			// http://www.networksorcery.com/enp/protocol/icmp.htm
			typedef struct ICMPHeader
			{

				// ICMP type. See: ICMPType.
				byte type;

				// ICMP code.
				byte code;

				// ICMP checksum. Its the checksum of the ICMP packet with
				// dummy checksum of 0 excluded Eth2 and IPv4 headers.
				byte chksum[2];
			};

			// ICMP Echo Header
			// http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
			struct ICMPEchoHeader
			{
				// ICMP Header
				ICMPHeader icmp;

				// Identifier
				byte identifier[2];

				// Sequence number
				byte seqnr[2];
			};			

			// ICMP Type enum.
			typedef enum
			{
				// ICMP type Echo Reply.
				ICMPType_EchoReply = 0,

				// ICMP type Echo Request.
				ICMPType_EchoRequest = 8
			} ICMPType;

			// Retrieve the ICMP Header from the given `ipv4' header.
			ICMPHeader *ICMPGetHeader(IPv4Header *ipv4);

			// Compute the ICMP checksum and store the value into the
			// checksum field. See also: ICMPHeader::chksum
			void ICMPWriteValidChecksum(IPv4Header *ipv4, ICMPHeader *icmp);

			// Prints ICMP Header fields.
			void ICMPPrint(ICMPHeader *icmp);

			//----------------------------------------------------------
			// UDP
			//----------------------------------------------------------

			// Standard UDP server port. DHCP server/client system filters
			// udp packets based on these port values.
			const byte UDP_PORT_BOOTP_SERVER = 67;

			// Standard UDP client port. DHCP server/client system filters
			// udp packets based on these port values.
			const byte UDP_PORT_BOOTP_CLIENT = 68;

			// UDP Header.
			// http://www.networksorcery.com/enp/protocol/udp.htm
			typedef struct UDPHeader
			{
				// Source port.
				byte sourcePort[2];

				// Destination port.
				byte destPort[2];

				// Data length.
				byte length[2];

				// Checksum computed over a pseudo header with dummy chksum=0
				// {srcip, dstip, protocol, udpLen} and UDP header + data.
				// http://www.tcpipguide.com/free/t_UDPMessageFormat-2.htm
				byte chksum[2];
			};

			// Retrieve the UDP header.
			UDPHeader *UDPGetHeader(IPv4Header *ipv4);

			// Retrieve the UDP pointer to the data.
			byte *UDPGetData(UDPHeader *udp);

			// Write a valid UDP checksum.
			void UDPWriteValidChecksum(IPv4Header *ipv4, UDPHeader *udp);

			// Fills out the UDP packet with the given `srcPort', `dstPort'
			// and udp packet+data `len'
			void UDPFill(UDPHeader *udp, uint16_t srcPort, uint16_t dstPort, uint16_t len);

			// Prints UDP Header fields.
			void UDPPrint(UDPHeader *udp);

			//----------------------------------------------------------
			// DHCP
			//----------------------------------------------------------			

			// Bytes count of the DHCP magic cookie.
			const byte DHCPMagicCookieSIZE = 4;

			// DHCP Header
			// http://www.networksorcery.com/enp/protocol/dhcp.htm - size:240
			typedef struct DHCPHeader
			{
				// DHCP opcode. See: DHCPOpCode.
				byte opCode;

				// DHCP hardware type. See: DHCPHwType.
				byte hwType;

				// Hardware addres length.
				byte hwLength;

				// Hop count.
				byte hopCount;

				// Transaction Id.
				byte transactionId[4];

				// Seconds from last renewal.
				byte nrSeconds[2];

				// Flags
				byte flags[2];

				// Client Ip address.
				byte clientIpAddress[4];

				// Ip assigned by the server.
				byte yourIp[4];

				// Ip of the server during a request. (0 for discover).
				byte serverIp[4];

				// Gateway (0 for discover).
				byte gatewayIp[4];

				// Client MAC
				byte clientHwAddress[16];

				// Server hostname ( 0 )
				byte serverHostname[64];

				// Bootfilename ( 0 )
				byte bootFilename[128];

				// 0x63825363 ( magic cookie bootp )
				byte magic[4];

				// DATA
				//------
				// Data of the DHCP protocol consists of one or more
				// option ( see DHCPOption ) ending with the
				// DHCPOption::DHCPOptionEnd ( 0xff ).				
				//
				// Typical data composition:
				//
				// DISCOVER
				//	0x35 0x01 0x01 (discover)
				//	0xff (end)
				//
				// OFFER
				//	0x35 0x01 0x02 (offer)
				//  0xff (end)
				//
				// REQUEST
				//	0x35 0x01 0x03 (request)
				//  0x32 0x04 a b c d (requested ip address a.b.c.d)
				//  0x36 0x04 a b c d (server identifier a.b.c.d)
				//	0xff (end)
				//
				// ACK
				//	0x35 0x01 0x05 (ack)
				//  0x33 leaseH leaseL (lease time)
				//  0x0c len x x x ... (hostname)
				//  0x0f len x x x ... (domainname)
				//  0x03 0x04 a b c d (gateway)
				//  0x1c 0x04 a b c d (broadcast)
				//  0x06 0x04 a b c d (dns)
				//  0x01 0x04 a b c d (subnet)
				//	0xff ( end )
			};

			// DHCP opcode enum.
			typedef enum
			{
				// DHCP request.
				DHCPOpCode_BootRequest = 1,

				// DHCP reply.
				DHCPOpCode_BootReply = 2
			} DHCPOpCode;

			// DHCP hardware type.
			typedef enum
			{
				// Ethernet.
				DHCPHwType_Ethernet = 1
			} DHCPHwType;

			// DHCP Option enum.
			typedef enum
			{

				// Subnet.
				DHCPOptionSubnetMask = 1,

				// Gateway.
				DHCPOptionGateway = 3,

				// Dns.
				DHCPOptionDns = 6,

				// Domain name.
				DHCPOptionDomainName = 15,

				// Broadcast.
				DHCPOptionBroadcast = 28,

				// Requested ip address.
				DHCPOptionRequestedIpAddress = 50,

				// Lease time.
				DHCPOptionLeaseTime = 51,

				// Msg type.
				DHCPOptionMsgType = 53,

				// Server identifier.
				DHCPOptionServerIdentifier = 54,

				// Hostname.
				DHCPOptionHostname = 12,

				// End.
				DHCPOptionEnd = 0xff
			} DHCPOption;

			// DHCP message type.
			typedef enum
			{

				// Discover.
				DHCPMsgTypeDiscover = 1,

				// Offer.
				DHCPMsgTypeOffer = 2,

				// Request.
				DHCPMsgTypeRequest = 3,

				// Ack.
				DHCPMsgTypeAck = 5
			} DHCPMsgType;

			// DHCP Magic Cookie ( 0x63 0x82 0x53 0x63 )
			extern byte DHCPMagicCookie[];

			// Retrieve the DHCP Header from the given `udp'.
			DHCPHeader *DHCPGetHeader(UDPHeader *udp);

			// Sets the DHCP magic cookie in the given DHCP header.
			void DHCPSetMagicCookie(DHCPHeader *dhcp);

			// Retrieve the options pointer from the given `dhcp' header.
			byte *DHCPGetOptions(DHCPHeader *dhcp);

			// Checks if the given `dhcp' packet contains the given 
			// `optionInfo' between their available options.
			bool DHCPMatchesOption(IPv4Header *ipv4, UDPHeader *udp, DHCPHeader *dhcp, BufferInfo optionInfo);

			// Locate the buf pointer of the given `dhcp' packet where the
			// given `option' starts. Returns NULL if no such option found.
			byte *DHCPLocateOption(IPv4Header *ipv4, UDPHeader *udp, DHCPHeader *dhcp, byte option);

			//----------------------------------------------------------
			// DNS
			//----------------------------------------------------------

			// UDP destination port to send request to a DNS server.
			const byte UDP_PORT_DNS_SERVER = 53;

			// DNS class Internet.
			const byte DNS_CLASS_IN = 1;

			// DNS qr-code Query.
			const byte DNS_QR_CODE_QUERY = 0;

			// DNS qr-code Response.
			const byte DNS_QR_CODE_RESPONSE = 1;

			// DNS query type A. ( Address )
			const byte DNS_QUERY_TYPE_A = 1;

			// DNS query type MX. (Mail Exchanger)
			const byte DNS_QUERY_TYPE_MX = 15;

			// DNS Header.
			// http://www.networksorcery.com/enp/protocol/dns.htm and
			// http://www.networksorcery.com/enp/rfc/rfc1035.txt
			typedef struct DNSHeader
			{

				// Transaction Id.
				byte id[2];

				// request recursive
				byte rd : 1;

				byte tc : 1;

				byte aa : 1;

				byte opCode : 4;

				// qr-code ( DNS_QR_CODE_{ QUERY, RESPONSE } )
				byte qr : 1;

				byte rCode : 4;

				byte cd : 1;

				byte ad : 1;

				byte z : 1;

				byte ra : 1;

				// Number of questions. We'll issue 1 question TypeA ClassIN
				byte totalQuestions[2];

				// Number of answers. We'll search for first answer
				// TypeA ClassIN
				byte totalAnswer[2];

				// Number of authorities.
				byte totalAuthority[2];

				// Number of additions.
				byte totalAdditions[2];
			};

			// Retrieve the DNS Header from the given `udp'.
			DNSHeader *DNSGetHeader(UDPHeader *udp);

			//----------------------------------------------------------
			// SRUDP
			//----------------------------------------------------------

			// SRUDP Header.
			typedef struct SRUDPHeader
			{

				// Connect request ( octet lower bit ).
				byte connect : 1;

				// Notify an Ack ( received message `id' ).
				byte ack : 1;

				// Message contains Data.
				byte data : 1;				

				// Request Disconnect.
				byte disconnect : 1;

				// (octet padding)
				byte pad : 4;

				// Sequence identifier. Each ends starts its own transmitted
				// packet with sequence from 0 and increment at each
				// new transmitted packet after it received correspondent
				// acknowledge. At the same time each ends manage a separate
				// rx Id that starts from 0 to state right sequence of
				// incoming packets from the other ends.
				byte id[2];
				
				// This packet data len.
				byte dataLen[2];

				// Data len left that expects over next packets.
				byte dataLenLeft[2];

			};

			// Retrieve the SRUDP header from the given `udp'.
			SRUDPHeader *SRUDPGetHeader(UDPHeader *udp);

			// Set the opcode ( Connect, Ack, Data, Cont, Disconnect, Pad )
			// to zero.
			void SRUDPResetOpCode(SRUDPHeader *srudp);

			// Retrieve the SRUDP data pointer from the given `srudp' packet.
			byte *SRUDPGetData(SRUDPHeader *srudp);

			// Retrieve the SRUDP data length from the given `srudp' packet.
			uint16_t SRUDPPacketDataLength(IPv4Header *ipv4, SRUDPHeader *srudp);

			// Prints SRUDP fields from the given packet.
			void SRUDPPrint(BufferInfo& pkt);

		}

	}

}

#endif
