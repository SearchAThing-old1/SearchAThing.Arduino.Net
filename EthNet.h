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

#ifndef _SEARCHATHING_ARDUINO_NET_ETH_NET_H
#define _SEARCHATHING_ARDUINO_NET_ETH_NET_H

#if defined(ARDUINO) && ARDUINO >= 100
#include "arduino.h"
#else
#include "WProgram.h"
#endif

#include <SearchAThing.Arduino.Utils\DebugMacros.h>

#include <SearchAThing.Arduino.Utils\SList.h>
#include <SearchAThing.Arduino.Utils\BufferInfo.h>
#include <SearchAThing.Arduino.Utils\IdStorage.h>
#include <SearchAThing.Arduino.Utils\RamData.h>
#include "EthDriver.h"
#include "EthProcess.h"
#include "Protocol.h"
#include "ARP.h"
#include "DHCP.h"
#include "ICMP.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			// Network subsystem ephemeral port allocator start number.
			// See: https://en.wikipedia.org/wiki/Ephemeral_port
			const int EPHEMERAL_PORT_START = 49152;

			// Maximum size of rx/tx packets.
			const uint16_t PACKET_SIZE = 600;

			// Ethernet subsystem.
			//---------------------------------------------------------------
			// Interact with an ethernet card driver that has to be passed
			// as argument at the construct-time.
			//
			// Manages basic networking informations such as:
			// - network card mac-address
			// - ipaddress, netmask, gateway, broadcast, dns
			// - networkAddress ( recomputed when ip or netmask changes )
			//
			// Supplies utilities functions such as ResolveIp(name) and
			// ResolveMAC(ip).
			//
			// Allocate a unique packet storage ( default PACKET_SIZE )
			// that the driver will use as buffer for reading data to
			// transmit and to store received data.
			//
			// Checks for every registered `EthProc' process during the main
			// maintenance routine loop that can be established this way:
			// void loop() { eth->Receive(); eth->FlushRx(); }
			// Provides bundle processes to manage ARP respond, ICMP respond,
			// and DHCP client.
			//
			// Allow synchronous processes ( eg. ResolveIp(name) ) when in a
			// user while loop is ensured a FlushRx() function to be called
			// before the loop restart to flush out received data to other
			// registered processes.
			//
			// Provides caching of the gateway and dns MACs.
			//
			// Provides allocation/release of ephemeral ports.
			//
			// Facilities function to extract various headers such as:
			// Eth2, ARP, IPv4, UDP, ICMP, DHCP, DNS
			//
			// Note: This object should be allocated dynamically, once, using
			// a pointer. ( eg. EthNet *net = new EthNet() ).			
			class EthNet
			{

			private:			
				RamData hostname;
				RamData domainName;

				RamData ipAddress;
				RamData netmask;
				RamData networkAddress;
				RamData gateway;
				RamData broadcastAddress;
				RamData dns;

				RamData gatewayMAC;
				bool gatewayResolved = false;

				RamData dnsMAC;
				bool dnsResolved = false;

				bool pktChanged = true;
				bool rxHandled = true;
				BufferInfo pkt;

				ARPRespondProcess arpRespondProc;
				ICMPRespondProcess icmpRespondProc;
				DhcpClientProcess *dhcpClientProc;
				SList<EthProcess *> ethProcs;
				IdStorage ephemeralPorts = IdStorage(EPHEMERAL_PORT_START);

				// Allocates ram for the unique packet used both for rx/tx.
				void InitPacket(uint16_t packetSize);

				// Add default ARP/ICMP respond processes to the network
				// subsystem processes.
				void InitDefaultProcesses();

				// Network subsystem loop until registered DHCP process
				// sets a valid IP address.
				void WaitDHCP();

				// Sweep over all registered ethernet subsystem processes
				// to evaluate current received packet and/or to do
				// maintenance tx actions ( eg. DHCP request renew ).
				void EvalRegisteredProcesses();

				// Recompute the netmask address to allow faster match
				// of ip route through the IsInSubnet().
				void RecomputeNetworkAddress();

			public:
				// Constructor for DHCP mode initialization.
				// Allocates a unique buffer packet of the given `packetSize'
				EthNet(EthDriver *_drv, uint16_t packetSize = PACKET_SIZE);

				// Constructor for STATIC ip mode initialization.
				// Allocates a unique buffer packet of the given `packetSize'
				EthNet(EthDriver *_drv, const RamData& _ipAddress, uint16_t packetSize = PACKET_SIZE);

				// Destructor. Release unique packet resources.
				~EthNet();

				EthDriver *drv;

				// MAC address programmed into the ethernet driver.
				const RamData& MacAddress() const;

				// Hostname (read-write). It will be assigned if provided
				// by the DHCP server when using DHCP mode initialization.
				RamData& Hostname();

				// DomainName (read-write). It will be assigned if provided
				// by the DHCP server when using DHCP mode initialization.
				RamData& DomainName();

				// Ip address
				const RamData& IpAddress() const;

				// Netmask (read-only). Assigned by the DHCP server or use
				// SetNetmask to change when STATIC mode.
				const RamData& Netmask() const;

				// NetworkAddress (read-only). Computed automatically when
				// Ip or Netmask changes.
				const RamData& NetworkAddress() const;

				// Gateway (read-only). Assigned by the DHCP server or use
				// SetGateway to change when STATIC mode.
				// This will be used when an ip address not fall in the
				// current network address ( IsInSubnet() ).
				const RamData& Gateway() const;

				// Broadcast address (read-only). Assigned by the DHCP server
				// or use SetBroadcastAddress to change when STATIC mode.
				const RamData& BroadcastAddress() const;

				// Dns address (read-only). Assigned by the DHCP server or
				// use SetDns to change when STATIC mode.
				// This will be used to know which dns server can respond
				// for the ResolveIp(name) function
				const RamData& Dns() const;

				// Sets the ipaddress. See also: disableDhcpRenewal
				void SetIpAddress(const RamData& newIpAddress);

				// Sets the netmask. See also: disableDhcpRenewal
				void SetNetmask(const RamData& newNetmask);

				// Sets the gateway. See also: disableDhcpRenewal
				void SetGateway(const RamData& newGateway);

				// Sets broadcastAddress. See also: disableDhcpRenewal
				void SetBroadcastAddress(const RamData& newBroadcastAddress);

				// Sets the dns. See also: disableDhcpRenewal
				void SetDns(const RamData& newDns);

				// When initialization was in dynamic mode sets this to true
				// to disactivate automatic dhcp renewal if want to pass
				// in static mode to avoid overwrite of settings.
				bool disableDhcpRenewal = false;

				// Prints current network settings.
				void PrintSettings();

				// States if the given ip address fall in the current subnet.
				bool IsInSubnet(const RamData& ip) const;

				// Retrieve the MAC address for the given ip target using an
				// ARP request.
				RamData ResolveMAC(const RamData& ip);

				// Retrieve the IP address for the given name target using a
				// DNS request.
				RamData ResolveIP(const RamData& name);

				// Retrieve cached MAC address of the gateway.
				const RamData& GatewayMAC();

				// Retrieve cached MAC address of the dns.
				const RamData& DNSMAC();

				// List of all registered ethernet processes.
				SList<EthProcess *>& AllProcesses();

				// Add a custom ethernet process to the subsystem.
				// See also: EthProcess and ARPRespondProcess as example.
				void AddProcess(EthProcess& ethProcess);

				// Remove registered process from the subsystem. Given
				// reference variable must be the same used when adding.
				// See also: EthProcess and ARPRespondProcess as example.
				void DelProcess(EthProcess& ethProcess);

				// Retrieve next or reuse a previously freed ephemeral port.
				uint16_t AllocEphemeralPort();

				// Release a previously allocated ephemeral port. If an
				// invalid port is given then no actions results.
				void ReleaseEphermeralPort(uint16_t port);

				//--

				// Current unique packet buffer. It is a RamData with a
				// capacity equals to the size specified at EthNet construct.
				BufferInfo& Packet();				

				// Invoke receive packet from the driver if the current
				// packet results already processed otherwise it left the
				// current received packet unchanged, until an RxMatched()
				// states it has been processed or a FlushRx() flush out
				// the received packet after trying to process it with the
				// registered handlers.
				// Note:
				// - After a Receive() function evaluation calls RxMatched()
				//   if the packet matched your requirements, elsewhere
				//   continue processing of the packet using the FlushRx()
				//   to allow registered process evaluate the packet.
				// - From inside a LoopProcess() the first Receive() is
				//   already ensured by the process manager and if the packet
				//   not meet requirements there is not need to call FlushRx
				//   because the process manager already provides to flush 
				//   unmanaged packets after each process executed.
				void Receive();

				// Mark the current packet as processed. This is a helper
				// function to interact with the packet process queue to
				// inform other processes that a next packet need to be
				// gathered from new by an hardware receive. Elsewhere the
				// same ram packet will be reused.
				void RxMatched();

				bool IsRxMatched() const;

				// Checks if the current packet has been matched, elsewhere
				// try with registered processes and finally if not matched
				// discard the packet.
				void FlushRx();				

				// Transmit current packet.
				// Before call transmit invoke:
				// - RxMatched() if previously received packet meet your
				//   requirements.
				// - FlushRx() if previously received packet does not meet
				//   any requirements to allow other process evaluate.
				// This allow you to overwrite the packet with transmit data
				// avoid to loose any previous received packet.
				bool Transmit();

				// Utility function that mark internally the unique packet.
				// This function could be used just after a packet tx to
				// mark your current packet and know in a successive loop
				// if the FlushRx reused the packet changing it for other
				// subsystem process purpose. This way you know if you need
				// to rebuild the packet. For example you can check with
				// PacketChanged() function that if the packet wasn't changed
				// after your tx you can avoid to rebuild some headers infos.				
				void MarkPacket();

				// States if the packet changed due to a rx/tx after it has
				// been reset with MarkPacket().
				bool PacketChanged() const;

				// Extract the EthII header from the current packet.
				Eth2Header *PacketGetEth2(Eth2Type type);

				// Extracts the ARP header (if any) from the current packet.
				// If it was an ARP packet a non-NULL pointer return the ARP
				// packet header. If optional parameters was specified, they
				// will be filled with intermediate preceding headers.
				ARPHeader *PacketGetARP(Eth2Header **outEth2 = NULL);

				// Extracts the IPv4 header (if any) from the current packet.
				// If it was an IPv4 packet a non-NULL pointer return the
				// IPv4 packet header. If optional parameters was specified,
				// they will be filled with intermediate preceding headers.
				IPv4Header *PacketGetIPv4(IPv4Type type, Eth2Header **outEth2 = NULL);

				// Extracts the UDP header (if any) from the current packet.
				// If it was an UDP packet a non-NULL pointer return the UDP
				// packet header. If optional parameters was specified, they
				// will be filled with intermediate preceding headers.
				UDPHeader *PacketGetUDP(Eth2Header **outEth2 = NULL, IPv4Header **outIpv4 = NULL);

				// Extracts the ICMP header (if any) from the current packet.
				// If it was an ICMP packet a non-NULL pointer return the
				// ICMP packet header. If optional parameters was specified,
				// they will be filled with intermediate preceding headers.
				ICMPHeader *PacketGetICMP(Eth2Header **outEth2 = NULL, IPv4Header **outIpv4 = NULL);

				// Extracts the DHCP header (if any) from the current packet.
				// If it was an DHCP packet a non-NULL pointer return the
				// DHCP packet header. If optional parameters was specified,
				// they will be filled with intermediate preceding headers.
				DHCPHeader *PacketGetDHCP(Eth2Header **outEth2 = NULL, IPv4Header **outIpv4 = NULL, UDPHeader **outUDP = NULL);

				// Extracts the DNS header (if any) from the current packet.
				// If it was an DNS packet a non-NULL pointer return the DNS
				// packet header. If optional parameters was specified, they
				// will be filled with intermediate preceding headers.
				DNSHeader *PacketGetDNS(Eth2Header **outEth2 = NULL, IPv4Header **outIpv4 = NULL);

			};

		}

	}

}

#endif
