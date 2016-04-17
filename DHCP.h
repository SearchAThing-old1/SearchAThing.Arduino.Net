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

#include <SearchAThing.Arduino.Utils\DebugMacros.h>

#ifndef _SEARCHATHING_ARDUINO_NET_DHCP_H
#define _SEARCHATHING_ARDUINO_NET_DHCP_H

#if defined(ARDUINO) && ARDUINO >= 100
#include "arduino.h"
#else
#include "WProgram.h"
#endif

#include <SearchAThing.Arduino.Utils\RamData.h>
#include <SearchAThing.Arduino.Utils\BufferInfo.h>
#include <SearchAThing.Arduino.Utils\DynamicTimeout.h>

#include "EthDriver.h"
#include "EthProcess.h"
#include "Protocol.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{			

			// Enum type used in the dhcp client process to keep track
			// of current phase.
			typedef enum DhcpClientPhase
			{
				None,
				DiscoverSent,
				RequestSent
			};

			class EthNet;

			// Ethernet process that search a dhcp server in order to
			// configure our network based on our MAC address.
			// After the process configured the network parameters for the
			// first time it will recheck if obtained lease expired and in
			// case it will update dhcp client configuration again.
			// DHCP client configuration informations that will be requested
			// to the DHCP server are:
			// - lease
			// - hostname
			// - domainname
			// - gateway
			// - broadcast
			// - dns
			// - netmask
			class DhcpClientProcess : public EthProcess
			{
				DhcpClientPhase phase = DhcpClientPhase::None;
				unsigned long transactionId;			
				
				DynamicTimeout reqTimeout = DynamicTimeout(REQUEST_TIMEOUT_MS, REQUEST_TIMEOUT_MAX);

				bool renewInProgress = false;

				unsigned long lastRenewTime = 0L;
				// default 10 min (it will be updated by the dhcp ack)
				unsigned long leaseExpireTimeDiffMs = 10L * 60 * 1000;

				void DhcpSendReq(EthNet *net,
					const BufferInfo& dhcpOptions, const byte *srcIP = NULL, const byte *dstMAC = NULL, const byte *srvIP = NULL);

				bool DhcpReplyMatchMy(Eth2Header *eth2, IPv4Header *ipv4, UDPHeader *udp, DHCPHeader *dhcp, const BufferInfo& opts) const;

			public:
				// Contructor. Initializes the transactionId.
				DhcpClientProcess();

				// Checks if the current dhcp client config has expired.
				bool LeaseExpired() const;
				
				// Ethernet loop process.
				void LoopProcessImpl(EthNet *net);

				// States if the dhcp client is configuring.
				bool Busy() const;

				// Retrieve current lease time (ms).
				unsigned long CurrentLease() const;

			};

		}

	}

}

#endif
