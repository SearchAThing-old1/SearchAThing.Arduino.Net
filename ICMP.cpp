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
#include <SearchAThing.Arduino.Utils\Util.h>

#include "ICMP.h"
#include "EthNet.h"
#include "Protocol.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{			

			void ICMPRespondProcess::LoopProcessImpl(EthNet *net)
			{				
				if (net->IpAddress().Size() == 0) return;

				BufferInfo& pkt = net->Packet();

				Eth2Header *eth2;
				IPv4Header *ipv4;
				auto icmp = net->PacketGetICMP(&eth2, &ipv4);

				if (icmp == NULL || icmp->type != ICMPType::ICMPType_EchoRequest) return;
				
				if (!net->IpAddress().Equals(ipv4->dstip, IPV4_IPSIZE)) return;

				net->RxMatched();

#if defined DEBUG && defined DEBUG_ICMP
				DPrint(F("rx ICMP req")); DNewline();
#endif

				// eth2 : set src/dst macs
				memcpy(eth2->dstMAC, eth2->srcMAC, sizeof(eth2->dstMAC));
				memcpy(eth2->srcMAC, net->MacAddress().ConstBuf(), sizeof(eth2->srcMAC));

				// iv4 : set src/dst ips
				memcpy(ipv4->dstip, ipv4->srcip, sizeof(ipv4->srcip));
				memcpy(ipv4->srcip, net->IpAddress().ConstBuf(), sizeof(ipv4->dstip));

				// icmp : set reply type
				icmp->type = ICMPType::ICMPType_EchoReply;

				ICMPWriteValidChecksum(ipv4, icmp);
				IPv4WriteValidChecksum(ipv4);

				net->Transmit();

#if defined DEBUG && defined DEBUG_ICMP
				DPrint(F("sent ICMP reply")); DNewline();
#endif				
			}

		}

	}

}
