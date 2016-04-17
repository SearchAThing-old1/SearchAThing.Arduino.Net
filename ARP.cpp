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

#include "EthNet.h"
#include "ARP.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			//===============================================================
			// PUBLIC
			//===============================================================					

			void ARPRespondProcess::LoopProcessImpl(EthNet *net)
			{
				BufferInfo& pkt = net->Packet();

				Eth2Header *eth2;
				auto arp = net->PacketGetARP(&eth2);
				if (arp == NULL) return;

				if (BufReadUInt16_t(arp->hwType) != ARPType::ARPType_Ethernet ||
					BufReadUInt16_t(arp->opCode) != ARPOpcodeType::ARPOpCodeType_Request ||
					!net->IpAddress().Equals(ARPDestinationProtocolAddress(arp), 4)) return;

				{
#if defined DEBUG && defined DEBUG_ARP
					DPrintln(F("ARP req match"));
#endif

					net->RxMatched();

					// eth2 : set src/dst macs
					{
						memcpy(eth2->dstMAC, eth2->srcMAC, IPV4_MACSIZE);
						memcpy(eth2->srcMAC, net->MacAddress().ConstBuf(), IPV4_MACSIZE);
					}

					// arp : hardware address
					{
						auto hwLen = arp->hwAddrLength;

						memcpy(ARPDestinationHardwareAddress(arp), ARPSourceHardwareAddress(arp), hwLen);
						memcpy(ARPSourceHardwareAddress(arp), net->MacAddress().ConstBuf(), hwLen);
					}

					// arp : protocol address
					{
						auto pLen = arp->protoAddrLength;

						memcpy(ARPDestinationProtocolAddress(arp), ARPSourceProtocolAddress(arp), pLen);
						memcpy(ARPSourceProtocolAddress(arp), net->IpAddress().ConstBuf(), pLen);
					}

					// arp : set opcode to reply
					ARPSetOpCodeType(arp, ARPOpcodeType::ARPOpCodeType_Reply);

					pkt.SetLength(sizeof(Eth2Header) + ARPSize(arp));

					net->Transmit();

#if defined DEBUG && defined DEBUG_ARP
					DPrint(F("sent ARP reply")); DNewline();
#endif
				}
			}

		}

	}

}