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

#include "Protocol.h"
#include "Checksum.h"
#include "EthDriver.h"
#include "EthNet.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			//----------------------------------------------------------
			// Utils
			//----------------------------------------------------------

			// https://en.wikipedia.org/wiki/MAC_address
			RamData PrivateMACAddress(byte lsb)
			{
				// 00:00:6C:xx:xx:xx - "Private" range that is Unicast / Local Admin

				// we use 00:00:6C:00:00:xx (where xx = lsb arg)
				return RamData::FromArray(IPV4_MACSIZE, 0x00, 0x00, 0x6C, 0x00, 0x00, lsb);
			}

			//----------------------------------------------------------
			// Eth2
			//----------------------------------------------------------

			Eth2Type Eth2GetType(Eth2Header *eth2)
			{
				auto type = BufReadUInt16_t(eth2->type);
				switch (type)
				{
					case Eth2Type::Eth2Type_IP: return Eth2Type_IP;
					case Eth2Type::Eth2Type_ARP: return Eth2Type_ARP;
					default: return Eth2Type_UNK;
				}
			}

			Eth2Header *Eth2GetHeader(byte *pkt)
			{
				return (Eth2Header *)pkt;
			}

			void Eth2Fill(const EthNet *net, Eth2Header *eth2, Eth2Type type)
			{
				memcpy(eth2->srcMAC, net->MacAddress().ConstBuf(), IPV4_MACSIZE);
				BufWrite16(eth2->type, type);
			}

			void Eth2Print(Eth2Header *eth2)
			{
				DPrint(F("ETH2"));
				DPrint(F(" d:")); DPrintHex(eth2->dstMAC, IPV4_MACSIZE);
				DPrint(F(" s:")); DPrintHex(eth2->srcMAC, IPV4_MACSIZE);
				DPrint(F(" t:")); DPrintHex(eth2->type, 2);
				DNewline();
			}

			//----------------------------------------------------------
			// ARP
			//----------------------------------------------------------

			ARPHeader *ARPGetHeader(Eth2Header *eth2)
			{
				return (ARPHeader *)((byte *)eth2 + sizeof(Eth2Header));
			}

			void ARPSetOpCodeType(ARPHeader *arp, ARPOpcodeType type)
			{
				BufWrite16(arp->opCode, type);
			}

			byte *ARPSourceHardwareAddress(ARPHeader *arp)
			{
				return (byte *)arp + sizeof(ARPHeader);
			}

			byte *ARPSourceProtocolAddress(ARPHeader *arp)
			{
				return ARPSourceHardwareAddress(arp) + arp->hwAddrLength;
			}

			byte *ARPDestinationHardwareAddress(ARPHeader *arp)
			{
				return ARPSourceProtocolAddress(arp) + arp->protoAddrLength;
			}

			byte *ARPDestinationProtocolAddress(ARPHeader *arp)
			{
				return ARPDestinationHardwareAddress(arp) + arp->hwAddrLength;
			}

			uint16_t ARPSize(ARPHeader *arp)
			{
				return sizeof(ARPHeader) +
					arp->hwAddrLength * 2 +
					arp->protoAddrLength * 2;
			}

			void ARPFill(const EthNet *net, ARPHeader *arp, ARPOpcodeType opCode)
			{
				BufWrite16(arp->hwType, ARPType::ARPType_Ethernet);
				BufWrite16(arp->protoType, ARPProtocolType::ARPProtocolType_IP);
				arp->hwAddrLength = IPV4_MACSIZE;
				arp->protoAddrLength = IPV4_IPSIZE;
				BufWrite16(arp->opCode, opCode);
				memcpy(ARPSourceHardwareAddress(arp), net->MacAddress().ConstBuf(), IPV4_MACSIZE);
				memcpy(ARPSourceProtocolAddress(arp), net->IpAddress().ConstBuf(), IPV4_IPSIZE);
			}

			void ARPPrint(ARPHeader *arp)
			{
				DPrint(F("ARP"));
				DPrint(F(" hwt:")); DPrintHex(arp->hwType, 2);
				DPrint(F(" prt:")); DPrintHex(arp->protoType, 2);
				DPrint(F(" hwl:")); DPrint(arp->hwAddrLength);
				DPrint(F(" prl:")); DPrint(arp->protoAddrLength);
				DPrint(F(" opc:")); DPrintHex(arp->opCode, 2);
				DPrint(F(" shw:")); DPrintHex(ARPSourceHardwareAddress(arp), arp->hwAddrLength);
				DPrint(F(" spr:")); DPrintBytes(ARPSourceProtocolAddress(arp), arp->protoAddrLength);
				DPrint(F(" dhw:")); DPrintHex(ARPDestinationHardwareAddress(arp), arp->hwAddrLength);
				DPrint(F(" dpr:")); DPrintBytes(ARPDestinationProtocolAddress(arp), arp->protoAddrLength);
				DNewline();
			}

			//----------------------------------------------------------
			// IPv4
			//----------------------------------------------------------

			IPv4Header *IPv4GetHeader(Eth2Header *hdr)
			{
				return (IPv4Header *)((byte *)hdr + sizeof(Eth2Header));
			}

			void IPv4WriteValidChecksum(IPv4Header *ipv4)
			{
				memset(ipv4->chksum, 0, 2);
				auto ipv4Size = ipv4->ihl * 4;
				auto chksum = CheckSum((byte *)ipv4, ipv4Size);
				BufWrite16(ipv4->chksum, chksum);
			}

			void IPv4Fill(const EthNet *net, IPv4Header *ipv4, uint16_t ipv4Len, IPv4Type type)
			{
				ipv4->ihl = sizeof(IPv4Header) / 4; // hdr len=20
				ipv4->version = 4; // ip v4
				ipv4->services = 0;
				BufWrite16(ipv4->totalLength, ipv4Len);
				ipv4->flags = 0;
				ipv4->fragmentOffsetH = 0; ipv4->fragmentOffsetL = 0;
				ipv4->ttl = IPV4_TTL;
				ipv4->protocol = type;
				if (net->IpAddress().Size() > 0) memcpy(ipv4->srcip, net->IpAddress().ConstBuf(), IPV4_IPSIZE);
			}

			void IPv4Print(IPv4Header *ipv4)
			{
				DPrint(F("IPv4"));
				DPrint(F(" ver:")); DPrint(ipv4->version);
				DPrint(F(" hln:")); DPrint(ipv4->ihl * 4);
				DPrint(F(" dsv:")); DPrint(ipv4->services);
				DPrint(F(" totl:")); DPrint(BufReadUInt16_t(ipv4->totalLength));
				DPrint(F(" ide:")); DPrint(BufReadUInt16_t(ipv4->identification));
				DPrint(F(" flg:")); DPrint(ipv4->flags);
				DPrint(F(" fro:")); DPrint((uint16_t)ipv4->fragmentOffsetH << 8 | ipv4->fragmentOffsetL);
				DPrint(F(" ttl:")); DPrint(ipv4->ttl);
				DPrint(F(" pro:")); DPrint(ipv4->protocol);
				DPrint(F(" chk:")); DPrint(BufReadUInt16_t(ipv4->chksum));
				DPrint(F(" sip:")); DPrintBytes(ipv4->srcip, IPV4_IPSIZE);
				DPrint(F(" dip:")); DPrintBytes(ipv4->dstip, IPV4_IPSIZE);
				DNewline();
			}

			//----------------------------------------------------------
			// ICMP
			//----------------------------------------------------------

			ICMPHeader *ICMPGetHeader(IPv4Header *ipv4)
			{
				return (ICMPHeader *)((byte *)ipv4 + (ipv4->ihl * 4));
			}

			ICMPType ICMPGetType(ICMPHeader *icmp)
			{
				return (ICMPType)icmp->type;
			}

			void ICMPWriteValidChecksum(IPv4Header *ipv4, ICMPHeader *icmp)
			{
				memset(icmp->chksum, 0, 2);
				auto icmpSize = BufReadUInt16_t(ipv4->totalLength) - ipv4->ihl * 4;
				auto chksum = CheckSum((byte *)icmp, icmpSize);
				BufWrite16(icmp->chksum, chksum);
			}

			void ICMPPrint(ICMPHeader *icmp)
			{
				DPrint(F("ICMP"));
				DPrint(F(" t:")); DPrint(icmp->type);
				DPrint(F(" c:")); DPrint(icmp->code);
				DPrint(F(" chk:")); DPrint(BufReadUInt16_t(icmp->chksum));
				DNewline();
			}

			//----------------------------------------------------------
			// UDP
			//----------------------------------------------------------

			UDPHeader *UDPGetHeader(IPv4Header *ipv4)
			{
				return (UDPHeader *)((byte *)ipv4 + (ipv4->ihl * 4));
			}

			byte *UDPGetData(UDPHeader *udp)
			{
				return ((byte *)udp) + sizeof(UDPHeader);
			}

			void UDPWriteValidChecksum(IPv4Header *ipv4, UDPHeader *udp)
			{
				memset(udp->chksum, 0, 2);

				// http://www.tcpipguide.com/free/t_UDPMessageFormat-2.htm
				uint32_t sum = 0;
				sum = CheckSumPartial(sum, ipv4->srcip, sizeof(ipv4->srcip));
				sum = CheckSumPartial(sum, ipv4->dstip, sizeof(ipv4->dstip));
				{
					byte x[2] = { 0, ipv4->protocol };
					sum = CheckSumPartial(sum, x, 2);
				}
				sum = CheckSumPartial(sum, udp->length, 2);
				sum = CheckSumPartial(sum, (byte *)udp, BufReadUInt16_t(ipv4->totalLength) - ipv4->ihl * 4, true);
				BufWrite16(udp->chksum, CheckSumFinalize(sum));
			}

			void UDPFill(UDPHeader *udp, uint16_t srcPort, uint16_t dstPort, uint16_t len)
			{
				BufWrite16(udp->sourcePort, srcPort);
				BufWrite16(udp->destPort, dstPort);
				BufWrite16(udp->length, len);
			}

			void UDPPrint(UDPHeader *udp)
			{
				DPrint(F("UDP"));
				DPrint(F(" sp:")); DPrint(BufReadUInt16_t(udp->sourcePort));
				DPrint(F(" dp:")); DPrint(BufReadUInt16_t(udp->destPort));
				DPrint(F(" len:")); DPrint(BufReadUInt16_t(udp->length));
				DPrint(F(" chk:")); DPrint(BufReadUInt16_t(udp->chksum));
				DNewline();
			}

			//----------------------------------------------------------
			// DHCP
			//----------------------------------------------------------

			byte DHCPMagicCookie[] = { 0x63, 0x82, 0x53, 0x63 };

			DHCPHeader *DHCPGetHeader(UDPHeader *udp)
			{
				return (DHCPHeader *)((byte *)udp + sizeof(UDPHeader));
			}

			void DHCPSetMagicCookie(DHCPHeader *dhcp)
			{
				memcpy(dhcp->magic, DHCPMagicCookie, DHCPMagicCookieSIZE);
			}

			byte *DHCPGetOptions(DHCPHeader *dhcp)
			{
				return ((byte *)dhcp) + sizeof(DHCPHeader);
			}

			bool DHCPMatchesOption(IPv4Header *ipv4, UDPHeader *udp, DHCPHeader *dhcp, BufferInfo optionInfo)
			{
				auto res = DHCPLocateOption(ipv4, udp, dhcp, optionInfo.Buf()[0]);
				if (res == NULL) return false;
				byte l = optionInfo.Buf()[1] + 1; // +1 to match length too
				const byte *buf = optionInfo.Buf();
				++res; ++buf;
				do
				{
					if (*buf != *res) return false;
					++res; ++buf;
					--l;
				} while (l);

				return true;
			}

			byte *DHCPLocateOption(IPv4Header *ipv4, UDPHeader *udp, DHCPHeader *dhcp, byte option)
			{
				auto optionLenMax = BufReadUInt16_t(ipv4->totalLength) -
					sizeof(IPv4Header) - sizeof(UDPHeader) - sizeof(DHCPHeader);

				byte *opt = ((byte *)dhcp) + sizeof(DHCPHeader);
				auto optEnd = opt + (optionLenMax - 1);

				while (opt <= optEnd)
				{
					if (*opt == option)
					{
						return opt;
					}
					else if (*opt == DHCPOption::DHCPOptionEnd) break;
					else
					{
						++opt; // skip opcode

						auto l = *opt; // len
						++opt;

						while (l) { ++opt; --l; } // skip option data
					}
				}

				return NULL;
			}

			//----------------------------------------------------------
			// DNS
			//----------------------------------------------------------

			DNSHeader *DNSGetHeader(UDPHeader *udp)
			{
				return (DNSHeader *)((byte *)udp + sizeof(UDPHeader));
			}

			//----------------------------------------------------------
			// SRUDP
			//----------------------------------------------------------

			SRUDPHeader *SRUDPGetHeader(UDPHeader *udp)
			{				
				return (SRUDPHeader *)((byte *)udp + sizeof(UDPHeader));
			}

			void SRUDPResetOpCode(SRUDPHeader *srudp)
			{
				srudp->pad = 0;
				srudp->disconnect = 0;				
				srudp->data = 0;
				srudp->ack = 0;
				srudp->connect = 0;
			}

			byte *SRUDPGetData(SRUDPHeader *srudp)
			{
				return ((byte *)srudp) + sizeof(SRUDPHeader);
			}

			uint16_t SRUDPPacketDataLength(IPv4Header *ipv4, SRUDPHeader *srudp)
			{
				return BufReadUInt16_t(ipv4->totalLength) -
					sizeof(IPv4Header) -
					sizeof(UDPHeader) -
					sizeof(SRUDPHeader);
			}

			void SRUDPPrint(BufferInfo& pkt)
			{
				auto eth2 = Eth2GetHeader(pkt.Buf());
				auto ipv4 = IPv4GetHeader(eth2);
				auto udp = UDPGetHeader(ipv4);
				auto srudp = SRUDPGetHeader(udp);

				DPrint(F("SRUDP type:"));
				if (srudp->connect) DPrint(F("CONNECT"));
				if (srudp->data)
				{
					DPrint(F("DATA"));					
				}
				if (srudp->ack) DPrint(F("ACK"));
				if (srudp->disconnect) DPrint(F("DISCONNECT"));

				DPrint(F(" id:")); DPrint(BufReadUInt16_t(srudp->id));

				if (srudp->data)
				{
					DPrint(F(" data=["));
					auto datasize = BufReadUInt16_t(srudp->dataLen);
					auto dataptr = SRUDPGetData(srudp);
					while (datasize)
					{
						DPrint((char)(*dataptr));
						++dataptr;
						--datasize;
					}
					DPrint(F("]"));
				}
			}

		}

	}

}

