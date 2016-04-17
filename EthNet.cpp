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
#include "Protocol.h"
#include "ARP.h"
#include "DNS.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			//----------------------------------------------------------
			// private
			//----------------------------------------------------------

			void EthNet::InitPacket(uint16_t packetSize)
			{
				byte *buf = new byte[packetSize];
				if (buf == NULL)
				{
#if defined DEBUG && defined DEBUG_ASSERT
					DPrint(F("* Fatal: out of memory, need block of ")); DPrint(packetSize); DNewline();
#endif
				}
				pkt = BufferInfo(buf, packetSize);
			}

			void EthNet::InitDefaultProcesses()
			{
				AddProcess(arpRespondProc);
				AddProcess(icmpRespondProc);
			}

			void EthNet::WaitDHCP()
			{
				while (ipAddress.Size() == 0)
				{
					dhcpClientProc->LoopProcess(this);
					FlushRx();
				}
			}

			void EthNet::EvalRegisteredProcesses()
			{
				auto node = ethProcs.GetNode(0);

				while (node != NULL)
				{
					if (dhcpClientProc != NULL && disableDhcpRenewal && node->data == dhcpClientProc) continue;

					// call the custom loop process
					node->data->LoopProcess(this);

					node = node->next;
				}
			}

			void EthNet::RecomputeNetworkAddress()
			{
				if (ipAddress.Size() == IPV4_IPSIZE && netmask.Size() == IPV4_IPSIZE)
				{
					networkAddress = ipAddress.And(netmask);
					gatewayResolved = false;
					dnsResolved = false;
				}
			}

			//----------------------------------------------------------
			// public
			//----------------------------------------------------------

			EthNet::EthNet(EthDriver *_drv, const RamData& _ipAddress, uint16_t packetSize)
			{
				drv = _drv;

				InitPacket(packetSize);

				ipAddress = _ipAddress;

				InitDefaultProcesses();
			}

			EthNet::EthNet(EthDriver *_drv, uint16_t packetSize)
			{
				drv = _drv;

				InitPacket(packetSize);

				dhcpClientProc = new DhcpClientProcess();
				AddProcess(*dhcpClientProc);
				WaitDHCP();

				InitDefaultProcesses();
			}

			EthNet::~EthNet()
			{
				if (dhcpClientProc != NULL) delete dhcpClientProc;

				if (pkt.Buf() != NULL) delete pkt.Buf();
			}

			//		EthDriver *EthNet::Driver() { return drv; }

			const RamData& EthNet::MacAddress() const { return drv->MacAddress(); }

			RamData& EthNet::Hostname() { return hostname; }
			RamData& EthNet::DomainName() { return domainName; }

			const RamData& EthNet::IpAddress() const { return ipAddress; }
			const RamData& EthNet::Netmask() const { return netmask; }
			const RamData& EthNet::NetworkAddress() const { return networkAddress; }
			const RamData& EthNet::Gateway() const { return gateway; }
			const RamData& EthNet::BroadcastAddress() const { return broadcastAddress; }
			const RamData& EthNet::Dns() const { return dns; }

			void EthNet::SetIpAddress(const RamData& newIpAddress)
			{
				ipAddress = newIpAddress;
				RecomputeNetworkAddress();
			}

			void EthNet::SetNetmask(const RamData& newNetmask)
			{
				netmask = newNetmask;
				RecomputeNetworkAddress();
			}

			void EthNet::SetGateway(const RamData& newGateway)
			{
				gatewayResolved = false;
				gateway = newGateway;
			}

			void EthNet::SetBroadcastAddress(const RamData& newBroadcastAddress)
			{
				broadcastAddress = newBroadcastAddress;
			}

			void EthNet::SetDns(const RamData& newDns)
			{
				dns = newDns;
				dnsResolved = false;
			}

			void EthNet::PrintSettings()
			{
				if (IpAddress().Size() > 0) { DPrint(F("IP\t")); DPrintBytes(IpAddress().ConstBuf(), IPV4_IPSIZE); DNewline(); }
				if (Hostname().Size() > 0) { DPrint(F("HOST\t")); Hostname().PrintAsChars(); DNewline(); }
				if (DomainName().Size() > 0) { DPrint(F("DOMAIN\t")); DomainName().PrintAsChars(); DNewline(); }
				if (Gateway().Size() > 0) { DPrint(F("GW\t")); DPrintBytes(Gateway().ConstBuf(), IPV4_IPSIZE); DNewline(); }
				if (BroadcastAddress().Size() > 0) { DPrint(F("BRD\t")); DPrintBytes(BroadcastAddress().ConstBuf(), IPV4_IPSIZE); DNewline(); }
				if (Dns().Size() > 0) { DPrint(F("DNS\t")); DPrintBytes(Dns().ConstBuf(), IPV4_IPSIZE); DNewline(); }
				if (Netmask().Size() > 0) { DPrint(F("NM\t")); DPrintBytes(Netmask().ConstBuf(), IPV4_IPSIZE); DNewline(); }
				if (dhcpClientProc != NULL)
				{
					DPrint(F("LEASE\t")); DPrint((uint16_t)(dhcpClientProc->CurrentLease() / 1000L)); DPrint(F(" (secs)"));
				}
				DNewline();
			}

			bool EthNet::IsInSubnet(const RamData& ip) const
			{
				return IpAddress().And(Netmask()).Equals(networkAddress);
			}

			RamData EthNet::ResolveMAC(const RamData& ip)
			{
				RamData mac;

				if (ip.Size() != IPV4_IPSIZE)
				{
#if defined DEBUG && defined DEBUG_ARP
					DPrintln(F("* invalid ip given"));
#endif
					return mac;
				}

				auto requestSent = false;
				bool answered = false;
				auto reqTimeout = DynamicTimeout(REQUEST_TIMEOUT_MS, REQUEST_TIMEOUT_MAX);

				while (!answered)
				{
					auto timedout = reqTimeout.Expired();

					if (timedout)
					{
#if defined DEBUG && defined DEBUG_ARP
						DPrint(F("ARP timeout")); DNewline();
#endif						
						requestSent = false;
					}

#if defined DEBUG && defined DEBUG_ARP
					DPrint(F("reqSent=")); DPrint(requestSent); DPrint(F(" timedout:")); DPrint(timedout); DNewline();
#endif					

					if (!requestSent || timedout)
					{
						FlushRx();

						// send request				
						pkt.SetLength(
							sizeof(Eth2Header) +
							sizeof(ARPHeader) +
							2 * IPV4_MACSIZE +
							2 * IPV4_IPSIZE);

						// eth2
						auto eth2 = (Eth2Header *)pkt.Buf();
						Eth2Fill(this, eth2, Eth2Type::Eth2Type_ARP);
						memset(eth2->dstMAC, 0xff, sizeof(eth2->dstMAC)); // broadcast

						// arp
						auto arp = ARPGetHeader(eth2);
						ARPFill(this, arp, ARPOpcodeType::ARPOpCodeType_Request);
						memset(ARPDestinationHardwareAddress(arp), 0, IPV4_MACSIZE);
						memcpy(ARPDestinationProtocolAddress(arp), ip.ConstBuf(), IPV4_IPSIZE);

#if defined DEBUG && defined DEBUG_ARP
						DPrint(F("sent ARP req to discover mac of ip:")); DPrintBytes(ip.ConstBuf(), ip.Size()); DNewline();
#endif						

						Transmit();

						requestSent = true;
						reqTimeout.Reset();
					}

					Receive();

#if defined DEBUG && defined DEBUG_ARP
					DPrint(F("checking for answ pktsize=")); DPrint(pkt.Length()); DNewline();
#endif

					auto arp = PacketGetARP();

					if (arp != NULL)
					{
						if (BufReadUInt16_t(arp->hwType) == ARPType::ARPType_Ethernet &&
							BufReadUInt16_t(arp->opCode) == ARPOpcodeType::ARPOpCodeType_Reply &&
							// if its an ARP reply for me
							IpAddress().Equals(ARPDestinationProtocolAddress(arp), IPV4_IPSIZE) &&
							MacAddress().Equals(ARPDestinationHardwareAddress(arp), IPV4_MACSIZE))
						{
							mac = RamData(ARPSourceHardwareAddress(arp), IPV4_MACSIZE);
							answered = true;

#if defined DEBUG && defined DEBUG_ARP
							DPrint(F("ARP reply match : mac=")); DPrintHex(mac.ConstBuf(), IPV4_MACSIZE); DNewline();
#endif								

							RxMatched();
						}
					}

					FlushRx();
				}

				return mac;
			}

			RamData EthNet::ResolveIP(const RamData& name)
			{				
				RamData ip;

				if (name.Size() == 0) return ip;

				if (Dns().Size() == 0)
				{
#if defined DEBUG && defined DEBUG_DNS
					DPrint(F("dns server not set")); DNewline();
#endif
					return ip;
				}

				if (Netmask().Size() != IPV4_IPSIZE)
				{
#if defined DEBUG && defined DEBUG_DNS
					DPrintln(F("* invalid netmask"));
#endif
					return ip;
				}

				auto needGateway = IsInSubnet(dns);

				uint16_t QueryType = DNS_QUERY_TYPE_A;

				auto srcport = AllocEphemeralPort();
				auto reqTimeout = DynamicTimeout(REQUEST_TIMEOUT_MS, REQUEST_TIMEOUT_MAX);
				auto reqSent = false;
				auto id = millis();
				auto answered = false;

				while (!answered)
				{
					auto timedout = reqTimeout.Expired();

					auto headersSize = sizeof(Eth2Header) + sizeof(IPv4Header) + sizeof(UDPHeader) + sizeof(DNSHeader);

					if (!reqSent || timedout)
					{
						if (timedout)
						{
							id = millis();
#if defined DEBUG && defined DEBUG_DNS
							DPrint(F("DNS req timeout")); DNewline();
#endif
						}

						FlushRx();

						BufferInfo& pkt = Packet();
						pkt.SetLength(
							headersSize +
							1 + // first token len
							name.Size() +
							1 + // string terminator character						
							2 + // query type
							2 // class
						);

						// eth2	
						auto eth2 = (Eth2Header *)pkt.Buf();
						Eth2Fill(this, eth2, Eth2Type::Eth2Type_IP);
						if (needGateway)
							memcpy(eth2->dstMAC, GatewayMAC().ConstBuf(), IPV4_MACSIZE);
						else
							memcpy(eth2->dstMAC, DNSMAC().ConstBuf(), IPV4_MACSIZE);

						// ipv4
						auto ipv4 = IPv4GetHeader(eth2);
						IPv4Fill(this, ipv4, pkt.Length() - sizeof(Eth2Header), IPv4Type::IPv4Type_UDP);
						memcpy(ipv4->dstip, dns.ConstBuf(), IPV4_IPSIZE);
						IPv4WriteValidChecksum(ipv4); // set valid ipv4 checksum

						// udp
						auto udp = UDPGetHeader(ipv4);
						UDPFill(udp, srcport,
							UDP_PORT_DNS_SERVER, // udp dstport:53 (dns server)
							BufReadUInt16_t(ipv4->totalLength) - (ipv4->ihl * 4)); // len = ipv4->total - ipv4 header length										

						// dns
						auto dns = DNSGetHeader(udp);
						memset(dns, 0, sizeof(DNSHeader));
						BufWrite16(dns->id, id);
						dns->qr = DNS_QR_CODE_QUERY; // query
													 // dns->opCode = 0; // already memset
													 // dns->aa = 0; dns->tc = 0; // already memset
						dns->rd = 1; // request recurse, want directly ips
									 // dns->ra = 0; dns->z = 0; dns->ad = 0; dns->cd = 0; dns->rCode = 0; // already memset
						BufWrite16(dns->totalQuestions, 1);
						// BufWrite16(dns->totalAnswer, 0); // already memset
						// BufWrite16(dns->totalAuthority, 0); // already memset
						// BufWrite16(dns->totalAdditions, 0); // already memset

						{
							byte *data = ((byte *)dns) + sizeof(DNSHeader);

							{
								auto ptr = name.ConstBuf();
								{
									auto j = 0;
									auto lenOff = 0;
									auto size = name.Size();
									while (j < size)
									{
										auto len = 0;
										while (j < size && ((*ptr) != '.'))
										{
											data[lenOff + 1 + len] = *ptr;

											++len;

											++ptr; ++j;
										}
										data[lenOff] = len;

										lenOff += len + 1;

										++ptr; ++j;
									}
								}
							}

							auto i = 1 + name.Size();
							data[i] = 0; // string terminator
							BufWrite16(data + i + 1, QueryType);
							BufWrite16(data + i + 3, DNS_CLASS_IN);
						}

						UDPWriteValidChecksum(ipv4, udp);

						Transmit();

						reqSent = true;
						reqTimeout.Reset();

#if defined DEBUG && defined DEBUG_DNS
						DPrint(F("DNS req sent")); DNewline();
#endif
					}

					Receive();

					// checking for answ
					BufferInfo& pkt = Packet();

					auto dns = PacketGetDNS();
					if (dns != NULL &&
						dns->qr == DNS_QR_CODE_RESPONSE && // check its a resp					
						BufReadUInt16_t(dns->id) == id && // check its same id
						BufReadUInt16_t(dns->totalAnswer) != 0) // check there are answers							
					{
						auto data = ((byte *)dns) + sizeof(DNSHeader);
						auto i = 0;
						auto dataLen = pkt.Length() - headersSize;
						
						RxMatched();

						// skip questions
						{
							auto qCnt = BufReadUInt16_t(dns->totalQuestions);							

							while (qCnt > 0)
							{												
								i = SkipDNSName(data, i, dataLen);								

								if (i == dataLen) // safety check
								{
									answered = true;
#if defined DEBUG && defined DEBUG_ASSERT
									DPrint(F("malformed packet"));
#endif
									break;
								}
								i += 4; // skip query,class

								qCnt--;
							}
						}

						// parse answers
						{
							auto aCnt = BufReadUInt16_t(dns->totalAnswer);							
							while (aCnt > 0)
							{								
								i = SkipDNSName(data, i, dataLen);
								
								if (i == dataLen) // safety check
								{									
									answered = true;
#if defined DEBUG && defined DEBUG_ASSERT
									DPrintln(F("malformed packet"));
#endif									
									break;
								}

								auto aType = BufReadUInt16_t(data + i); i += 2;
								auto aClass = BufReadUInt16_t(data + i); i += 2;
								i += 4; // skip ttl
								auto aLen = BufReadUInt16_t(data + i); i += 2;								

								if (aType == DNS_QUERY_TYPE_A &&
									aClass == DNS_CLASS_IN &&
									aLen == IPV4_IPSIZE)
								{
									// found									
									ip = RamData(data + i, IPV4_IPSIZE);
#if defined DEBUG && defined DEBUG_DNS
									DPrint(F("DNS answer: ")); name.PrintAsChars(); DPrint(F(" is "));
									DPrintBytes(ip.ConstBuf(), IPV4_IPSIZE); DNewline();
#endif
									answered = true;
									break;
								}
								else
									i += aLen;

								--aCnt;
							}
						}
					}

					FlushRx();
				}				

				return ip;
			}

			const RamData& EthNet::GatewayMAC()
			{
				if (!gatewayResolved)
				{
					gatewayMAC = ResolveMAC(gateway);
					gatewayResolved = true;
				}

				return gatewayMAC;
			}

			const RamData& EthNet::DNSMAC()
			{
				if (!dnsResolved)
				{
					dnsMAC = ResolveMAC(dns);
					dnsResolved = true;
				}

				return dnsMAC;
			}
			SList<EthProcess *>& EthNet::AllProcesses()
			{
				return ethProcs;
			}

			void EthNet::AddProcess(EthProcess& ethProcess)
			{
				ethProcs.Add(&ethProcess);
#if defined DEBUG && defined DEBUG_ETH_PROC
				DPrint(F("added eth process")); DNewline();
#endif
			}

			void EthNet::DelProcess(EthProcess& ethProcess)
			{
				int i = 0;
				auto node = ethProcs.GetNode(i);
				while (node != NULL)
				{
					if (node->data == &ethProcess)
						break;

					node = node->next;
					++i;
				}

				if (node != NULL)
				{
					delete node->data;
					ethProcs.Remove(i);
#if defined DEBUG && defined DEBUG_ETH_PROC
					DPrint(F("removed eth process")); DNewline();
#endif					
				}
			}

			uint16_t EthNet::AllocEphemeralPort()
			{
				return ephemeralPorts.Allocate();
			}

			void EthNet::ReleaseEphermeralPort(uint16_t port)
			{
				ephemeralPorts.Release(port);
			}

			// packet buffer
			BufferInfo& EthNet::Packet() { return pkt; }

			// if the packet contains rx data unhandled returns it otherwise it will be replaced with a new one
			// remarks: 
			// - if the rx packet matches your requirements and then was handled call RxMatched
			// - if the Receive was not called from an EthProcess:LoopProcess invoke the RxFlush after packet inspection done				
			// - its not need to call the first Receive at inside an EthProcess::LoopProcess
			void EthNet::Receive()
			{
				// previous received packet not yet processed
				if (!rxHandled)
				{
#if defined DEBUG && defined DEBUG_ETH_RX_VERBOSE
					DPrint(F("prevpkt !proc")); DNewline();
#endif					
					return;
				}

				auto lBefore = pkt.Length();
				auto lAfterRx = drv->Receive(pkt.Buf(), pkt.Capacity());

				if (lAfterRx > 0 || lBefore != lAfterRx)
				{
					pktChanged = true;
					rxHandled = false;
				}

				pkt.SetLength(lAfterRx);
			}

			// mark current rx packet as processed
			void EthNet::RxMatched()
			{
				rxHandled = true;
			}

			bool EthNet::IsRxMatched() const { return rxHandled; }

			// if the packet was not matched then process it with registered handlers
			void EthNet::FlushRx()
			{
				if (!rxHandled && pkt.Length() > 0) EvalRegisteredProcesses();

				if (!rxHandled)
				{
#if defined DEBUG && defined DEBUG_ETH_RX
					DPrint(F("unmanaged rx pkt")); DNewline();
#endif
					RxMatched();
				}
			}

			bool EthNet::Transmit()
			{
#if defined DEBUG && defined DEBUG_ETH_TX
				if (!rxHandled)
				{
					DPrintln(F("* unhandled rx packet before tx"));
					RxMatched();
				}
#endif

				pktChanged = true;

				return drv->Transmit(pkt.ConstBuf(), pkt.Length());
			}

			void EthNet::MarkPacket()
			{
				pktChanged = false;
			}

			bool EthNet::PacketChanged() const
			{
				return pktChanged;
			}

			Eth2Header *EthNet::PacketGetEth2(Eth2Type type)
			{
				if (pkt.Length() > 0)
				{
					auto eth2 = Eth2GetHeader(pkt.Buf());
					if (BufReadUInt16_t(eth2->type) == type) return eth2;
				}
				return NULL;
			}

			ARPHeader *EthNet::PacketGetARP(Eth2Header **outEth2)
			{
				auto eth2 = PacketGetEth2(Eth2Type::Eth2Type_ARP);
				if (eth2 != NULL)
				{
					if (outEth2 != NULL) *outEth2 = eth2;
					return ARPGetHeader(eth2);
				}
				else
					return NULL;
			}

			IPv4Header *EthNet::PacketGetIPv4(IPv4Type type, Eth2Header **outEth2)
			{
				auto eth2 = PacketGetEth2(Eth2Type::Eth2Type_IP);
				if (eth2 != NULL)
				{
					if (outEth2 != NULL) *outEth2 = eth2;
					auto ipv4 = IPv4GetHeader(eth2);
					if (ipv4->protocol == type) return IPv4GetHeader(eth2);
				}

				return NULL;
			}

			UDPHeader *EthNet::PacketGetUDP(Eth2Header **outEth2, IPv4Header **outIpv4)
			{
				auto ipv4 = PacketGetIPv4(IPv4Type::IPv4Type_UDP, outEth2);
				if (outIpv4 != NULL) *outIpv4 = ipv4;
				if (ipv4 != NULL) return UDPGetHeader(ipv4);

				return NULL;
			}

			ICMPHeader *EthNet::PacketGetICMP(Eth2Header **outEth2, IPv4Header **outIpv4)
			{
				auto ipv4 = PacketGetIPv4(IPv4Type::IPv4Type_ICMP, outEth2);
				if (outIpv4 != NULL) *outIpv4 = ipv4;
				if (ipv4 != NULL) return ICMPGetHeader(ipv4);

				return NULL;
			}

			DHCPHeader *EthNet::PacketGetDHCP(Eth2Header **outEth2, IPv4Header **outIpv4, UDPHeader **outUDP)
			{
				auto udp = PacketGetUDP(outEth2, outIpv4);
				if (outUDP != NULL) *outUDP = udp;
				if (BufReadUInt16_t(udp->sourcePort) == UDP_PORT_BOOTP_SERVER) return DHCPGetHeader(udp);

				return NULL;
			}

			DNSHeader *EthNet::PacketGetDNS(Eth2Header **outEth2, IPv4Header **outIpv4)
			{
				auto udp = PacketGetUDP(outEth2, outIpv4);
				if (BufReadUInt16_t(udp->sourcePort) == UDP_PORT_DNS_SERVER) return DNSGetHeader(udp);

				return NULL;
			}

		}

	}

}
