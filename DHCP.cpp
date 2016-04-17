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

#include <MemoryFree\MemoryFree.h>

#include "DHCP.h"

#include "Protocol.h"
#include "EthDriver.h"
#include "EthNet.h"

#include <SearchAThing.Arduino.Utils\Util.h>
#include <SearchAThing.Arduino.Utils\RamData.h>
#include <SearchAThing.Arduino.Utils\BufferInfo.h>

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			//---------------------------------------------------------------
			// private
			//---------------------------------------------------------------

			void DhcpClientProcess::DhcpSendReq(EthNet *net,
				const BufferInfo& dhcpOptions, const byte *srcIP, const byte *dstMAC, const byte *srvIP)
			{
				reqTimeout.Reset();

				BufferInfo& pkt = net->Packet();

				net->FlushRx();

				pkt.SetLength(
					sizeof(Eth2Header) +
					sizeof(IPv4Header) +
					sizeof(UDPHeader) +
					sizeof(DHCPHeader) + dhcpOptions.Length());

				// eth2	
				auto eth2 = (Eth2Header *)pkt.Buf();

				Eth2Fill(net, eth2, Eth2Type::Eth2Type_IP);
				if (dstMAC == NULL)
					memset(eth2->dstMAC, 0xff, IPV4_MACSIZE); // broadcast
				else
					memcpy(eth2->dstMAC, dstMAC, IPV4_MACSIZE);

				// ipv4
				auto ipv4 = IPv4GetHeader(eth2);
				IPv4Fill(net, ipv4, pkt.Length() - sizeof(Eth2Header), IPv4Type::IPv4Type_UDP);
				memset(ipv4->srcip, 0, IPV4_IPSIZE);
				memset(ipv4->dstip, 0xff, IPV4_IPSIZE);

				IPv4WriteValidChecksum(ipv4); // set valid ipv4 checksum

				// udp
				auto udp = UDPGetHeader(ipv4);
				UDPFill(udp,
					UDP_PORT_BOOTP_CLIENT, // udp srcport:67 (bootp client)
					UDP_PORT_BOOTP_SERVER, // udp dstport:68 (bootp server)
					BufReadUInt16_t(ipv4->totalLength) - (ipv4->ihl * 4)); // len = ipv4->total - ipv4 header length

				// dhcp
				auto dhcp = DHCPGetHeader(udp);
				memset(dhcp, 0, sizeof(DHCPHeader));
				dhcp->opCode = DHCPOpCode::DHCPOpCode_BootRequest;
				dhcp->hwType = DHCPHwType::DHCPHwType_Ethernet;
				dhcp->hwLength = 6;
				//dhcp->hopCount = 0; // already memset 0
				BufWrite32(dhcp->transactionId, transactionId);

				//BufWrite16(dhcp->nrSeconds, 0); // already memset 0
				//BufWrite16(dhcp->flags, 0); // already memset 0

				//memset(dhcp->clientIpAddress, 0, IPV4_IPSIZE); // already memset 0
				//memset(dhcp->yourIp, 0, IPV4_IPSIZE); // already memset 0
				if (srvIP == NULL)
					memset(dhcp->serverIp, 0, sizeof(dhcp->serverIp));
				else
					memcpy(dhcp->serverIp, srvIP, sizeof(dhcp->serverIp));
				//memset(dhcp->gatewayIp, 0, IPV4_IPSIZE); // already memset 0
				//memset(dhcp->clientHwAddress, 0, IPV4_MACSIZE); // already memset 0
				memcpy(dhcp->clientHwAddress, net->MacAddress().ConstBuf(), IPV4_MACSIZE);
				//memset(dhcp->serverHostname, 0, sizeof(dhcp->serverHostname)); // already memset 0
				//memset(dhcp->bootFilename, 0, sizeof(dhcp->bootFilename)); // already memset 0

				DHCPSetMagicCookie(dhcp);

				// append dhcp options
				memcpy(DHCPGetOptions(dhcp), dhcpOptions.ConstBuf(), dhcpOptions.Length());

				UDPWriteValidChecksum(ipv4, udp);

				net->Transmit();
			}

			bool DhcpClientProcess::DhcpReplyMatchMy(Eth2Header *eth2, IPv4Header *ipv4, UDPHeader *udp, DHCPHeader *dhcp, const BufferInfo& opts) const
			{
				if (BufReadUInt32_t(dhcp->transactionId) != transactionId ||
					dhcp->opCode != DHCPOpCode::DHCPOpCode_BootReply ||
					!DHCPMatchesOption(ipv4, udp, dhcp, opts))
					return false;

				return true;
			}			

			//---------------------------------------------------------------
			// public
			//---------------------------------------------------------------

			// https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
			DhcpClientProcess::DhcpClientProcess()
			{
				transactionId = millis();
			}

			bool DhcpClientProcess::LeaseExpired() const
			{
				return TimeDiff(lastRenewTime, millis()) > leaseExpireTimeDiffMs;
			}

			void DhcpClientProcess::LoopProcessImpl(EthNet *net)
			{
				if (net->IpAddress().Size() != 0 && !LeaseExpired()) return;

				BufferInfo& pkt = net->Packet();
				renewInProgress = true;

				Eth2Header *eth2;
				IPv4Header *ipv4;
				UDPHeader *udp;
				DHCPHeader *dhcp;
				if (phase != DhcpClientPhase::None)
				{
					net->Receive();

					dhcp = net->PacketGetDHCP(&eth2, &ipv4, &udp);
				}

				switch (phase)
				{
					case DhcpClientPhase::None:
					{
						// send a discover

#if defined DEBUG && defined DEBUG_DHCP
						if (LeaseExpired())
						{
							DPrint(F("DHCP lease expired "));
							DPrintHex(millis(), true); DPrint(F(" - ")); DPrintHex(lastRenewTime, true);
							DPrint(F(" > ")); DPrintHexln(leaseExpireTimeDiffMs, true);
						}
#endif
						byte dhcpDiscoverOptions[] =
						{
							DHCPOption::DHCPOptionMsgType,
							0x01,
							DHCPMsgType::DHCPMsgTypeDiscover,

							DHCPOption::DHCPOptionEnd
						};
						DhcpSendReq(net, BufferInfo(dhcpDiscoverOptions, sizeof(dhcpDiscoverOptions)));
#if defined DEBUG && defined DEBUG_DHCP
						DPrint(F("sent DHCP discover id: ")); DPrintHexln(transactionId, true);
#endif

						phase = DhcpClientPhase::DiscoverSent;						
					}
					break;

					case DhcpClientPhase::DiscoverSent:
					{
						// waiting for an offer, then sent request						

						if (dhcp != NULL)
						{
							byte dhcpOfferOption[] =
							{
								DHCPOption::DHCPOptionMsgType,
								0x01,
								DHCPMsgType::DHCPMsgTypeOffer
							};

							if (DhcpReplyMatchMy(eth2, ipv4, udp, dhcp, BufferInfo(dhcpOfferOption, sizeof(dhcpOfferOption))))
							{
#if defined DEBUG && defined DEBUG_DHCP
								DPrint(F("DHCP offer match id: "));  DPrintHexln(transactionId, true);
#endif

								net->RxMatched();

								auto ipRequested = dhcp->yourIp;
								auto srvIp = IPv4GetHeader(eth2)->srcip;

								byte dhcpRequestOptions[] =
								{
									DHCPOption::DHCPOptionMsgType,
									0x01,
									DHCPMsgType::DHCPMsgTypeRequest,

									DHCPOption::DHCPOptionRequestedIpAddress,
									IPV4_IPSIZE,
									0, 0, 0, 0, // ip requested

									DHCPOption::DHCPOptionServerIdentifier,
									IPV4_IPSIZE,
									0, 0, 0, 0, // dhcp server

									DHCPOption::DHCPOptionEnd
								};

								memcpy(dhcpRequestOptions + 5, ipRequested, IPV4_IPSIZE);
								memcpy(dhcpRequestOptions + 11, srvIp, IPV4_IPSIZE);

								{
									byte dstMAC[IPV4_MACSIZE];
									memcpy(dstMAC, eth2->srcMAC, IPV4_MACSIZE);
									DhcpSendReq(net, BufferInfo(dhcpRequestOptions, sizeof(dhcpRequestOptions)),
										dhcp->yourIp, dstMAC, srvIp);
								}
#if defined DEBUG && defined DEBUG_DHCP
								DPrint(F("sent DHCP req id: "));  DPrintHexln(transactionId, true);
#endif								

								phase = DhcpClientPhase::RequestSent;
							}
							else
							{
#if defined DEBUG && defined DEBUG_DHCP					
								DPrintln(F("DHCP pkt not match"));
#endif								
							}

							net->FlushRx();
						}

						if (phase == DhcpClientPhase::DiscoverSent && reqTimeout.Expired())
						{
#if defined DEBUG && defined DEBUG_DHCP
							DPrintln(F("DHCP timeout"));
#endif							
							phase = DhcpClientPhase::None;
						}
					}
					break;

					case DhcpClientPhase::RequestSent:
					{
						// request sent, waiting for ack						

						if (dhcp != NULL)
						{
							byte dhcpAckOption[] =
							{
								DHCPOption::DHCPOptionMsgType,
								0x01,
								DHCPMsgType::DHCPMsgTypeAck
							};

							if (DhcpReplyMatchMy(eth2, ipv4, udp, dhcp, BufferInfo(dhcpAckOption, sizeof(dhcpAckOption))))
							{
#if defined DEBUG && defined DEBUG_DHCP
								DPrint(F("DHCP ack match id: "));  DPrintHexln(transactionId, true);
#endif

								net->RxMatched();

								// read lease time
								{
									auto buf = DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionLeaseTime);
									if (buf != NULL)
									{
										leaseExpireTimeDiffMs = BufReadUInt32_t(buf + 2) * 1000L;
									}									
								}

								// read hostname
								{
									auto buf = DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionHostname);
									if (buf != NULL)
									{
										auto len = buf[1];
										if (len > 0) net->Hostname() = RamData(buf + 2, len);
									}
								}

								// read domain name
								{
									auto buf = DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionDomainName);
									if (buf != NULL)
									{
										auto len = buf[1];
										if (len > 0) net->DomainName() = RamData(buf + 2, len);
									}
								}

								// read gateway
								{
									auto buf = DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionGateway);
									if (buf != NULL)
									{
										auto len = buf[1];
										if (len == IPV4_IPSIZE) net->SetGateway(RamData(buf + 2, len));
									}
								}

								// read broadcast address
								{
									auto buf = DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionBroadcast);
									if (buf != NULL)
									{
										auto len = buf[1];
										if (len == IPV4_IPSIZE) net->SetBroadcastAddress(RamData(buf + 2, len));
									}
								}

								// read dns
								{
									auto buf = DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionDns);
									if (buf != NULL)
									{
										auto len = buf[1];
										if (len > 0) net->SetDns(RamData(buf + 2, len));
									}
								}

								// read subnet
								{
									auto buf = DHCPLocateOption(ipv4, udp, dhcp, DHCPOption::DHCPOptionSubnetMask);
									if (buf != NULL)
									{
										auto len = buf[1];
										if (len > 0) net->SetNetmask(RamData(buf + 2, len));
									}
								}								

								// store ip directly into the network subsystem
								net->SetIpAddress(RamData(dhcp->yourIp, IPV4_IPSIZE));		

								lastRenewTime = millis();
								transactionId = millis();
								renewInProgress = false;
								phase = DhcpClientPhase::None;
							}
						}

						net->FlushRx();

						if (phase == DhcpClientPhase::RequestSent && reqTimeout.Expired())
						{
#if defined DEBUG && defined DEBUG_DHCP
							DPrintln(F("DHCP timeout"));
#endif							
							phase = DhcpClientPhase::None;
						}
					}
					break;

				}
			}

			bool DhcpClientProcess::Busy() const { return renewInProgress; }

			unsigned long DhcpClientProcess::CurrentLease() const
			{
				return leaseExpireTimeDiffMs;
			}

		}

	}

}

