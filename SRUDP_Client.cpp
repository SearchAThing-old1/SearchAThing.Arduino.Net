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
#include "SRUDP_Client.h"

#include <SearchAThing.Arduino.Utils\Util.h>
using namespace SearchAThing::Arduino;

#include "Protocol.h"
#include "IPEndPoint.h"
using namespace SearchAThing::Arduino::Net;

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			namespace SRUDP
			{

				//-----------------------------------------------------------
				// protected
				//-----------------------------------------------------------

				void Client::ManageAcks(SRUDPHeader *srudp, uint16_t id)
				{
					if (!srudp->ack)
					{
						if (srudp->disconnect && id == rxId)
						{
#if defined DEBUG && defined DEBUG_SRUDP
							DPrintln(F("ManageAcks: Disconnect"));
#endif
							state = ClientState::Disconnecting;
							Send(OpCodeType::Ack, id);
							state = ClientState::Disconnected;
							net->RxMatched();
						}
						else if (id == rxId - 1)
						{
#if defined DEBUG && defined DEBUG_SRUDP
							DPrintln(F("ManageAcks: Ack previously received packet"));
#endif
							net->RxMatched();
							Send(OpCodeType::Ack, id);
						}
						else
						{
#if defined DEBUG && defined DEBUG_SRUDP
							DPrint(F("UnManagedAcks ack:")); DPrint(srudp->ack); DPrint(F(" data:")); DPrint(srudp->data);
							DPrint(F(" id:")); DPrintln(id);
#endif
						}
					}
				}

				TransactionResult Client::Send(OpCodeType opCodeType, uint16_t overrideAckId, const byte *data, uint16_t dataLenTotal)
				{
					if (data == NULL || dataLenTotal <= txChunkSizeMax)
					{
						return SendChunk(opCodeType, overrideAckId, data, dataLenTotal, 0);
					}
					else
					{
						uint16_t dataLen = txChunkSizeMax;
						uint16_t dataLenLeft = dataLenTotal;
						auto i = 0;

						while (dataLenLeft != 0)
						{
							dataLenLeft -= dataLen;

							if (SendChunk(opCodeType, 0, data + i, dataLen, dataLenLeft) == TransactionResult::Failed) return TransactionResult::Failed;
							i += dataLen;

							if (dataLenLeft > 0 && dataLenLeft < txChunkSizeMax) dataLen = dataLenLeft;
						}
						return TransactionResult::Successful;
					}
				}

				TransactionResult Client::SendChunk(OpCodeType opCodeType, uint16_t ackId, const byte *data, uint16_t dataLen, uint16_t dataLenLeft)
				{
					if (state == ClientState::Disconnected) return TransactionResult::Failed;

					auto beginTime = millis();
					BufferInfo& pkt = net->Packet();
					auto ackReceived = false;

					while (!ackReceived && state != ClientState::Disconnected && TimeDiff(beginTime, millis()) <= REQUEST_TIMEOUT_MAX)
					{
						net->FlushRx();

						pkt.SetLength(
							sizeof(Eth2Header) +
							sizeof(IPv4Header) +
							sizeof(UDPHeader) +
							sizeof(SRUDPHeader) + dataLen);

						// eth2
						auto eth2 = (Eth2Header *)pkt.Buf();
						Eth2Fill(net, eth2, Eth2Type::Eth2Type_IP);
						memcpy(eth2->dstMAC, remoteHwAddress.Buf(), sizeof(eth2->dstMAC));

						// ipv4
						auto ipv4 = IPv4GetHeader(eth2);
						IPv4Fill(net, ipv4, pkt.Length() - sizeof(Eth2Header), IPv4Type::IPv4Type_UDP);
						memcpy(ipv4->dstip, remoteEndPoint.Ip().ConstBuf(), IPV4_IPSIZE);
						// set valid ipv4 checksum
						IPv4WriteValidChecksum(ipv4);

						// udp
						auto udp = UDPGetHeader(ipv4);
						UDPFill(udp,
							// ephemeral port
							localEndPoint.Port(),
							remoteEndPoint.Port(),
							// len = ipv4->total - ipv4 header length
							BufReadUInt16_t(ipv4->totalLength) - (ipv4->ihl * 4));

						// srudp
						auto srudp = SRUDPGetHeader(udp);
						SRUDPResetOpCode(srudp);
						auto id = txId;
						switch (opCodeType)
						{
							case OpCodeType::Ack:
							{
								srudp->ack = 1;
								id = ackId;
							}
							break;
							case OpCodeType::Connect: srudp->connect = 1; break;
							case OpCodeType::Data:
							{
								srudp->data = 1;
								memcpy(SRUDPGetData(srudp), data, dataLen);
							}
							break;
							case OpCodeType::Disconnect: srudp->disconnect = 1; break;
						}
						BufWrite16(srudp->id, id);
						BufWrite16(srudp->dataLen, dataLen);
						BufWrite16(srudp->dataLenLeft, dataLenLeft);

						UDPWriteValidChecksum(ipv4, udp);

						if (!net->Transmit())
						{
#if defined DEBUG && defined DEBUG_SRUDP
							DPrintln(F("*** TX Err"));
#endif
							continue;
						}
						else
						{
#if defined DEBUG && defined DEBUG_SRUDP
							DPrint(F("tx -> [port:")); DPrint(BufReadUInt16_t(udp->destPort)); DPrint(F("] "));
							SRUDPPrint(net->Packet());
							DPrint(F(" rxId:")); DPrint(rxId); DPrint(F(" txId:")); DPrint(txId);
							DNewline();
#endif
						}

						if (opCodeType == OpCodeType::Ack)
						{
							return TransactionResult::Successful;
						}

						auto ackBegin = millis();

						while (!ackReceived && state != ClientState::Disconnected && TimeDiff(ackBegin, millis()) <= REQUEST_TIMEOUT_MS)
						{
							auto rxSomething = false;
							do
							{
								net->Receive();
								rxSomething = pkt.Length() > 0;

								auto udp = net->PacketGetUDP(&eth2, &ipv4);
								if (udp != NULL)
								{
									auto udpLocalEndPoint = IPEndPoint(ipv4->dstip, BufReadUInt16_t(udp->destPort));
									auto udpRemoteEndPoint = IPEndPoint(ipv4->srcip, BufReadUInt16_t(udp->sourcePort));

									if (udpLocalEndPoint.Equals(localEndPoint) && udpRemoteEndPoint.Equals(remoteEndPoint))
									{
#if defined DEBUG && defined DEBUG_SRUDP
										DPrint(F("rx <- [port:")); DPrint(BufReadUInt16_t(udp->sourcePort)); DPrint(F("] "));
										SRUDPPrint(net->Packet());
										DPrint(F(" rxId:")); DPrint(rxId); DPrint(F(" txId:")); DPrint(txId);
										DNewline();
#endif

										auto srudp = SRUDPGetHeader(udp);
										auto id = BufReadUInt16_t(srudp->id);

										if (srudp->ack && id == txId)
										{
											ackReceived = true;
											net->RxMatched();
											++txId;

											return TransactionResult::Successful;
										}
										else
										{
											net->RxMatched();
											ManageAcks(srudp, id);
										}
									}
								}

								net->FlushRx();
							} while (rxSomething);
						}

						{
#if defined DEBUG && defined DEBUG_SRUDP
							DPrintln(F("acktimeout during Write"));
#endif
						}
					}

					return TransactionResult::Failed;
				}

				void Client::ForceDisconnect()
				{
					state = ClientState::Disconnected;
					txId = rxId = 0;
					net->ReleaseEphermeralPort(localEndPoint.Port());
					localEndPoint = IPEndPoint();
					remoteHwAddress.Clear();
				}

				//-----------------------------------------------------------
				// public
				//-----------------------------------------------------------

				Client::Client(EthNet *_net, const IPEndPoint& _remoteEndPoint, uint16_t _txChunkSizeMax)
				{
					net = _net;
					remoteEndPoint = _remoteEndPoint;
					if (_txChunkSizeMax == 0)
					{
						_txChunkSizeMax = _net->Packet().Capacity() -
							sizeof(Eth2Header) -
							sizeof(IPv4Header) -
							sizeof(UDPHeader) -
							sizeof(SRUDPHeader);
					}
					txChunkSizeMax = _txChunkSizeMax;
				}

				Client::~Client()
				{
				}

				ClientState Client::State() const { return state; }

				TransactionResult Client::Connect()
				{
					if (state != ClientState::Disconnected)
					{
						return TransactionResult::Failed; // TODO debug
					}

					if (remoteHwAddress.Size() == 0)
					{
						remoteHwAddress = net->ResolveMAC(remoteEndPoint.Ip());
					}

					if (remoteHwAddress.Size() == 0)
					{
#if defined DEBUG && defined DEBUG_SRUDP
						DPrint(F("* unable to resolve mac of ip ")); DPrintBytes(remoteEndPoint.Ip().ConstBuf(), IPV4_IPSIZE); DNewline();
#endif
						return TransactionResult::Failed;
					}

					localEndPoint = IPEndPoint(net->IpAddress(), net->AllocEphemeralPort());

					state = ClientState::Connecting;

					auto res = Send(OpCodeType::Connect, 0);
					if (res == TransactionResult::Successful) state = ClientState::Connected;

					return res;
				}

				TransactionResult Client::Write(const RamData& data)
				{
					return Send(OpCodeType::Data, 0, data.ConstBuf(), data.Size());
				}

				TransactionResult Client::Write(const byte *buf, uint16_t size)
				{
					return Send(OpCodeType::Data, 0, buf, size);
				}

				uint16_t Client::MaxDataBytes() const
				{
					return txChunkSizeMax;
				}

				TransactionResult Client::Read(RamData& res)
				{
					BufferInfo& pkt = net->Packet();
					Eth2Header *eth2;
					IPv4Header *ipv4;

					uint16_t dataLenReaded = 0;
					auto rxBegin = millis();

					while (state == ClientState::Connected)
					{
						if (TimeDiff(rxBegin, millis()) > REQUEST_TIMEOUT_MAX)
						{
							return TransactionResult::Failed;
						}

						net->Receive();

						auto udp = net->PacketGetUDP(&eth2, &ipv4);
						if (udp != NULL)
						{
							auto udpLocalEndPoint = IPEndPoint(ipv4->dstip, BufReadUInt16_t(udp->destPort));
							auto udpRemoteEndPoint = IPEndPoint(ipv4->srcip, BufReadUInt16_t(udp->sourcePort));

							if (udpLocalEndPoint.Equals(localEndPoint) && udpRemoteEndPoint.Equals(remoteEndPoint))
							{
								auto srudp = SRUDPGetHeader(udp);
								auto id = BufReadUInt16_t(srudp->id);

#if defined DEBUG && defined DEBUG_SRUDP
								DPrint(F("rx <- [port:")); DPrint(BufReadUInt16_t(udp->sourcePort)); DPrint(F("] "));
								SRUDPPrint(net->Packet());
								DPrint(F(" rxId:")); DPrint(rxId); DPrint(F(" txId:")); DPrint(txId);
								DNewline();
#endif

								if (srudp->data && id == rxId)
								{
									rxBegin = millis();

									auto data = SRUDPGetData(srudp);
									auto dataLen = BufReadUInt16_t(srudp->dataLen);
									auto dataLenLeft = BufReadUInt16_t(srudp->dataLenLeft);

									net->RxMatched();

									if (dataLenReaded == 0)
										res = RamData(dataLen + dataLenLeft); // TODO check out-of-memory

									memcpy(res.Buf() + dataLenReaded, data, dataLen);
									dataLenReaded += dataLen;

									Send(OpCodeType::Ack, rxId);
									++rxId;

									if (dataLenReaded == res.Size()) return TransactionResult::Successful;
								}
								else
								{
#if defined DEBUG && defined DEBUG_SRUDP
									DPrintln(F("Managing unsequenced packet during a Read"));
#endif
									ManageAcks(srudp, id);
								}
							}

						}

						net->FlushRx();
					}
				}

				TransactionResult Client::Disconnect()
				{
					state = ClientState::Disconnecting;
					auto res = Send(OpCodeType::Disconnect, 0);
					ForceDisconnect();

					return res;
				}

				Client Client::Listen(EthNet *net, const IPEndPoint& srvEndPoint)
				{
					IPEndPoint remoteEndPoint;
					auto pkt = net->Packet();
					Eth2Header *eth2;
					IPv4Header *ipv4;

					while (true)
					{
						net->Receive();

						auto udp = net->PacketGetUDP(&eth2, &ipv4);
						if (udp != NULL)
						{
							auto udpLocalEndPoint = IPEndPoint(ipv4->dstip, BufReadUInt16_t(udp->destPort));

							if (udpLocalEndPoint.Equals(srvEndPoint))
							{
								auto srudp = SRUDPGetHeader(udp);
								auto srudpId = BufReadUInt16_t(srudp->id);

								if (srudp->connect && srudpId == 0)
								{
									net->RxMatched();

									Client client(net, IPEndPoint(ipv4->srcip, BufReadUInt16_t(udp->sourcePort)));
									client.localEndPoint = srvEndPoint;
									client.state = ClientState::Connecting;
									client.Send(OpCodeType::Ack, client.rxId++); // ack to the connect
									client.state = ClientState::Connected;

									return client;
								}
							}
						}

						net->FlushRx();
					}
				}

				const IPEndPoint& Client::LocalEndPoint() const { return localEndPoint; }
				const IPEndPoint& Client::RemoteEndPoint() const { return remoteEndPoint; }

			}

		}

	}

}
