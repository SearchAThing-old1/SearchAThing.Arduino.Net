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

// ref. doc https://searchathing.com/?p=59

#ifndef _SEARCHATHING_ARDUINO_NET_SRUDP_CLIENT_H
#define _SEARCHATHING_ARDUINO_NET_SRUDP_CLIENT_H

#if defined(ARDUINO) && ARDUINO >= 100
#include "arduino.h"
#else
#include "WProgram.h"
#endif

#include <SearchAThing.Arduino.Utils\RamData.h>
using namespace SearchAThing::Arduino;

#include "EthNet.h"
#include "IPEndPoint.h"
#include "Protocol.h"
using namespace SearchAThing::Arduino::Net;

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			namespace SRUDP
			{

				// Client state.
				typedef enum ClientState
				{
					// Connect in progress.
					Connecting,

					// Client connected or received a connect from the
					// remote endpoint.
					Connected,
					
					// Disconnect in progress.
					Disconnecting,

					// Client disconnected or received a disconnect from
					// remote endpoint.					
					Disconnected
				};

				// SRUDP transaction result.
				typedef enum TransactionResult
				{					
					Failed,
					Successful,
				};

				// SRUDP protocol opcode type.
				typedef enum OpCodeType
				{

					// Connect request
					Connect,

					// Received packet ack.
					Ack,

					// Data transmission.
					Data,

					// Disconnect request.
					Disconnect
				};

				// SRUDP Client
				//-----------------------------------------------------------
				// Manages proper client connection and listener mode
				// for 1 connection request at time.
				//
				// Main functions available are:
				// - Connect
				// - Write
				// - Read
				// - Disconnect
				// - Listen
				//
				// When used as proper client start the connection using
				// the Connect, then Disconnect to stop.
				// When used as listener use the static method Listen
				// that will return a client object in Connected state
				// so there is no need to call the Connect again.
				//
				// In either modes (proper client or listener) the disconnect
				// can controlled by the client itself or can issue from the
				// remote endpoint.
				class Client
				{

				private:
					EthNet *net;

					ClientState state = ClientState::Disconnected;

					// Receive sequence id.
					// We expect the first received packet has id=0.
					// Each subsequent new packet must have id incremented
					// by one.
					uint16_t rxId = 0;

					// Transmission sequence id.
					// First packet we sent has id=0.
					// Each subsequent new packet sent will have id
					// incremented by one.
					// Foreach transmitted packet we expect an ACK packet
					// with the id equals to those we just sent.
					// See also: ManageAcks
					uint16_t txId = 0;

					// Max size of data after which the packet will be
					// chunked into multiple packets.
					uint16_t txChunkSizeMax;

					IPEndPoint localEndPoint;
					IPEndPoint remoteEndPoint;

					// Cached remote MAC, used for transmission.
					RamData remoteHwAddress;					

				protected:
					// net state: not yet matched packet
					void ManageAcks(SRUDPHeader *srudp, uint16_t id);

					// Send a packet of the given type.
					// If packet is Connect, Data, Disconnect the ackId will
					// ignored.
					// If packet is Ack the ackId is the id encapsulated into
					// the packet.
					// If packet is Data a buffer of bytes `data' is expected
					// for the given `dataLenTotal' length.
					TransactionResult Send(OpCodeType opCodeType, uint16_t ackId, const byte *data = NULL, uint16_t dataLenTotal = 0);

					// See: Send.
					// This is the core function of the Send() which it take
					// loops until multichunk packets are sent.
					TransactionResult SendChunk(OpCodeType opCodeType, uint16_t ackId, const byte *data = NULL, uint16_t dataLen = 0, uint16_t dataLenLeft = 0);

					// Sets the state to Disconnected and cleanup variables.
					void ForceDisconnect();

				public:
					// Creates a proper client that connects to the SRUDP
					// given endpoint.
					// The parameter `_txChunkSizeMax' controls the max size
					// over which the transmitted data using Write will be
					// chunked.
					Client(EthNet *_net, const IPEndPoint& _remoteEndPoint, uint16_t _txChunkSizeMax = 0);

					// Destructor.
					~Client();

					// Current state of the client.
					ClientState State() const;

					// Issue a connect command. This has to be used when
					// client is constructed without the `Listen` method.
					// If the connection isn't handled from the remote
					// endpoint between the REQUEST_TIMEOUT_MAX it will
					// returns Failed, otherwise Successful.
					// After connect sent an appropriate ack is
					// expected from the remoteEndpoint. If all acks are
					// received with correct sequence then a Success value
					// is returned, Failed otherwise.
					TransactionResult Connect();

					// Issue a write command for the given data to be send
					// toward the remote endpoint. If data.Size() exceed
					// the current txChunkSizeMax then multi chunk packets
					// will be sent of that max size until entire message
					// are consumed.
					// After each packet written an appropriate ack is
					// expected from the remoteEndpoint. If all acks are
					// received with correct sequence then a Success value
					// is returned, Failed otherwise.
					TransactionResult Write(const RamData& data);

					// See: Write(const RamData& data)
					TransactionResult Write(const byte *buf, uint16_t size);

					// States how much bytes can be sent as data with a
					// single packet using the write.
					uint16_t MaxDataBytes() const;

					// Issue a read command to retrieve data from the
					// remoteEndPoint. If multichunk data comes this will
					// be reassembled into a single res. A check over correct
					// sequence of each received data packet is done.
					// After each packet readed an appropriate ack is sent
					// to the remoteEndPoint to notify the reception.
					// If not all packets of a multichunk read gets readed
					// over the connection timeout span a Failed transaction
					// code is returned.					
					TransactionResult Read(RamData& res);

					// Issue a Disconnect command.
					// An ack is awaited until connection timeout.
					TransactionResult Disconnect();

					// Wait for an incoming connection from the given remote
					// endpoint.
					static Client Listen(EthNet *net, const IPEndPoint& srvEndPoint);

					// This client endpoint.
					const IPEndPoint& LocalEndPoint() const;

					// Remote endpoint.
					const IPEndPoint& RemoteEndPoint() const;

				};

			}

		}

	}

}
#endif

