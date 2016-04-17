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

#ifndef _SEARCHATHING_ARDUINO_NET_IPENDPOINT_H
#define _SEARCHATHING_ARDUINO_NET_IPENDPOINT_H

#if defined(ARDUINO) && ARDUINO >= 100
#include "arduino.h"
#else
#include "WProgram.h"
#endif

#include <SearchAThing.Arduino.Utils\DebugMacros.h>
#include <SearchAThing.Arduino.Utils\RamData.h>

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			// Helper container for Ip and Port.
			class IPEndPoint
			{
				RamData ip;
				uint16_t port;

			public:
				// Default constructor.
				IPEndPoint();

				// Construct an ip-endpoint by the given `_ip' and `_port'.
				IPEndPoint(const RamData& _ip, uint16_t _port);

				// Construct an ip-endpoint by the given `_ip' and `_port'.
				IPEndPoint(const byte *_ip, uint16_t _port);

				// Retrieve ip of the endpoint.
				const RamData& Ip() const;

				// Retrieve the port of the endpoint.
				uint16_t Port() const;
				
				// States if two endpoint are equals.
				bool Equals(const IPEndPoint& other) const;

				// String 0-leading representing ip:port of the endpoint.
				RamData ToString() const;

			};

		}

	}

}

#endif
