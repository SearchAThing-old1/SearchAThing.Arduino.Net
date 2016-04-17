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

#ifndef _SEARCHATHING_ARDUINO_NET_ETH_DRIVER_H
#define _SEARCHATHING_ARDUINO_NET_ETH_DRIVER_H

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

			// Max size of received/transmitted frames.
			const uint16_t MAX_FRAME_LENGTH = 1518;

			// Type to keep track of line status.
			typedef enum LineStatusEnum
			{
				LinkUp,
				LinkDown
			};

			// Abstract ethernet driver.			
			class EthDriver
			{

			public:
				// Programmed MAC address.
				virtual const RamData& MacAddress() const = 0;

				// States the current line status.
				virtual LineStatusEnum LineStatus() = 0;

				// Read current receive buffer packet and store it
				// (eventually empty) into the given buffer of maximum
				// `capacity' given returning the length of effective
				// received bytes.
				virtual uint16_t Receive(byte *buf, uint16_t capacity) = 0;

				// Transmit the buffer bytes for the given length.
				virtual bool Transmit(const byte *buf, uint16_t len) = 0;

			};

		}

	}

}

#endif
