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

#ifndef _SEARCHATHING_ARDUINO_NET_CHECKSUM_H
#define _SEARCHATHING_ARDUINO_NET_CHECKSUM_H

#if defined(ARDUINO) && ARDUINO >= 100
#include "arduino.h"
#else
#include "WProgram.h"
#endif

#include <SearchAThing.Arduino.Utils\DebugMacros.h>

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			// Compute Internet checksum of the given buffer data for count
			// bytes in partial mode:
			// - for the first call use `prevSum'=0
			// - for subsequent call use `prevSum' the returned value of
			//   previous
			// - for the latest call set `last' to true.
			// Actual implementation expects event count of bytes foreach
			// call except the last.
			// If DEBUG and DEBUG_ASSERT defined a check on the fact
			// not-latest calls pass event count bytes will be done.
			uint32_t CheckSumPartial(uint32_t prevSum, byte *data, uint16_t count, bool last = false);

			// Finalize the partial checksum obtained from the
			// `CheckSumPartial'.
			uint16_t CheckSumFinalize(uint32_t sum);

			// Compute Internet checksum of the given buffer for `len' bytes.
			// http://www.faqs.org/rfcs/rfc1071.html (4.1)
			uint16_t CheckSum(byte *data, uint16_t len);

		}

	}

}

#endif
