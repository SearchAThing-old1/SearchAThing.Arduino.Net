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

#include "Checksum.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			uint32_t CheckSumPartial(uint32_t prevSum, byte *data, uint16_t count, bool last)
			{
#if defined DEBUG && defined DEBUG_ASSERT
				if (!last && count % 2 != 0)
				{
					DPrint(F("* chksum partial not support odd count="));
					DPrint(count);
					DNewline();
				}
#endif
				auto sum = prevSum;

				while (count > 1)
				{
					sum += (((uint32_t)(*data)) << 8) | (*(data + 1));
					count -= 2;
					data += 2;
				}

				if (count)
				{
					sum += (uint32_t)(((uint16_t)*data) << 8);
				}

				return sum;
			}

			uint16_t CheckSumFinalize(uint32_t sum)
			{
				while (sum >> 16)
				{
					sum = (sum & 0xffff) + (sum >> 16);
				}

				uint16_t chksum = (~sum) & 0xffff;

				return chksum;
			}

			uint16_t CheckSum(byte *data, uint16_t count)
			{
				return CheckSumFinalize(CheckSumPartial(0, data, count, true));
			}

		}

	}

}
