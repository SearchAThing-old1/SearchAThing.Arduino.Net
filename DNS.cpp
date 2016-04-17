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

#include "DNS.h"
#include "Protocol.h"
#include "EthNet.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			uint16_t SkipDNSName(const byte *_ptr, uint16_t i, uint16_t maxOff)
			{
				auto ptr = _ptr + i;

				// https://tools.ietf.org/html/rfc1035#section-4.1.4
				if (*ptr & B11000000) // its a pointer
				{					
					// just skip two bytes
					i += 2;
				}
				else
				{
					// skip name tokens
					while (i < maxOff) // safety check 
					{
						auto len = ptr[i];						
						++i; // skip token len / terminator[len=0]
						if (len > 0)
						{
							while (i < maxOff && len>0) { ++i; --len; } // skip token itself
						}
						else
							break;
					}
				}

				return i;
			}

		}

	}

}


