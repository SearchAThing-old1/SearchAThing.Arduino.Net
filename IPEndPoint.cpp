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

#include "IPEndPoint.h"
#include "Protocol.h"

namespace SearchAThing
{

	namespace Arduino
	{

		namespace Net
		{

			IPEndPoint::IPEndPoint()
			{
				port = 0;
			}

			IPEndPoint::IPEndPoint(const RamData& _ip, uint16_t _port)
			{
				ip = _ip;
				port = _port;
			}

			IPEndPoint::IPEndPoint(const byte *_ip, uint16_t _port)
			{
				ip = RamData(_ip, IPV4_IPSIZE);
				port = _port;
			}

			const RamData& IPEndPoint::Ip() const { return ip; }
			uint16_t IPEndPoint::Port() const { return port; }

			bool IPEndPoint::Equals(const IPEndPoint& other) const
			{
				return
					(ip.Size() == other.ip.Size())
					&&
					memcmp(ip.ConstBuf(), other.ip.ConstBuf(), IPV4_IPSIZE) == 0
					&&
					port == other.port;
			}

			RamData IPEndPoint::ToString() const
			{
				if (ip.Size() == 0) return RamData("", true);

				auto ipbytes = ip.ConstBuf();
				char buf[4 * 3 + 4 + 6 + 1];
				sprintf(buf, "%u.%u.%u.%u:%u", ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3], port);
				return RamData(buf, false);
			}

		}

	}

}
