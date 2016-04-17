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

#ifndef _SEARCHATHING_ARDUINO_NET_ETH_PROCESS_H
#define _SEARCHATHING_ARDUINO_NET_ETH_PROCESS_H

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

			class EthNet;

			// Ethernet subsystem process.
			// To allow synchronous processes to work in a non-threaded
			// environment in order to ensure the flow or received packet
			// can be processed and normal activity operation to be done
			// a process can be registered into the network subsystem of
			// the EthNet so that the LoopProcess() function will be called
			// at every sync-share point that the FlushRx() establish
			// between them.
			class EthProcess
			{

			private:
				bool busy = false;

			protected:
				// This function is ensured to be called from proper managed
				// processed that handle packet and then pass the control
				// to other scenario processes through the FlushRx()
				virtual void LoopProcessImpl(EthNet *net) = 0;

			public:
				
				void LoopProcess(EthNet *net);				

			};

		}

	}

}

#endif
