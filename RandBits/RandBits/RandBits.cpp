// Copyright 2013 Alan Ludwig
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http ://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// RandBits.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void usage();
bool parseCommandLine(int argc, wchar_t* argv[], long *pcb);

int wmain(int argc, wchar_t* argv[])
{
	HCRYPTPROV hCryptProv = NULL;
	BOOL fRet = FALSE;
	long cb = 0; // Count of bytes

	fRet = parseCommandLine(argc, argv, &cb);
	if (!fRet){
		usage();
		return 1;
	}

	if (fRet)
	{
		fRet = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	}

	BYTE* pbData = nullptr;
	if (fRet)
	{
		pbData = new BYTE[cb];
		if (nullptr == pbData){
			printf("Out Of Memory!");
			fRet = false;
		}
	}
	
	if (fRet)
	{
		fRet = CryptGenRandom(hCryptProv, cb, pbData);
	}

	if (fRet)
	{
		for (int i = 1; i < cb; ++i)
		{
			printf("%02X", pbData[i]);
		}
		printf("\n");
	}

	if (hCryptProv)
	{
		CryptReleaseContext(hCryptProv, 0);
		hCryptProv = NULL;
	}

	return 0;
}

void usage()
{
	printf("Prints out a cryptograpically secure random number of bytes as hex encoded string.\n");
	printf("\n");
    printf("RandBits <bytes>\n");
	printf("\n");
	printf("<bytes>   The number of random bytes to produce.\n");
	printf("          If not specified, it generates 32 bytes (256bits) of random data.\n");
	printf("          The tool will generate a maximum of 1MB of random data\n");
}

bool parseCommandLine(int argc, wchar_t* argv[], long *pcb)
{
	bool fRet = true;
	*pcb = 32;


	if (argc > 2)
	{
		printf("Too many arguments!\n\n");
		*pcb = 0;
		return false;
	}
	else if (argc == 2)
	{
		// We've got one argument.. 
		long bytes = _wtol(argv[1]);
		if (bytes > 0x100000)
		{
			printf("Input too large. A maximum of 1048576 bytes can be requested.\n\n");
			*pcb = 0;
			return false;
		}
		
		if (bytes < 1)
		{
			printf("Input too small, A minimum of 1 byte can be requested. \n\n");
			*pcb = 0;
			return false;
		}

		*pcb = bytes;
	}

	return fRet;
}