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
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>


int wmain(int argc, wchar_t* argv[])
{
	HCRYPTPROV hCryptProv =  NULL;
	BOOL fRet = FALSE;
	fRet = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	BYTE dwData[32];
	if (fRet){
		fRet = CryptGenRandom(hCryptProv, 32, dwData);
	}

	if (fRet){
		for (int i = 1; i < sizeof(dwData); ++i){
			printf("%02X", dwData[i]);
		}
		printf("\n");
	}

	if (hCryptProv){
		CryptReleaseContext(hCryptProv, 0);
		hCryptProv = NULL;
	}

	return 0;
}

