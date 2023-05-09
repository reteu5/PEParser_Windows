#pragma once

#include "typedef.h"
#include "CLogUtil.h"

namespace HashUtil {

	class CHashUtil {

	private:
		LogUtil::CLogUtil m_logger;
		DWORD m_hashSize = 0;
		DWORD m_hashSizeBufferLength = sizeof(DWORD);
		HCRYPTPROV m_prov = NULL;
		HCRYPTHASH m_hash = NULL;

	private:
		BOOL toString(const BYTE* hashBytes, DWORD srcLength, tstring& outString);

	public:
		CHashUtil();
		~CHashUtil();
		BOOL open(void);
		void close(void);
		BOOL compareBytes(const BYTE* srcBytes, DWORD srcLength, const BYTE* destBytes, DWORD destLength);
		BOOL calculateHash(const BYTE* srcBytes, DWORD srcLength);
		BOOL getMD5Hash(BYTE* md5Bytes, DWORD* md5BufferLength);
		BOOL getMD5Hash(tstring& md5String);

	};

};


