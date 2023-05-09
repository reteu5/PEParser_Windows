#pragma once

#include "CHashUtil.h"
#include <algorithm>
#include <format>

using namespace std;

namespace HashUtil {

    CHashUtil::CHashUtil()
    {
    };

    CHashUtil::~CHashUtil(void)
    {
        close();
    };

    BOOL CHashUtil::open(void)
    {
        BOOL result = FALSE;

        if (m_prov != NULL)
        {
            close();
        }
        // Get the handle to the crypto provider
        if (CryptAcquireContext(&m_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == NULL)
        {
            m_logger.log(_T("CryptAcquireContext fail"), GetLastError(), LOG_LEVEL_ERROR);
        }
        else
        {
            // Get the handle to the md5 hash object
            if (CryptCreateHash(m_prov, CALG_MD5, 0, 0, &m_hash) == NULL)
            {
                m_logger.log(_T("CryptCreateHash fail"), GetLastError(), LOG_LEVEL_ERROR);
            }
            else
            {
                result = TRUE;
            }
        }
        if (!result) close();

        return result;
    };

    void CHashUtil::close(void)
    {
        if (m_hash != NULL)
        {
            CryptDestroyHash(m_hash);
            m_hash = NULL;
        }
        if (m_prov != NULL)
        {
            CryptReleaseContext(m_prov, 0);
            m_prov = NULL;
        }
    };

    BOOL CHashUtil::compareBytes(const BYTE* srcBytes, DWORD srcLength, const BYTE* destBytes, DWORD destLength)
    {
        return ((srcLength == destLength) && equal(srcBytes, srcBytes + srcLength, destBytes));
    };

    BOOL CHashUtil::toString(const BYTE* hashBytes, DWORD srcLength, tstring& outString)
    {
        if (hashBytes != NULL)
        {
            for (DWORD index = 0; index < srcLength; index++)
            {
                outString.append(format(_T("{:02x}"), hashBytes[index]));
            }
        }
        return (!outString.empty());
    };

    BOOL CHashUtil::calculateHash(const BYTE* srcBytes, DWORD srcLength)
    {
        BOOL result = FALSE;

        // Get the hash from the bytes
        if (CryptHashData(m_hash, srcBytes, srcLength, 0) != 0)
        {
            result = TRUE;
        }
        else
        {
            m_logger.log(_T("CryptHashData fail"), GetLastError(), LOG_LEVEL_ERROR);
        }
        return result;
    };

    BOOL CHashUtil::getMD5Hash(BYTE* md5Bytes, DWORD* md5BufferLength)
    {
        BOOL result = FALSE;

        // Get the hash size
        if ((m_hash != NULL) && (CryptGetHashParam(m_hash, HP_HASHSIZE, (BYTE*)&m_hashSize, &m_hashSizeBufferLength, 0) != 0))
        {
            // Check buffer size
            if (*md5BufferLength >= m_hashSize)
            {
                // Get the hash value
                if (CryptGetHashParam(m_hash, HP_HASHVAL, md5Bytes, md5BufferLength, 0))
                {
                    result = TRUE;
                }
            }
        }
        return result;
    };

    BOOL CHashUtil::getMD5Hash(tstring& md5String)
    {
        BYTE md5HashBytes[MD5_LENGTH] = { 0, };
        DWORD md5BufferLength = MD5_LENGTH;

        return (getMD5Hash(md5HashBytes, &md5BufferLength) && toString(md5HashBytes, MD5_LENGTH, md5String));
    };

};
