#pragma once

#include <windows.h>
#include <tchar.h>
#include <string>

typedef std::basic_string<TCHAR> tstring;
#if defined(UNICODE) || defined(_UNICODE)
#define tcout std::wcout
#define OutputDebugStringT OutputDebugStringW
#else
#define tcout std::cout
#define OutputDebugStringT OutputDebugStringA
#endif

interface i_PEParser {
public:
	virtual ~i_PEParser() {};
	virtual void clean() abstract;
	virtual void debug(tstring debugMsg) abstract;
	virtual BOOL parsePE(tstring filePath) abstract;
	virtual BOOL printDosHeader() abstract;
	virtual BOOL printImageSectionHeader() abstract;
	virtual BOOL printNTHeader() abstract;
	virtual BOOL printEAT() abstract;
	virtual BOOL printIAT() abstract;
	virtual BOOL printTLS() abstract;
};
