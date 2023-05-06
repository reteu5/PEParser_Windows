//#pragma once
//#include <windows.h>
//#include <tchar.h>
//#include <string>
//
//typedef std::basic_string<TCHAR> tstring;
//#if defined(UNICODE) || defined(_UNICODE)
//#define tcout std::wcout
//#define OutputDebugStringT OutputDebugStringW
//#else
//#define tcout std::cout
//#define OutputDebugStringT OutputDebugStringA
//#endif
//
//namespace varUtil {
//	class varUtils {
//	private:
//		DWORD m_processId = NULL;
//		tstring m_FilePath = NULL;
//		LPVOID m_peBaseAddress = NULL;
//		HANDLE m_threadHandle = NULL;
//		HANDLE m_processHandle = NULL;
//		void clean();
//	public:
//		tstring readString(LONGLONG addressOfString);		//LONGLONG for sufficient room for address from 64bit
//
//	};
//}