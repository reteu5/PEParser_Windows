#pragma once

#include "typedef.h"

namespace LogUtil {

	class CLogUtil {

	private:
		BOOL m_addFuncInfo;
		LogLevel m_logLevel;
		LogDirection m_logDirection;

	private:
		void output(const tstring& logMessage, BOOL useEndl);

	public:
		CLogUtil();
		~CLogUtil();
		void setLogType(LogLevel logLevel, LogDirection logDirection, BOOL addFuncInfo = TRUE);
		void log(const tstring& logMessage, LogLevel logLevel = LOG_LEVEL_ALL, BOOL useEndl = TRUE, const char* funcName = __builtin_FUNCTION(), int funcLine = __builtin_LINE());
		void log(const TCHAR* logMessage, LogLevel logLevel = LOG_LEVEL_ALL, BOOL useEndl = TRUE, const char* funcName = __builtin_FUNCTION(), int funcLine = __builtin_LINE());
		void log(const TCHAR* logMessage, DWORD errorCode, LogLevel logLevel = LOG_LEVEL_ALL, BOOL useEndl = TRUE, const char* funcName = __builtin_FUNCTION(), int funcLine = __builtin_LINE());
	};
};

