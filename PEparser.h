#pragma once
#include "interface.h"

namespace PEParse {
	class PEParser : i_PEParser {
	private:
		tstring m_peFilePath = _T("");
		HANDLE m_peFileHandle = NULL;
		HANDLE m_peFileMapping = NULL;
		LPVOID m_peBaseAddress = NULL;
		IMAGE_DOS_HEADER* m_peDosHeader = NULL;

	protected:
		void printNTHeader32();
		void printNTHeader64();
		void printFileSize();

	public:
		~PEParser() override;
		void clean() override;
		void debug(tstring debugmsg) override;
		BOOL parsePE(tstring filepath) override;
		BOOL printDosHeader() override;
		BOOL printNTHeader() override;
	};
};