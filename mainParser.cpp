#include <iostream>
#include "PEParser.h"
#include "scanner.h"

using namespace std;
using namespace PEParse;

/*int main(void) {
	PEParser peParser = PEParser();
	if (peParser.parsePE(_T("C:\Windows\System32\calc.exe"))) {
		peParser.printDosHeader();
		peParser.printNTHeader();
	}

	return 0;
};*/


int main(void) {
	tstring filePath = _T("=========== INPUT DESIRED FILE PATH HERE ===========");

	filePath = _T("C:\\Windows\\System32\\shell32.dll");
	//PEParserTest(filePath);
	scannerTest(filePath);

	return 0;
};

void PEParserTest(tstring filePath) {
	PEParser peParser = PEParser();
	if (peParser.parsePE(filePath) == TRUE) {
		if (peParser.printDosHeader() == FALSE) {
			GetLastError(); 
			exit(-1);
		}
		if (peParser.printNTHeader() == FALSE) {
			GetLastError(); 
			exit(-1);
		}
		if (peParser.printImageSectionHeader() == FALSE) {
			GetLastError();
			exit(-1);
		}
		if (peParser.printEAT() == FALSE) {
			tcout << _T("EAT Do Not Exist In This Program!\n");
		}
		if (peParser.printIAT() == FALSE) {
			tcout << _T("IAT Do Not Exist In This Program!\n");
		}	
		if (peParser.printTLS() == FALSE) {
			tcout << _T("TLS Do Not Exist In This Program!\n");
		}
	}
}

void scannerTest(tstring filePath) {
	//아무 생각없이 ROP 기준으로 코드를 짜버려서 OOP 식으로 refactoring 필요함. TODO
		scanner::Scanner peScanner = scanner::Scanner();
		PEParse::PEParser peclass = PEParse::PEParser();
		HANDLE PEFileMapping = NULL;
		LPVOID peBaseAddress = NULL;
		DWORD textSectionSize = NULL;

		PEFileMapping = peclass.getPEFileMapping(filePath);
		peBaseAddress = peclass.getPEBaseAddress(PEFileMapping);
		textSectionSize = peScanner.getTextSectionSize(filePath);

		BYTE* textSectionBytes = new BYTE[textSectionSize];
		textSectionBytes = peScanner.getTextSectionBytes(filePath, textSectionSize);
		peScanner.debugTextSectionBytes(textSectionBytes, textSectionSize);
		tcout << _T("Printed every bytes of .text section.") << endl;
}