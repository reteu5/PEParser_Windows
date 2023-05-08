#include <iostream>
#include "PEParser.h"

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
	PEParser peParser = PEParser();
	tstring filePath = _T("=========== INPUT DESIRED FILE PATH HERE ===========");

	filePath = _T("C:\\Windows\\System32\\shell32.dll");
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
		/*if (peParser.printIAT() == FALSE) {
			tcout << _T("IAT Do Not Exist In This Program!\n");
		}*/	
		if (peParser.printTLS() == FALSE) {
			tcout << _T("TLS Do Not Exist In This Program!\n");
		}
	}
	return 0;
};