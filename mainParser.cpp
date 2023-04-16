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

	filePath = _T("C:\\Windows\\System32\\calc.exe");
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
		if (peParser.printIAT() == FALSE) {
			GetLastError();
			exit(-1);
		}	
	}
	return 0;
};