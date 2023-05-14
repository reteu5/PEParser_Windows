#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <windows.h>
#include <tchar.h>
#include "typedef.h"
#include "PEparser.h"
#include "scanner.h"

using namespace scanner;
using std::hex;

void scannerMain() {
	//dbg
	tcout << _T("ScannerMain() called") << std::endl;
	
	PEParse::PEParser peclass = PEParse::PEParser();

	HANDLE PEFileMapping = NULL;
	tstring filePath = _T("C:\\Windows\\System32\\shell32.dll");

	PEFileMapping = peclass.getPEFileMapping(filePath);
}

void Scanner::debug(tstring debugmsg) {
	OutputDebugStringT(debugmsg.c_str());
	OutputDebugStringT(_T("\n"));
}

<<<<<<< HEAD
//PE ���� ��θ� �Է¹޾� .text ������ ��ü ũ�⸦ ���ϴ� �Լ�
DWORD Scanner::getTextSectionSize(const tstring filePath) {
=======
//PE ???? ??��? ??��?? .text ?????? ??? ??? ????? ???
DWORD scanner::getTextSectionSize(const tstring filePath) {
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
	PEParse::PEParser peclass = PEParse::PEParser();
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = peclass.getPEFileMapping(filePath);
	peBaseAddress = peclass.getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)peBaseAddress + (WORD)peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));

    if (sectionHeader == NULL) 
        debug(_T("Error: Invalid Image Section Header\n"));
	else {
		for (int i = 0; i < (WORD)ntHeader->FileHeader.NumberOfSections; i++) {
			if ((char*)sectionHeader[i].Name == ".text") 
				// VirtualSize : ???? ???? ???. (NULL ?��? ????? ??.)
				return (DWORD)sectionHeader[i].Misc.VirtualSize;
		}
	}
	return NULL;
}

<<<<<<< HEAD
// �Ű������� �Է¹��� ũ�⸸ŭ�� �޸𸮸� �Ҵ��ϰ�, �Ҵ�� �޸𸮿� PE ������ .text ���� ����Ʈ�� ��ü�� �����ϴ� �Լ�
BYTE* Scanner::getTextSectionBytes(const tstring filePath, DWORD sectionSize) {
=======
// ????????? ??��??? ?????? ???? ??????, ???? ???? PE ?????? .text ???? ??????? ????? ??????? ???
BYTE* scanner::getTextSectionBytes(const tstring filePath, DWORD sectionSize) {
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
	PEParse::PEParser peclass = PEParse::PEParser(); 
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = peclass.getPEFileMapping(filePath);
	peBaseAddress = peclass.getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)peBaseAddress + (WORD)peDosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));

	if (sectionHeader == NULL) 
		debug(_T("Error: Invalid Image Section Header\n"));
	else {
		for (int i = 0; i < (WORD)ntHeader->FileHeader.NumberOfSections; i++) {
			if ((char*)sectionHeader[i].Name == ".text") {
				BYTE* sectionBytes = new BYTE[sectionSize];
				memcpy(sectionBytes, (BYTE*)peBaseAddress + sectionHeader[i].VirtualAddress, sectionSize);
				return sectionBytes;
			}
		}
	}
	return NULL;
}

<<<<<<< HEAD
//getTextSectionBytes �Լ����� �Ҵ��� �޸𸮸� �����ϴ� �Լ�
void Scanner::freeTextSectionBytes(BYTE* sectionBytes) {
	delete[] sectionBytes;
}

//getTextSectionBytes �Լ����� �Ҵ��� �޸𸮿� ���� �Ǽ��ڵ� ������ �˻��ϴ� �Լ�
BOOL Scanner::scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize) {
	// �Ǽ��ڵ� ������ ������ �迭
=======
// getTextSectionBytes ??????? ????? ???? ??????? ???
void Scanner::freeTextSectionBytes(BYTE* sectionBytes)
{
	delete[] sectionBytes;
}

// getTextSectionBytes ??????? ????? ???? ???? ?????? ?????? ?????? ???
BOOL Scanner::scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize) {
	// ?????? ?????? ?????? ?��
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
	BYTE malwarePattern[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56 };
	// ?????? ?????? ???
	DWORD malwarePatternSize = sizeof(malwarePattern) / sizeof(BYTE);

	// ?????? ?????? ????? ????? ??? ?????? ?????? ????? ?????? ????? ??? ??????? FALSE ???
	if (sectionSize < malwarePatternSize) 
		return FALSE;

	// ?????? ?????? ????? ????? ??? ?????? ?????? ????? ???? ?????? ??? ????
	for (int i = 0; i < sectionSize - malwarePatternSize; i++) {
		// ?????? ?????? ???? ???? ?????? ?????? ????? ???????? ???
		if (memcmp(sectionBytes + i, malwarePattern, malwarePatternSize) == 0) {
			// ?????? ????? ?????? TRUE ???
			return TRUE;
		}
	}
	// ?????? ????? ?????? ???? ??? ????? FALSE ???
	return FALSE;
}

<<<<<<< HEAD
// getTextSectionBytes �Լ����� �о�� ����Ʈ �� ��ü�� ����ϴ� ������ �Լ�
=======
// getTextSectionBytes ??????? ?��?? ????? ?? ????? ?????? ?????? ???
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
void Scanner::debugTextSectionBytes(BYTE* sectionBytes, DWORD sectionSize) {
	for (int i = 0; i < sectionSize; i++) {
		tcout << hex << (int)sectionBytes[i] << _T(" ");
		if (i % 16 == 15) 
			tcout << endl;
	}
}

<<<<<<< HEAD
// EntryPointSection ������ �̿��ؼ� ó�� ����Ǵ� �ڵ尡 ���Ե� ������ ã�� �Լ�
=======
//EntryPointSection ?????? ?????? ??? ?????? ??? ????? ?????? ??? ???
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
DWORD Scanner::getEntryPointSection(const tstring filePath) {
	PEParse::PEParser peclass = PEParse::PEParser();
	HANDLE peFileMapping = NULL;
	peFileMapping = peclass.getPEFileMapping(filePath);

}

<<<<<<< HEAD
//PE ���� ��θ� �Է¹޾� DEBUG_FILE_DIRECTORY�� ���� pdb ��θ� ���ϴ� �Լ�
=======
//PE ???? ??��? ??��?? DEBUG_FILE_DIRECTORY?? ???? pdb ??��? ????? ???
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
tstring Scanner::getPdbPath(const tstring filePath) {
	PEParse::PEParser peclass = PEParse::PEParser();
	HANDLE peFileMapping = NULL;
	peFileMapping = peclass.getPEFileMapping(filePath);

	if (peFileMapping != NULL) {
		IMAGE_DEBUG_DIRECTORY debugDirectory = {0, };
		DWORD callbackAddress = NULL;

		if ()
	}
}