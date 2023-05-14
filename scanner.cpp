#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <windows.h>
#include <tchar.h>
#include "PEparser.cpp"

using namespace scanner;

void scannerMain() {
	// dbg
	tcout << _T("scannerMain") << endl;
	HANDLE PEFileMapping = NULL;
	tstring filePath = _T("C:\\Windows\\System32\\shell32.dll");

	PEFileMapping = PEParser::getPEFileMapping(filePath);
}


//PE ���� ��θ� �Է¹޾� .text ������ ��ü ũ�⸦ ���ϴ� �Լ�
DWORD Scanner::getTextSectionSize(const tstring filePath) {
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = PEParser::getPEFileMapping(filePath);
	peBaseAddress = PEParser::getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)m_peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));

    if (sectionHeader == NULL) 
        debug(_T("Error: Invalid Image Section Header\n"));
	else {
		for (int i = 0; i < (WORD)ntHeader->FileHeader.NumberOfSections; i++) {
			if ((char*)sectionHeader[i].Name == ".text") 
				// VirtualSize : �޸𸮿� ž��� ũ��. (NULL �е� ���ܵ� ��.)
				return (DWORD)sectionHeader[i].Misc.VirtualSize;
		}
	}
	return NULL;
}

// �Ű������� �Է¹��� ũ�⸸ŭ�� �޸𸮸� �Ҵ��ϰ�, �Ҵ�� �޸𸮿� PE ������ .text ���� ����Ʈ�� ��ü�� �����ϴ� �Լ�
BYTE* Scanner::getTextSectionBytes(const tstring filePath, DWORD sectionSize) {
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = PEParser::getPEFileMapping(filePath);
	peBaseAddress = PEParser::getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)m_peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
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

// getTextSectionBytes �Լ����� �Ҵ��� �޸𸮸� �����ϴ� �Լ�
void Scanner::freeTextSectionBytes(BYTE* sectionBytes)
{
	delete[] sectionBytes;
}

// getTextSectionBytes �Լ����� �Ҵ��� �޸𸮿� ���� �Ǽ��ڵ� ������ �˻��ϴ� �Լ�
BOOL Scanner::scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize) {
	// �Ǽ��ڵ� ������ ������ �迭
	BYTE malwarePattern[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56 };
	// �Ǽ��ڵ� ������ ũ��
	DWORD malwarePatternSize = sizeof(malwarePattern) / sizeof(BYTE);

	// �Ǽ��ڵ� ������ �˻��� �޸��� ũ�Ⱑ �Ǽ��ڵ� ������ ũ�⺸�� ������ �˻��� �ʿ䰡 �����Ƿ� FALSE ��ȯ
	if (sectionSize < malwarePatternSize) 
		return FALSE;

	// �Ǽ��ڵ� ������ �˻��� �޸��� ũ�Ⱑ �Ǽ��ڵ� ������ ũ�⺸�� ũ�ų� ������ �˻� ����
	for (int i = 0; i < sectionSize - malwarePatternSize; i++) {
		// �Ǽ��ڵ� ������ ũ�⸸ŭ �޸𸮸� �˻��ؼ� �Ǽ��ڵ� ���ϰ� ��ġ�ϴ��� �˻�
		if (memcmp(sectionBytes + i, malwarePattern, malwarePatternSize) == 0) {
			// �Ǽ��ڵ� ���ϰ� ��ġ�ϸ� TRUE ��ȯ
			return TRUE;
		}
	}
	// �Ǽ��ڵ� ���ϰ� ��ġ�ϴ� ���� ã�� ���ϸ� FALSE ��ȯ
	return FALSE;
}

// getTextSectionBytes �Լ����� �о�� ����Ʈ �� ��ü�� ����ϴ� ������ �Լ�
void Scanner::debugTextSectionBytes(BYTE* sectionBytes, DWORD sectionSize) {
	for (int i = 0; i < sectionSize; i++) {
		tcout << hex << (int)sectionBytes[i] << _T(" ");
		if (i % 16 == 15) 
			tcout << endl;
	}
}

//EntryPointSection ������ �̿��ؼ� ó�� ����Ǵ� �ڵ尡 ���Ե� ������ ã�� �Լ�
DWORD Scanner::getEntryPointSection(const tstring filePath) {
	HANDLE peFileMapping = NULL;
	peFileMapping = PEParser::getPEFileMapping(filePath);
}

//PE ���� ��θ� �Է¹޾� DEBUG_FILE_DIRECTORY�� ���� pdb ��θ� ���ϴ� �Լ�
tstring Scanner::getPdbPath(const tstring filePath) {
	HANDLE peFileMapping = NULL;
	peFileMapping = PEParser::getPEFileMapping(filePath);

	
}