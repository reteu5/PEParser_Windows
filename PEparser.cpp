#include <iostream>
#include <iomanip>
#include <format>
#include <sstream>
#include "PEParser.h"
using namespace PEParse;
using std::endl;

PEParser::~PEParser() {
    clean();
};

void PEParser::clean() {
    if (m_peFileMapping != NULL)
    {
        UnmapViewOfFile(m_peBaseAddress);
        CloseHandle(m_peFileMapping);
    }
    if (m_peFileHandle != NULL)
    {
        CloseHandle(m_peFileHandle);
    }
    m_peDosHeader = NULL;
    m_peBaseAddress = NULL;
    m_peFilePath.clear();
};

void PEParser::debug(tstring debugMsg) {
    OutputDebugStringT(debugMsg.c_str());
    OutputDebugStringT(_T("\n"));
};

BOOL PEParser::parsePE(tstring filePath) {
    BOOL flag = FALSE;
    tstring debugmessage = _T("");

    clean();
    m_peFilePath = filePath;
    debugmessage = _T("Inputted File Path : ");
    debugmessage.append(m_peFilePath);
    debug(debugmessage);

    m_peFileHandle = CreateFile(m_peFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_peFileHandle == INVALID_HANDLE_VALUE) {
        debug(_T("Error: Failed to open file.\n"));
    }
    else {

        m_peFileMapping = CreateFileMapping(m_peFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m_peFileMapping == NULL) {
            CloseHandle(m_peFileHandle);
            m_peFileHandle = NULL;

            debug(_T("Error: Failed to create a file mapping.\n"));
        }
        else
        {
            m_peBaseAddress = MapViewOfFile(m_peFileMapping, FILE_MAP_READ, 0, 0, 0);
            if (m_peBaseAddress != NULL)
            {
                flag = TRUE;
            }
            else
            {
                CloseHandle(m_peFileMapping);
                CloseHandle(m_peFileHandle);
                m_peFileMapping = NULL;
                m_peFileHandle = NULL;
                debug(_T("Error: Cannot map view of file.\n"));
            }
        }
    }
    return flag;
};

BOOL PEParser::printDosHeader() {
    BOOL flag = FALSE;
    m_peDosHeader = (IMAGE_DOS_HEADER*)m_peBaseAddress;
    if (m_peDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        debug(_T("Error: Invalid DOS header signature\n"));
    }
    else
    {
        printFileSize();
        tcout << _T("DOS signature:0x") << std::hex << (WORD)m_peDosHeader->e_magic << endl;
        flag = TRUE;
    }
    return flag;
};

BOOL PEParser::printNTHeader() {
    BOOL flag = FALSE;
    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printFileSize();
        debug(_T("Error: Invalid NT header signature\n"));
    }
    else
    {
        if ((WORD)ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        {
            // 32bit PE
            printNTHeader32();
            flag = TRUE;
        }
        else
        {
            // 64bit PE
            printNTHeader64();
            flag = TRUE;
        }
    }
    return flag;
};

void PEParser::printNTHeader32() {
    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    tcout << _T("== this is 32 bit ==") << std::endl;

    tcout << _T("Offset to NT Header : 0x") << std::hex << (WORD)m_peDosHeader->e_lfanew << endl;
    tcout << _T("Machine type : 0x") << std::hex << (WORD)ntHeader->FileHeader.Machine << endl;
    tcout << _T("Size of Optional Header : 0x") << std::hex << ntHeader->FileHeader.SizeOfOptionalHeader << endl; //Image_OPTIONAL_HEADER32 丑厄元匹內勾仄天太 六天丑太
    tcout << _T("Number of sections : 0x") << std::hex << (WORD)ntHeader->FileHeader.NumberOfSections << endl;
    tcout << _T("Timestamp : 0x") << std::hex << (DWORD)ntHeader->FileHeader.TimeDateStamp << endl;
    tcout << _T("Entry point address : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
    tcout << _T("Image base address : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.ImageBase << endl;
    tcout << _T("Section alignment : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SectionAlignment << endl;
    tcout << _T("File alignment : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.FileAlignment << endl;
    tcout << _T("Size of image : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SizeOfImage << endl;
    tcout << _T("Size of headers : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SizeOfHeaders << endl;
    tcout << _T("Subsystem : 0x") << std::hex << (WORD)ntHeader->OptionalHeader.Subsystem << endl;
    tcout << _T("Number of RVA and sizes : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.NumberOfRvaAndSizes << endl;
};

void PEParser::printNTHeader64() {
    IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)m_peBaseAddress + (((IMAGE_DOS_HEADER*)m_peBaseAddress)->e_lfanew));

    std::stringstream stream;
    stream << (WORD)ntHeader->FileHeader.Machine;

    tcout << _T("Offset to NT Header : 0x") << std::hex << (WORD)m_peDosHeader->e_lfanew << endl;
    tcout << _T("Machine type : 0x") << std::hex << (WORD)ntHeader->FileHeader.Machine << endl;
    tcout << _T("Size of Optional Header : 0x") << std::hex << ntHeader->FileHeader.SizeOfOptionalHeader << endl;
    tcout << _T("Number of sections : 0x") << std::hex << (WORD)ntHeader->FileHeader.NumberOfSections << endl;
    tcout << _T("Timestamp : 0x") << std::hex << (DWORD)ntHeader->FileHeader.TimeDateStamp << endl;
    tcout << _T("Entry point address : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
    tcout << _T("Image base address : 0x") << std::hex << (ULONGLONG)ntHeader->OptionalHeader.ImageBase << endl;
    tcout << _T("Section alignment : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SectionAlignment << endl;
    tcout << _T("File alignment : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.FileAlignment << endl;
    tcout << _T("Size of image : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SizeOfImage << endl;
    tcout << _T("Size of headers : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SizeOfHeaders << endl;
    tcout << _T("Subsystem : 0x") << std::hex << (WORD)ntHeader->OptionalHeader.Subsystem << endl;
    tcout << _T("Number of RVA and sizes : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.NumberOfRvaAndSizes << endl;
};

void PEParser::printFileSize() {
    DWORD dwSize = GetFileSize(m_peFileHandle, 0);
    tcout << _T("Size of PE File : ") << std::dec << dwSize << " Byte" << endl;
}