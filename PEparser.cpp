#include <iostream>
#include <iomanip>
#include <format>
#include <sstream>
#include <string>
#include "PEParser.h"
#define NEW_LINE tcout << _T("\n") << endl;
using namespace PEParse;
using std::endl;

PEParser::~PEParser() {
    clean();
};

void PEParser::clean() {
    if (m_peFileMapping != NULL) {
        UnmapViewOfFile(m_peBaseAddress);
        CloseHandle(m_peFileMapping);
    }
    if (m_peFileHandle != NULL) {
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
        else {
            m_peBaseAddress = MapViewOfFile(m_peFileMapping, FILE_MAP_READ, 0, 0, 0);
            if (m_peBaseAddress != NULL) {
                flag = TRUE;
            }
            else {
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
    else {
        tcout << _T("\n") << _T(" == DOS Header == ") << endl;
        printFileSize();
        tcout << _T("DOS signature : 0x") << std::hex << (WORD)m_peDosHeader->e_magic << endl;
        tcout << _T("Address of DOS Stub : 0x") << std::hex << (WORD)(m_peDosHeader->e_magic + 0x40) << endl;
        NEW_LINE;

        flag = TRUE;
    }
    return flag;
};

BOOL PEParser::printImageSectionHeader() {
    BOOL flag = FALSE;

    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));

    if (sectionHeader == NULL) {
        debug(_T("Error: Invalid Image Section Header\n"));
    }
    else {
        tcout << _T("\n") << _T(" == Image Section Header == ") << endl;
        for (int i = 0; i < (WORD)ntHeader->FileHeader.NumberOfSections; i++)
        {
            tcout << _T("Name of ") << (i+1) << _T("th Section : ") << (char*)sectionHeader[i].Name << endl;
            tcout << _T("Size of this Section Header: 0x") << std::hex << (WORD)sizeof(sectionHeader[i]) << endl;
            tcout << _T("VirtualAddress (M_Section Address starts): ") << (DWORD)sectionHeader[i].VirtualAddress << endl;
            tcout << _T("Virtual Size (M_Size of section(NULL padding X)): ") << (DWORD)sectionHeader[i].Misc.VirtualSize << endl;
            tcout << _T("PointerToRawData (F_Section Address starts): ") << (DWORD)sectionHeader[i].PointerToRawData << endl;
            tcout << _T("SizeOfRawData (F_Size of section(NULL padding O)): ") << (DWORD)sectionHeader[i].SizeOfRawData << endl;
            tcout << _T("PointerToRelocations : ") << (DWORD)sectionHeader[i].PointerToRelocations << endl;
            tcout << _T("PointerToLinenumbers : ") << (DWORD)sectionHeader[i].PointerToLinenumbers << endl;
            tcout << _T("NumberOfRelocations : ") << (WORD)sectionHeader[i].NumberOfRelocations << endl;
            tcout << _T("NumberOfLinenumbers : ") << (WORD)sectionHeader[i].NumberOfLinenumbers << endl;
            tcout << _T("Characteristics : ") << (DWORD)sectionHeader[i].Characteristics << endl;
            NEW_LINE;

            flag = TRUE;
        }
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
        tcout << _T(" == NT Header == ") << endl;
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

BOOL PEParser::printEAT() {
    BOOL flag = FALSE;
    int i = 0;
    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));
    DWORD RVAExport = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    //RVAExport : IED의 상대주소(RVA) 값을 담고 있음.
    IMAGE_SECTION_HEADER* SectionEAT = NULL;

    tcout << _T(" == EAT == ") << endl;
    if (RVAExport == 0) {
        debug(_T("Error: Failed to get virtual address of EAT from 'DataDirectory[0]'.\n"));
    }
    else {
        DWORD_PTR imageExportDirectoryVA = RVAExport + (DWORD_PTR)m_peBaseAddress;
        //imageExportDirecoryVA : 메모리 상에서 IED 구조체의 절대주소를 담고 있음.
        IMAGE_EXPORT_DIRECTORY* exportTable = (IMAGE_EXPORT_DIRECTORY*)imageExportDirectoryVA;
        //IEDexportTable : IED 구조체의 시작주소를 담는 포인터 변수.
        
        DWORD_PTR* numberofFunctions = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->NumberOfFunctions);
        DWORD_PTR* addressOfFunctions = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->AddressOfFunctions);

        DWORD_PTR* numberofNames = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->NumberOfNames);
        DWORD_PTR* addressOfNames = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->AddressOfNames);
        WORD* addressOfNameOrdinals = (WORD*)(imageExportDirectoryVA + exportTable->AddressOfNameOrdinals);
        

        tcout << _T("number of Functions in IED : ") << *numberofFunctions << endl;
        //int howmany = sizeof(exportTable->AddressOfNames) / sizeof(int);
        //printf("%d", howmany);
        printf("BBB test line\n");

        for (i = 0; i < exportTable->NumberOfFunctions; i++) {
            DWORD_PTR* functionNamePointer = (DWORD_PTR*)(addressOfNames);
            DWORD_PTR functionNameVA = (DWORD_PTR)(functionNamePointer[i] + (DWORD_PTR)m_peBaseAddress);
            tcout << _T("Function Name : ") << (char*)functionNameVA << endl;
        }
        NEW_LINE;
        printf("AAA test line\n");

        for (i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            printf("%d\n", i);
            if (sectionHeader[i].VirtualAddress <= RVAExport && RVAExport < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                SectionEAT = (IMAGE_SECTION_HEADER*)(sectionHeader + i);
                break;
            }
        }
        tcout << _T("Name of ExportTable : ") << (DWORD)(exportTable->Name) << endl;
        NEW_LINE;
        tcout << _T("EAT Section Name : ") << (char*)SectionEAT->Name << endl;
        tcout << _T("EAT Section Virtual Address : ") << SectionEAT->VirtualAddress << endl;
        tcout << _T("EAT Section Virtual Size : ") << SectionEAT->Misc.VirtualSize << endl;
        tcout << _T("EAT Section PointerToRawData : ") << SectionEAT->PointerToRawData << endl;
        tcout << _T("EAT Section SizeOfRawData : ") << SectionEAT->SizeOfRawData << endl;
        tcout << _T("EAT Section Characteristics : ") << SectionEAT->Characteristics << endl;
        NEW_LINE;
        tcout << _T("EAT RVA : ") << RVAExport << endl;
        tcout << _T("EAT VA : ") << imageExportDirectoryVA << endl;
        NEW_LINE;

        flag = TRUE;
    }
    return flag;
}

BOOL PEParser::printIAT() {
    BOOL flag = FALSE;
    int i = 0;
    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));
    DWORD RVAImport = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    //RVAExport : IED의 상대주소(RVA) 값을 담고 있음.
    IMAGE_SECTION_HEADER* SectionIAT = NULL;

    tcout << _T(" == IAT == ") << endl;
    if (RVAImport == 0) {
        printf("  RVAImport value ERROR!\n");
		debug(_T("Error: Failed to get virtual address of IAT from 'DataDirectory[1]'.\n"));
	}
    else {
        DWORD_PTR importTableVA = RVAImport + (DWORD_PTR)m_peBaseAddress; // convert RVA to VA
        for (i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].VirtualAddress <= RVAImport && RVAImport < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                SectionIAT = (IMAGE_SECTION_HEADER*)(sectionHeader + i);
                break;
            }
        }
        tcout << _T("IAT Section Name : ") << (char*)SectionIAT->Name << endl;
        tcout << _T("IAT Section Virtual Address : ") << SectionIAT->VirtualAddress << endl;
        tcout << _T("IAT Section Virtual Size : ") << SectionIAT->Misc.VirtualSize << endl;
        tcout << _T("IAT Section PointerToRawData : ") << SectionIAT->PointerToRawData << endl;
        tcout << _T("IAT Section SizeOfRawData : ") << SectionIAT->SizeOfRawData << endl;
        tcout << _T("IAT Section Characteristics : ") << SectionIAT->Characteristics << endl;
        tcout << _T("IAT RVA : ") << RVAImport << endl;
        tcout << _T("IAT VA : ") << importTableVA << endl;
        NEW_LINE;

        flag = TRUE;
    }
    return flag;
}

void PEParser::printNTHeader32() {
    IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    tcout << _T(" == this is 32 bit == ") << std::endl;

    tcout << _T("Offset to NT Header : 0x") << std::hex << (WORD)m_peDosHeader->e_lfanew << endl;
    tcout << _T("Machine type : 0x") << std::hex << (WORD)ntHeader->FileHeader.Machine << endl;
    tcout << _T("Size of NT Header ->  Signature : 0x") << std::hex << (WORD)ntHeader + sizeof(ntHeader->Signature) << endl;
    tcout << _T("Size of NT Header ->  Header : 0x") << std::hex << (WORD)ntHeader + sizeof(ntHeader->Signature) + sizeof(ntHeader->FileHeader) << endl;
    tcout << _T("Size of NT Header -> Optional Header : 0x") << std::hex << ntHeader->FileHeader.SizeOfOptionalHeader << endl; //Image_OPTIONAL_HEADER32 구조체의 크기
    tcout << _T("Number of sections : 0x") << std::hex << (WORD)ntHeader->FileHeader.NumberOfSections << endl;
    tcout << _T("Timestamp : 0x") << std::hex << (DWORD)ntHeader->FileHeader.TimeDateStamp << endl;
    tcout << _T("Entry point address : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
    tcout << _T("Optional Header -> Base of Code : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.BaseOfCode << endl;
    tcout << _T("Optional Headr -> Size of Code : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SizeOfCode << endl;
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
    tcout << _T("Size of NT Header ->  Signature : 0x") << std::hex << (WORD)ntHeader + sizeof(ntHeader->Signature) << endl;
    tcout << _T("Size of NT Header ->  Header : 0x") << std::hex << (WORD)ntHeader + sizeof(ntHeader->Signature) + sizeof(ntHeader->FileHeader) << endl;
    tcout << _T("Size of NT Header -> Optional Header : 0x") << std::hex << ntHeader->FileHeader.SizeOfOptionalHeader << endl;
    tcout << _T("Number of sections : 0x") << std::hex << (WORD)ntHeader->FileHeader.NumberOfSections << endl;
    tcout << _T("Timestamp : 0x") << std::hex << (DWORD)ntHeader->FileHeader.TimeDateStamp << endl;
    tcout << _T("Entry point address : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
    tcout << _T("Optional Header -> Base of Code : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.BaseOfCode << endl;
    tcout << _T("Optional Headr -> Size of Code : 0x") << std::hex << (DWORD)ntHeader->OptionalHeader.SizeOfCode << endl;
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