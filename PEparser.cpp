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

HANDLE PEParser::getPEFileMapping(tstring filepath) {
    tstring debugmessage = _T("");
    
    clean();
    m_peFilePath = filepath;
    debugmessage = _T("Inputted File Path : ");
    debugmessage.append(m_peFilePath);
    debug(debugmessage);

    m_peFileHandle = CreateFile(m_peFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_peFileHandle == INVALID_HANDLE_VALUE) 
        debug(_T("Error: Failed to open file.\n"));
    else {
        m_peFileMapping = CreateFileMapping(m_peFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m_peFileMapping == NULL) {
            CloseHandle(m_peFileHandle);
            m_peFileHandle = NULL;

            debug(_T("Error: Failed to create a file mapping.\n"));
        }
        else {
            return m_peFileMapping;
        }
    }
    return NULL;
}

LPVOID PEParser::getPEBaseAddress(HANDLE peFileMapping) {
    LPVOID peBaseAddress = NULL;
    if (peFileMapping == NULL) {
            debug(_T("Error: Failed to create a file mapping.\n"));
            return NULL;
        }
        else {
            peBaseAddress = MapViewOfFile(peFileMapping, FILE_MAP_READ, 0, 0, 0);
            if (peBaseAddress != NULL) {
                return peBaseAddress;
            }
            else {
                CloseHandle(peFileMapping);
                m_peFileMapping = NULL;
                debug(_T("Error: Cannot map view of file.\n"));
                return NULL;
            }
        }
}

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
    tcout << _T("(DEBUG) RVA of EAT : 0x") << std::hex << RVAExport << endl;

    if (RVAExport == 0) {
        debug(_T("Error: It is unavailable to get virtual address of EAT from 'DataDirectory[0]'.\n"));
    }
    else {
        DWORD_PTR imageExportDirectoryVA = RVAExport + (DWORD_PTR)m_peBaseAddress;
        tcout << _T("Base of Image : 0x") << std::hex << (DWORD_PTR)m_peBaseAddress << endl;
        tcout << _T("VA of IED : 0x") << std::hex << imageExportDirectoryVA << endl;
        //imageExportDirecoryVA : 메모리 상에서 IED 구조체의 절대주소를 담고 있음.
        IMAGE_EXPORT_DIRECTORY* exportTable = (IMAGE_EXPORT_DIRECTORY*)imageExportDirectoryVA;
        //IEDexportTable : IED 구조체의 시작주소를 담는 포인터 변수.

        DWORD_PTR* numberofFunctions = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->NumberOfFunctions);
        DWORD_PTR* addressOfFunctions = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->AddressOfFunctions);

        DWORD_PTR* numberofNames = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->NumberOfNames);
        DWORD_PTR* addressOfNames = (DWORD_PTR*)(imageExportDirectoryVA + exportTable->AddressOfNames);
        WORD* addressOfNameOrdinals = (WORD*)(imageExportDirectoryVA + exportTable->AddressOfNameOrdinals);
        
        tcout << _T("RVAExport : 0x") << std::hex << RVAExport << endl;
        tcout << _T("m_peBaseAddress : 0x") << std::hex << (DWORD_PTR)m_peBaseAddress << endl;
        tcout << _T("addressOfNameOrdinals : 0x") << std::hex << addressOfNameOrdinals << endl;
        tcout << _T("addressOfNameOrdinals[1] : 0x") << std::hex << addressOfNameOrdinals + sizeof(WORD*) << endl;
        tcout << _T("addressOfNames : 0x") << std::hex << addressOfNames << endl;
        tcout << _T("addressOfNames[1] : 0x") << std::hex << addressOfNames + sizeof(WORD*) << endl;

        //IMAGE_EXPORT_DIRECTORY의 멤버인 AddressofNames 배열에 접근하여, 원소 담겨있는 메모리 주소에 접근하여 함수명을 가져와 출력한다.
        for (i = 0; i < exportTable->NumberOfNames; i++) {
            //nameRVA : IED의 AddressOfNames 배열의 원소들의 값들(함수명 문자열의 시작주소)을 담고 있음.
            DWORD_PTR nameRVA = (DWORD_PTR)addressOfNames + (sizeof(DWORD) * i);

            if (nameRVA >= RVAExport && nameRVA < RVAExport + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                tcout << _T("DEBUG) Success!") << endl;
                char* nameOfFunction = (char*)(addressOfNames + (sizeof(DWORD) * i));
                int ordinalOfFunction = addressOfNameOrdinals[i];

                DWORD_PTR addressOfFunction = addressOfFunctions[ordinalOfFunction];
                tcout << _T("Function Name : ") << nameOfFunction << endl;
                tcout << _T("Function Ordinal : ") << ordinalOfFunction << endl;
                tcout << _T("Function Address : 0x") << std::hex << addressOfFunction << endl;
                NEW_LINE;
                flag = TRUE;
            }
            tcout << _T("DEBUG) Failed!") << endl;
        }
    }
    return flag;
}

BOOL PEParser::printIAT() {
    BOOL flag = FALSE;
    int i = 0;
    tcout << _T(" == IAT == ") << endl;

    IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    tcout << _T("(DEBUG) ntHeader : ") << ntHeader << endl;
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));
    tcout << _T("(DEBUG) sectionHeader : ") << sectionHeader << endl;
    DWORD RVAImport = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    //RVAExport : IED의 상대주소(RVA) 값을 담고 있음.
    tcout << _T("(DEBUG) RVAImport : ") << RVAImport << endl;
    IMAGE_SECTION_HEADER* SectionIAT = NULL;

    if (RVAImport == 0) {
        printf("  RVAImport value ERROR!\n");
		debug(_T("Error: Failed to get virtual address of IAT from 'DataDirectory[1]'.\n"));
	}
    else {
        DWORD_PTR importTableVA = RVAImport + (DWORD_PTR)m_peBaseAddress; // convert RVA to VA
        for (i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].VirtualAddress <= RVAImport && RVAImport < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                tcout << _T("Found IAT from the section as descripted below..") << endl;
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


        tcout << _T("DEBUG STRING 01") << endl;
        //pe 파일이 32비트인지 64비트인지 if문을 통해 확인하여 구분.
        if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			IMAGE_IMPORT_DESCRIPTOR* importTable = (IMAGE_IMPORT_DESCRIPTOR*)importTableVA;
			//importTable : IAT 구조체의 시작주소를 담는 포인터 변수.
            while (importTable->Name != 0) {
                char* dllName = (char*)((DWORD_PTR)m_peBaseAddress + importTable->Name);
				tcout << _T("DLL Name : ") << dllName << endl;
				tcout << _T("DLL OriginalFirstThunk : ") << importTable->OriginalFirstThunk << endl;
				tcout << _T("DLL TimeDateStamp : ") << importTable->TimeDateStamp << endl;
				tcout << _T("DLL ForwarderChain : ") << importTable->ForwarderChain << endl;
				tcout << _T("DLL FirstThunk : ") << importTable->FirstThunk << endl;
				NEW_LINE;
				importTable++;
			}
		}
        else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			IMAGE_IMPORT_DESCRIPTOR* importTable = (IMAGE_IMPORT_DESCRIPTOR*)importTableVA;
			//importTable : IAT 구조체의 시작주소를 담는 포인터 변수.
            while (importTable->Name != 0) {
				//tcout << _T("DLL Name : ") << (char*)(importTableVA + importTable->Name) << endl;
                char* dllName = (char*)((DWORD_PTR)m_peBaseAddress + importTable->Name);
                tcout << _T("DLL Name : ") << dllName << endl;
				tcout << _T("DLL OriginalFirstThunk : ") << importTable->OriginalFirstThunk << endl;
				tcout << _T("DLL TimeDateStamp : ") << importTable->TimeDateStamp << endl;
				tcout << _T("DLL ForwarderChain : ") << importTable->ForwarderChain << endl;
				tcout << _T("DLL FirstThunk : ") << importTable->FirstThunk << endl;
				NEW_LINE;
				importTable++;
			}
		}
        else {
			debug(_T("Error: Failed to get magic number of optional header.\n"));
		}
        flag = TRUE;
    }
    return flag;
}

BOOL PEParser::printTLS() {
    BOOL flag = FALSE;
    IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));
    DWORD RTVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    IMAGE_SECTION_HEADER* SectionTLS = NULL;

    tcout << _T(" == TLS == ") << endl;

    if (RTVA == 0) {
		printf("  RTVA value ERROR!\n");
    }
    else {
        //TLSDirectory에 존재하는 구조체 변수들을 하나씩 파싱하여 출력함
        IMAGE_TLS_DIRECTORY64* TLSDirectory = (IMAGE_TLS_DIRECTORY64*)(RTVA + (DWORD_PTR)m_peBaseAddress);
        tcout << _T("TLS Directory VA : ") << RTVA << endl;
        tcout << _T("TLS Directory RVA : ") << TLSDirectory << endl;
        tcout << _T("TLS Directory StartAddressOfRawData : ") << TLSDirectory->StartAddressOfRawData << endl;
        tcout << _T("TLS Directory EndAddressOfRawData : ") << TLSDirectory->EndAddressOfRawData << endl;
        tcout << _T("TLS Directory AddressOfIndex : ") << TLSDirectory->AddressOfIndex << endl;
        tcout << _T("TLS Directory AddressOfCallBacks : ") << TLSDirectory->AddressOfCallBacks << endl;
        tcout << _T("TLS Directory SizeOfZeroFill : ") << TLSDirectory->SizeOfZeroFill << endl;
        tcout << _T("TLS Directory Characteristics : ") << TLSDirectory->Characteristics << endl;
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

BOOL printpdb() {
    BOOL result = FALSE;
    SIZE_T sizeofRead = 0;

    if ()

    return result;
}