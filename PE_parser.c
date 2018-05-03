#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include <unistd.h>



typedef struct _IMAGE_DOS_HEADER
{
    uint8_t e_magic[2];
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint8_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
}_IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
}_IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
}_IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32
{
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionalAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    _IMAGE_DATA_DIRECTORY DataDirectory[16];
}_IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS
{
    uint32_t Signature;
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER32 OptionalHeader;
}_IMAGE_NT_HEADERS;



typedef struct _IMAGE_SECTION_HEADER
{
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
}_IMAGE_SECTION_HEADER;


int main(int argc, char ** argv)
{
    FILE *fptr;
    int sectionCount;
    // the PE Header
    unsigned char PeHeader[4];
    
    
    _IMAGE_DOS_HEADER Dos_header;
    _IMAGE_NT_HEADERS Nt_headers;
    _IMAGE_FILE_HEADER File_Header;
    _IMAGE_SECTION_HEADER Section_Header;
    _IMAGE_OPTIONAL_HEADER32  Optional_Header;
    
    if(argc == 1)
    {
        printf("No input File");
        return 0;
    }
    // Program exits if the file pointer returns NULL.
    fptr = fopen(argv[1], "r");
    if(fptr == NULL){
        printf("Error! opening file");
        return 0;
    }
    
    fread(&Dos_header, sizeof(_IMAGE_DOS_HEADER), 1, fptr);
    if(Dos_header.e_magic[0] =='M' && Dos_header.e_magic[1] == 'Z')
    {
    printf("\nValid Dos SIG '%c%c'\n'", Dos_header.e_magic[0], Dos_header.e_magic[1]);
    }
    else{
        printf("not a valid signature");
        return 0;
    }
    
    //    printf("sizeoimagedos %d\n", (int)sizeof(_IMAGE_DOS_HEADER));
    //    printf("Nt_headers %d\n", (int)sizeof(_IMAGE_NT_HEADERS));
    //    printf("FileHeader %d\n", (int)sizeof(_IMAGE_FILE_HEADER));
    //    printf("SectionHeader %d\n", (int)sizeof(_IMAGE_SECTION_HEADER));
    //    printf("Optional_Header %d\n", (int)sizeof(_IMAGE_OPTIONAL_HEADER32));
    printf("Address of PE header:\t%04X",Dos_header.e_lfanew);
    
    fseek(fptr, (long int)Dos_header.e_lfanew, SEEK_SET);
    fread(&PeHeader, sizeof(PeHeader), 1, fptr);
    printf("\nPE Header\t = 00%s\n", PeHeader);
    //    fread(&Nt_headers, sizeof(_IMAGE_NT_HEADERS),1, fptr);
    fread(&File_Header, sizeof(_IMAGE_FILE_HEADER),1, fptr);
    fread(&Optional_Header, sizeof(_IMAGE_OPTIONAL_HEADER32), 1, fptr);
    printf("Sections\t = %04x\n", File_Header.NumberOfSections);
    printf("Timestamp\t = %08X\n",File_Header.TimeDateStamp);
    printf("Entry Point\t = %08X\n", Optional_Header.AddressOfEntryPoint+Optional_Header.ImageBase);
    sectionCount = File_Header.NumberOfSections;
    for (int i = 0; i < sectionCount; i++) {
        fread(&Section_Header, sizeof(_IMAGE_SECTION_HEADER), 1, fptr);
        printf("\t%s\n", Section_Header.Name);
        printf("\t\tVirtual Address\t%08X\n", Section_Header.VirtualAddress+Optional_Header.ImageBase);
        printf("\t\tVirtual Size\t%08X\n", Section_Header.VirtualSize);
        printf("\t\tRaw size\t%08X\n", Section_Header.SizeOfRawData);
        printf("\t\tPointerRaw\t%08X\n\n", Section_Header.PointerToRawData);
    }
    printf("\nData Directory\t\tVirtual Address\tSize\n");
    printf("Export\t\t\t%08X",Optional_Header.DataDirectory[0].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[0].Size);
    printf("Import\t\t\t%08X",Optional_Header.DataDirectory[1].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[1].Size);
    printf("Resource\t\t%08X",Optional_Header.DataDirectory[2].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[2].Size);
    printf("Exception\t\t%08X",Optional_Header.DataDirectory[3].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[3].Size);
    printf("Security\t\t%08X",Optional_Header.DataDirectory[4].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[4].Size);
    printf("BASE_RLOC\t\t%08X",Optional_Header.DataDirectory[5].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[5].Size);
    printf("DEBUG\t\t\t%08X",Optional_Header.DataDirectory[6].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[6].Size);
    printf("Copyright\t\t%08X",Optional_Header.DataDirectory[7].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[7].Size);
    printf("Global_ptr\t\t%08X",Optional_Header.DataDirectory[8].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[8].Size);
    printf("TLS\t\t\t%08X",Optional_Header.DataDirectory[9].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[9].Size);
    printf("LOAD_CONFIG\t\t%08X",Optional_Header.DataDirectory[10].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[10].Size);
    printf("Bound_Import_Table\t%08X",Optional_Header.DataDirectory[11].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[11].Size);
    printf("Import Address Table\t%08X",Optional_Header.DataDirectory[12].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[12].Size);
    printf("Delay_Import_Desc\t%08X",Optional_Header.DataDirectory[13].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[13].Size);
    printf("CLI Header\t\t%08X",Optional_Header.DataDirectory[14].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[14].Size);
    printf("\t\t\t%08X",Optional_Header.DataDirectory[15].VirtualAddress);
    printf("\t%08X\n",Optional_Header.DataDirectory[15].Size);
    fclose(fptr);
    
    
}

