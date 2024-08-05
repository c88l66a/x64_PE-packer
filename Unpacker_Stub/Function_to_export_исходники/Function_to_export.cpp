#include <iostream>
#include <Windows.h>
#include <winternl.h>



extern "C" PVOID   GetProcAddress_HASH_VERSION(HMODULE hModule, DWORD HashApiName);
extern "C" HMODULE GetModuleHandleA_HASH_Version(DWORD hash_dll_name);
extern "C" void Fix_Import_Table(DWORD Import_Directory_RVA, ULONGLONG pBase, ULONGLONG Address_loadlibraryA_function, ULONGLONG Address_GetProcAddress_function);
extern "C" void Fix_relocation_Table(BYTE* loadedAddr, BYTE* preferableAddr, IMAGE_DATA_DIRECTORY* relocDir);

DWORD HASH_DEK(const char * str)
{
    unsigned int hash = 0;
    while (*str)
    {   
        hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
        *str++;
    }
    return hash;
}

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;


extern "C" void Fix_relocation_Table(BYTE* Image_Loaded_Address, BYTE* ImageBase_Before_reloc, IMAGE_DATA_DIRECTORY* Relocation_Directory)
{

	size_t maxSizeOfDir = Relocation_Directory->Size;
	size_t relocBlocks = Relocation_Directory->VirtualAddress;
	IMAGE_BASE_RELOCATION* relocBlockMetadata = NULL;

	if (Image_Loaded_Address != ImageBase_Before_reloc && Relocation_Directory !=0)
	{
		
		for (size_t relocBlockOffset = 0; relocBlockOffset < maxSizeOfDir; relocBlockOffset += relocBlockMetadata->SizeOfBlock)
		{
			relocBlockMetadata = reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocBlocks + relocBlockOffset + Image_Loaded_Address);

			if (relocBlockMetadata->VirtualAddress == 0 || relocBlockMetadata->SizeOfBlock == 0)
			{
				break;
			}

			size_t EntriesNum = (relocBlockMetadata->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
			size_t PageStart = relocBlockMetadata->VirtualAddress;
			
			BASE_RELOCATION_ENTRY* relocEntryCursor = reinterpret_cast<BASE_RELOCATION_ENTRY*>(reinterpret_cast<BYTE*>(relocBlockMetadata) + sizeof(IMAGE_BASE_RELOCATION));

			for (int i = 0; i < EntriesNum; i++)
			{
				if (relocEntryCursor->Type == 0)
				{
					continue;
				}

				ULONGLONG* relocation_Address = reinterpret_cast<ULONGLONG*>(PageStart + Image_Loaded_Address + relocEntryCursor->Offset);

				*relocation_Address = *relocation_Address + Image_Loaded_Address - ImageBase_Before_reloc;
				relocEntryCursor = reinterpret_cast<BASE_RELOCATION_ENTRY*>(reinterpret_cast<BYTE*>(relocEntryCursor) + sizeof(BASE_RELOCATION_ENTRY));
			}
		}
	}
}




typedef HMODULE (__fastcall* load_library_a_func)(const char* library_name);
typedef INT_PTR (__fastcall* get_proc_address_func)(HMODULE dll, const char* func_name);

extern "C" void Fix_Import_Table(DWORD Import_Directory_RVA, ULONGLONG pBase, ULONGLONG Address_loadlibraryA_function, ULONGLONG Address_GetProcAddress_function)
{

    load_library_a_func LoadLibA;
    LoadLibA = reinterpret_cast<load_library_a_func>(Address_loadlibraryA_function);

    get_proc_address_func Get_Proc_Address;
    Get_Proc_Address = reinterpret_cast<get_proc_address_func>(Address_GetProcAddress_function);

    //Если у файла имеются импорты
	if(Import_Directory_RVA)
	{
		//Виртуальный адрес первого дескриптора
		IMAGE_IMPORT_DESCRIPTOR* Description;
		Description = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(Import_Directory_RVA + pBase);
		//Перечисляем все дескрипторы
		//Последний - нулевой
		while(Description->Name)
		{
			//Загружаем необходимую DLL
			HMODULE dll;
			dll = LoadLibA(reinterpret_cast<char*>(Description->Name + pBase));
			//Указатели на таблицу адресов и lookup-таблицу
			ULONGLONG *lookup, *address;
			//Учтем, что lookup-таблицы может и не быть,
			//как я говорил в предыдущем шаге
			lookup = reinterpret_cast<ULONGLONG*>(pBase + (Description->OriginalFirstThunk ? Description->OriginalFirstThunk : Description->FirstThunk));
			address = reinterpret_cast<ULONGLONG*>(Description->FirstThunk + pBase);
			//Перечисляем все импорты в дескрипторе
			while(true)
			{
				//До первого нулевого элемента в лукап-таблице
				ULONGLONG lookup_value = *lookup;
				if(!lookup_value)
					break;
				//Проверим, импортируется ли функция по ординалу
				if(IMAGE_SNAP_BY_ORDINAL64(lookup_value))
					*address = static_cast<ULONGLONG>(Get_Proc_Address(dll, reinterpret_cast<const char*>(lookup_value & ~IMAGE_ORDINAL_FLAG64)));
				else
					*address = static_cast<ULONGLONG>(Get_Proc_Address(dll, reinterpret_cast<const char*>(lookup_value + pBase + sizeof(WORD))));
				//Переходим к следующему элементу
				++lookup;
				++address;
			}
			//Переходим к следующему дескриптору
			++Description;
		}
	}
}

int Toupper_replace(int c)
{
	if (c >= 'a' && c <= 'z') return c - 'a' + 'A';
	return c;
}

extern "C" HMODULE GetModuleHandleA_HASH_Version(DWORD Hash_Dll_Name)
{   
    // указатель на PEB
    PPEB p_PEB                   = reinterpret_cast<PPEB>(__readgsqword(0x60));
    PPEB_LDR_DATA p_Ldr_Data     = reinterpret_cast<PPEB_LDR_DATA>(p_PEB->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte   = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(p_Ldr_Data->InMemoryOrderModuleList.Flink);
    while (pDte)
    {
        if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < 0xff)
        {   
            
            if (!Hash_Dll_Name)
            {
                return reinterpret_cast<HMODULE>(pDte->Reserved2[0]);
            }

            char to_upper_char[0xff];          
            DWORD i = 0;
            while (pDte->FullDllName.Buffer[i])
            {
                to_upper_char[i] = static_cast<char>(Toupper_replace(pDte->FullDllName.Buffer[i]));
                i++;
            }

            to_upper_char[i] = '\0';
            DWORD Hashed_DLL_Name_string = HASH_DEK(to_upper_char);
            
            if (!(Hashed_DLL_Name_string - Hash_Dll_Name))
            {
                return reinterpret_cast<HMODULE>(reinterpret_cast<ULONGLONG>(pDte->Reserved2[0]));
            }
        }
        else
        {
            break;
        }

        pDte = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pDte);
    }
return NULL;
}


extern "C" PVOID GetProcAddress_HASH_VERSION(HMODULE hModule, DWORD Hash_Function_Name)
{   
    PBYTE pBase = reinterpret_cast<PBYTE>(hModule);

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    PDWORD FunctionNameArray = reinterpret_cast<PDWORD>(pBase + pImgExportDir->AddressOfNames);

    // Указатель на массив адресов функций
    PDWORD FunctionAddressArray = reinterpret_cast<PDWORD>(pBase + pImgExportDir->AddressOfFunctions);

    // Указатель на массив порядковых номеров функции
    PWORD  FunctionOrdinalArray = reinterpret_cast<PWORD>(pBase + pImgExportDir->AddressOfNameOrdinals);

    // Цикл по всем экспортированным функциям
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){

        char* pFunctionName = reinterpret_cast<char*>(pBase + FunctionNameArray[i]);

        WORD wFunctionOrdinal = FunctionOrdinalArray[i];

        DWORD Hashed_Funtion_Name_string = HASH_DEK(pFunctionName);
        if(!(Hash_Function_Name - Hashed_Funtion_Name_string))
        {   
            PVOID pFunctionAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONGLONG>(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]));
            return pFunctionAddress;
        }
    }
    return NULL;
}
