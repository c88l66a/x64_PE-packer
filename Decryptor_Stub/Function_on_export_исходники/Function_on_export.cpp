#include <Windows.h>
#include <winternl.h>


DWORD HASH_DEK(const char *str);
int   Toupper_replace(int c);
extern "C" unsigned long long sqrt(long long l);
extern "C" long long          Factorize(long long num);
extern "C" void               Decrypt_Second_KEY(unsigned char *Result_of_factorization, unsigned char *Hint_Bytes, unsigned char *HB_position, unsigned char *decrypt_main_key);
extern "C" HMODULE            GetModuleHandleA_HASH_VERSION(DWORD Hash_Dll_Name, PPEB p_PEB);
extern "C" PVOID              GetProcAddress_HASH_VERSION(HMODULE hModule, DWORD HashApiName);


extern "C" HMODULE GetModuleHandleA_HASH_VERSION(DWORD Hash_Dll_Name, PPEB p_PEB)
{   

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
                return reinterpret_cast<HMODULE>(pDte->Reserved2[0]);
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
            PVOID pFunctionAddress = reinterpret_cast<PVOID>(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
            return pFunctionAddress;
        }
    }
    return NULL;
}

DWORD HASH_DEK(const char *str)
{
    unsigned int hash = 0;
    while (*str)
    {   
        hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
        *str++;
    }
    return hash;
}

int Toupper_replace(int c)
{
	if (c >= 'a' && c <= 'z') return c - 'a' + 'A';
	return c;
}

unsigned long long sqrt(long long l)
{
    unsigned long long res;
    unsigned long long div;
   
    res = l;
    div = l;

    if (l <= 0)
        return 0;
    while (1)
    {
        div =  (l / div + div) / 2;
        if (res > div)
            res = div;
        else
            return res;
    }
    return res;
}

long long Factorize(long long num)
{
    while (num % 2 == 0) {
        num /= 2;
        return 2;
    }

    for (int i = 3; i <= sqrt(num); i += 2) {
        while (num % i == 0) {
            num /= i;
            return i;
        }
    }

    if (num > 2) {
        return num;
    }

    return num;
}
