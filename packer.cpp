#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <memory>
#include <cmath>
#include <iomanip>
#include <vector>
#include <set>
#include <algorithm>
#include <random>
#include <chrono>
#include "structs_for_pack_and_unpack.h"
#include "./lzo-2.10/include/lzo/lzo1z.h"



// Функция для выравнивания секций в новом PE файле
DWORD align(DWORD size, DWORD align, DWORD addr);

// Для переработки ресурсов если они есть
std::string GetResource(BYTE* pBase, DWORD img_res_directory_rva_old, DWORD img_res_directory_rva_new);

int main(int argc, char * argv[])
{   
    // Для изменения цвета консоли
    HANDLE  hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	FlushConsoleInputBuffer(hConsole);

    if(argc < 2)
    {
        std::cout << "" << std::endl;
        std::cout << "How to use: packer.exe [input PE file] [Option]" << std::endl;
        CONSOLE_COLOR_BLUE
        std::cout << "" << std::endl;
        std::cout << "Option:" << std::endl;
        CONSOLE_COLOR_WHITE
        std::cout << "  -el   Encryption Layer" << std::endl;
        ExitProcess(0);
    }
    
    char* Input_PE_file = argv[1];
    bool  Encryption_option = 0;

    if((argv[2] != NULL) and strcmp(argv[2], "-el") == 0)
    {
        Encryption_option = 1;
    }

    HANDLE hFile = CreateFile(Input_PE_file, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if( hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] File don't open" << std::endl;
        ExitProcess(0);
    }

    DWORD FileSize = GetFileSize(hFile, 0);

    if(FileSize == INVALID_FILE_SIZE)
    {
        std::cout << "[-] GetFileSize: Failed" << std::endl;
        CloseHandle(hFile);
        ExitProcess(0);
    }

    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);

    if(hMapping == nullptr)
    {
        std::cout << "[-] CreateFileMapping: Failed" << std::endl;
        CloseHandle(hFile);
        ExitProcess(0);
    }

    // Указатель на входные данные PE файла
    unsigned char* pointer_on_input_PE_data= reinterpret_cast<unsigned char*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, FileSize));

    if(pointer_on_input_PE_data == nullptr)
    {
        std::cout << "[-] MapViewOfFile: Failed" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        ExitProcess(0);
    }

    // Считывание DOS Заголовока
    memcpy(&DOS_header, pointer_on_input_PE_data, sizeof(IMAGE_DOS_HEADER));
    
    // Проверка на то что входной файл исполняемый
    if(DOS_header.e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "[-] Input file is not PE" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        ExitProcess(0);
    }

    // Считывание NT Заголовока
    memcpy(&NT_header, pointer_on_input_PE_data + DOS_header.e_lfanew, sizeof(IMAGE_NT_HEADERS));
    
    // Проверка на то что входной файл x64 
    if(NT_header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        std::cout << "[-] Input PE file must be 64 bit" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        ExitProcess(0);
    }

    // Проверка на то что входной файл не DLL
    if(NT_header.FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        std::cout << "[-] Input PE file should not be DLL" << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        ExitProcess(0);
    }

    // Инициализация алгоритма сжатия LZO
    if(LZO_E_OK != lzo_init())
    {
        std::cout << "[-] LZO Initializing library: Failed" << std::endl;
        ExitProcess(0);
    }

                                            // ЗАПОЛНЕНИЕ СТРУКТУРЫ original_file_info
//===========================================================================================================================================
    original_file_info basic_info                           = {0};
    basic_info.Number_of_sections                           = NT_header.FileHeader.NumberOfSections;
    basic_info.Total_virtual_size_of_sections               = NT_header.OptionalHeader.SizeOfImage;
    basic_info.Original_entry_point                         = NT_header.OptionalHeader.AddressOfEntryPoint;
    basic_info.Original_rva_import_directory                = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    basic_info.Original_size_import_directory               = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    basic_info.Original_rva_resource_directory              = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    basic_info.Original_size_resource_directory             = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    basic_info.Original_rva_relocations_directory           = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    basic_info.Original_size_relocations_directory          = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    basic_info.Original_rva_exceptions_directory            = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    basic_info.Original_size_exceptions_directory           = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    basic_info.Original_rva_export_directory                = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    basic_info.Original_size_export_directory               = NT_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    basic_info.HASH_string__Kernel32DLL__                   = KERNE32_HASH;
    basic_info.HASH_string__VirtualAlloc__                  = VIRTUAL_ALLOC_HASH;
    basic_info.HASH_string__VirtualProtect__                = VIRTUAL_PROTECT_HASH;
    basic_info.HASH_string__VirtualFree__                   = VIRTUAL_FREE_HASH;
    basic_info.HASH_string__LoadLibrary__                   = LOAD_LIBRARY_A_HASH;
    basic_info.HASH_string__GetProcAddress__                = GET_PROC_ADDRESS_HASH;



                                        // ЗАПОЛНЕНИЕ СТРУКТУРЫ packed_section ЗАГОЛОВКАМИ СЕКЦИЙ
//===========================================================================================================================================
                                                                                            // Указатель на начало заголовка секций
    unsigned char* Pointer_Section_Header = pointer_on_input_PE_data +                      // pBase
                                            DOS_header.e_lfanew +                           // e_lfanew
                                            sizeof(DWORD) +                                 // PE_signature
                                            sizeof(IMAGE_FILE_HEADER) +                     // File Header
                                            NT_header.FileHeader.SizeOfOptionalHeader;      // szOptionalHeader
    
    std::cout << "[INFO] Reading sections..." << std::endl;
    std::string packed_sections_info;                                                       // Строка, которая будет хранить все секции входного PE файла
    packed_sections_info.resize(NT_header.FileHeader.NumberOfSections * sizeof(packed_section));

    std::string RAW_Data_Of_Setion;                                                         // Строка, которая будет хранить физические данные секций входного PE файла
    std::string resource_buff;                                                              // Под данные ресурсов (Если есть)

    for(int Current_Section = 0; Current_Section < NT_header.FileHeader.NumberOfSections; Current_Section++)
    {   
        memcpy(&Section_header, (Pointer_Section_Header + (sizeof(IMAGE_SECTION_HEADER) * Current_Section)), sizeof(IMAGE_SECTION_HEADER));                                                                                    
        packed_section& info = reinterpret_cast<packed_section&>(packed_sections_info[Current_Section * sizeof(packed_section)]);
        memset(info.Name, 0, sizeof(info.Name));
        memcpy(info.Name, Section_header.Name, 8);                                          // Имя секции
        info.Virtual_Size = Section_header.Misc.VirtualSize;                                // Виртуальный размер секции
        info.Virtual_Address = Section_header.VirtualAddress;                               // RVA секции
        info.Size_of_RAW_data = Section_header.SizeOfRawData;                               // Физический размер секции
        info.Pointer_to_RAW_data = Section_header.PointerToRawData;                         // Физический адрес секции    
        info.Characteristics = Section_header.Characteristics;                              // Характеристики секции    
        RAW_Data_Of_Setion.append(reinterpret_cast<const char*>(pointer_on_input_PE_data + Section_header.PointerToRawData), Section_header.SizeOfRawData);
        if (strcmp(info.Name, ".rsrc") == 0)                                                // если есть ресурсы
        {
            resource_buff.append(reinterpret_cast<const char*>(pointer_on_input_PE_data + Section_header.PointerToRawData), Section_header.SizeOfRawData);
        }
    }

                                                        // ФИЗИЧЕСКИЕ ДАННЫЕ СЕКЦИЙ
//===========================================================================================================================================
    packed_sections_info += RAW_Data_Of_Setion;
    std::cout << "       [*] Sections Reading completed." << std::endl;




                                            // ПОДГОТОВКА АЛГОРИТМА СЖАТИЯ lzo1z_999_compress
//===========================================================================================================================================
    std::string out_buf;                                                                    // Здесь будут лежать сжатые данные                                              
    std::unique_ptr<lzo_align_t> work_memory(new lzo_align_t[LZO1Z_999_MEM_COMPRESS]);
    lzo_uint src_length = packed_sections_info.size();

    basic_info.Size_of_source_data = src_length;                                            // Изначальный размер данных входного PE файла
    lzo_uint out_length = 0;
    out_buf.resize(src_length + src_length / 16 + 64 + 3);                                  // Необходимый размер буфера для сжатых данных

    DWORD start_time = GetTickCount();                                                      // Время старта алгоритма сжатия

    
    std::cout << "[INFO] Packing data..." << std::endl;    
    if(LZO_E_OK != lzo1z_999_compress(reinterpret_cast<const unsigned char*>(packed_sections_info.data()), 
                   src_length, 
                   reinterpret_cast<unsigned char*>(&out_buf[0]), 
                   &out_length, work_memory.get()))
    {
      std::cout << "       [-] lzo1z_999_compress: Failed" << std::endl;
      ExitProcess(0);
    }

    basic_info.Size_of_packed_data = out_length;                                           // Длина упакованных данных
    out_buf.resize(out_length);

    if(out_buf.size() >= src_length)                                                       // Проверка на то, что размер сжатых данных меньше оригинального размера
    {
        std::cout << "       [-] lzo1z_999_compress: File is incompressible" << std::endl;
        ExitProcess(0);
    }

    out_buf =    
    std::string(reinterpret_cast<const char*>(&basic_info), sizeof(basic_info))            // Данные структуры basic_info          
    + out_buf;                                                                             // Выходной буфер

    DWORD end_time = GetTickCount();                                                       // Время завершения алгоритма сжатия

    DWORD seconds = static_cast<float>(end_time - start_time) / 1000.0;

    std::cout << "       [*] Size Before packing : " << src_length << " Bytes"<< std::endl;
    std::cout << "       [*] Size After packing  : " << out_buf.size() << " Bytes"<< std::endl;
    float ratio = (((float)src_length - (float)out_buf.size()) / (float)src_length) * 100.0;
    std::cout << "       [*] Compression ratio   : " << std::setprecision(4) << ratio << " %"<< std::endl;
    std::cout << "       [*] Compression time    : " << seconds / 60 << "m:" << seconds % 60 << "s" << std::endl;
    std::cout << "       [*] Data has been Packed." << std::endl;

                                                // ШИФРОВАНИЕ СЖАТОГО БУФЕРА PE ФАЙЛА
//===========================================================================================================================================
    if(Encryption_option)
    {
        
        std::cout << "[INFO] Encryption..." << std::endl;
        *reinterpret_cast<ULONGLONG*>(&Unpacker_STUB[IMAGE_BASE_BEFORE_RELOC]) = NT_header.OptionalHeader.ImageBase;

        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();                            // Генерация seed`а для рандомизации 
        std::mt19937 generator(seed);
        std::uniform_int_distribution<int> distribution(20, 255);                                               // Числа от 20 до 255

        std::vector<uint8_t> Main_Key;                                                                          // Ключ которым будут зашифрованны сжатые данные и код распаковщика
        std::vector<uint8_t> Key_for_encrypting_Main_Key;                                                       // Ключ для шифрования Main Key

                                                                                                                // Генерация Main_Key
        for(int i = 0; i < MAIN_KEY_LENGHT; i++) Main_Key.push_back(distribution(generator));
                                                                                                                // Генерация Ключа для шифрования Main_Key
        for(int i = 0; i < SECONDERY_KEY_LENGHT; i++) Key_for_encrypting_Main_Key.push_back(distribution(generator));
            
                                                                                                                // Пул простых чисел для выборки Hint_Bytes
        std::vector<uint8_t> Prime_numbers_pool {2, 3, 5, 7, 11, 13, 17, 19, 23, 
                                                 29, 31, 37, 41, 43, 47, 53, 59, 
                                                 61, 67, 71, 73, 79, 83, 89, 97, 
                                                 101, 103, 107, 109, 113, 127, 131,
                                                 137, 139, 149, 151, 157, 163, 167, 
                                                 173, 179, 181, 191, 193, 197, 199, 
                                                 211, 223, 227, 229, 233, 239, 241, 251};
                                                                    
        std::vector<uint8_t> Hint_Bytes;                                                                        // Байты подсказки для расшифрования Main Key

        std::shuffle(Prime_numbers_pool.begin(), Prime_numbers_pool.end(), std::default_random_engine(seed));   // Перемешивание Hint_Bytes

        std::set<uint8_t> unique_elements;                                                                      // Множество, в котором будут уникальные Hint_Bytes

        for(int i = 0; i < Prime_numbers_pool.size(); i ++)                                                     
        {  
            unique_elements.insert(Prime_numbers_pool[i]);                                                      // Уникальные Hint_Bytes
            if(unique_elements.size() >= SECONDERY_KEY_LENGHT) break;
        }

        Hint_Bytes.assign(unique_elements.begin(), unique_elements.end());                                      // Добавление в Hint_Bytes

        std::shuffle(Hint_Bytes.begin(), Hint_Bytes.end(), std::default_random_engine(seed));                   // перемешивание Hint_Bytes еще раз

        ULONGLONG multiplication_of_prime_numbers_for_factorization = 1;                                        // Для перебора Key_for_encrypting_Main_Key путем факторизации

                                                                                                                // Результат произведение всех Hint_Bytes
        for(int i = 0; i < Hint_Bytes.size(); i ++) multiplication_of_prime_numbers_for_factorization *= Hint_Bytes[i];

        std::vector<uint8_t> Result_of_factorization;                                                           // Псевдо результат факторизации multiplication_of_prime_numbers_for_factorization
        Result_of_factorization.assign(Hint_Bytes.begin(), Hint_Bytes.end());                           

        std::sort(Result_of_factorization.begin(), Result_of_factorization.end());                              // Отсортированный в порядке возрастания псевдо результат факторизации 

        std::vector<uint8_t> HB_position;                                                                       // Позиции Hint_Bytes относительно Result_of_factorization
        for(int i = 0; i < Result_of_factorization.size(); i++)
        {
            for(int j = 0; j < Hint_Bytes.size(); j++)
            {
                  if(Result_of_factorization[i] == Hint_Bytes[j])   
                  {
                       HB_position.push_back(j);                                                                // Сохранение позиции
                  }
            }
        }
                                                                                                                // Шифрование сжатых данных, ключом Main_Key, а также вспомогательной структуры
        for(int i = 0; i < out_buf.size(); i++) out_buf[i] ^= Main_Key[i % MAIN_KEY_LENGHT];                    
                                                                                                                // Шифрование массива Unpacker_STUB, ключом Main_Key 
        for(int i = 0; i < sizeof(Unpacker_STUB); i++) Unpacker_STUB[i] ^= Main_Key[i % MAIN_KEY_LENGHT];
            

        std::cout << "       [*] Compressed Data and Unpacker Stub has been encrypted." << std::endl;
        
                                                                                                                // Шифрование Main_Key, ключом Key_for_encrypting_Main_Key
        for(int i = 0; i < Main_Key.size(); i++) Main_Key[i] ^= Key_for_encrypting_Main_Key[i % SECONDERY_KEY_LENGHT];
                                                                                                                // Шифрование Hint_Bytes для дальнейшего брута ключа Key_for_encrypting_Main_Key
        for(int i = 0; i < Hint_Bytes.size(); i++) Hint_Bytes[i] ^= Key_for_encrypting_Main_Key[i % SECONDERY_KEY_LENGHT];
                                                                                                                // Шифрование HB_position
        for(int i = 0; i < HB_position.size(); i++) HB_position[i] ^= Hint_Bytes[i];



     
                                // В результате после сжато-шифрованных данных и перед Таблицей импорта будут лежать следующие данные:

   //-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
  // Sz_Decryptor_Stubloader | CHECK_REMOTE_DEBUGGER_PRESENT_HASH | Sz_Enc_Data | Prime_Mult | HB_position | Hint_Bytes(encrypted) | Main_Key(encrypted) | KERNEL32_HASH | VP_HASH //   
 //-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//

        Crypto_Stub_info crypto_info = {0};
        crypto_info.Size_Decryptor_Stubloader                 = sizeof(Decryptor_STUB);                             // Размер заглушки Декриптора
        crypto_info.HASH_string__CheckRemoteDebuggerPresent__ = CHECK_REMOTE_DEBUGGER_PRESENT_HASH;                 // Хэш строки CheckRemoteDebuggerPresent
        crypto_info.Size_of_encrypted_data                    = out_buf.size();                                     // Размер шифрованных данных
        crypto_info.prime_MLT                                 = multiplication_of_prime_numbers_for_factorization;  // Произведение простых чисел

        Hash_STR HS = {0};
        HS.HASH_string__Kernel32DLL__                         = KERNE32_HASH;                                       // Хэш строки KERNEL32.DLL
        HS.HASH_string__VirtualProtect__                      = VIRTUAL_PROTECT_HASH;                               // Хэш строки VirtualProtect

        std::ostringstream Information_for_crypto_stub;

        for(int i = 0; i < HB_position.size(); i++) Information_for_crypto_stub << HB_position[i];                  // Позиции Hint_Bytes (Зашифрованные) относительно Result_of_factorization
        for(int i = 0; i < Hint_Bytes.size(); i++)  Information_for_crypto_stub << Hint_Bytes[i];                   // Hint_Bytes (Зашифрованные)
        for(int i = 0; i < Main_Key.size(); i++)    Information_for_crypto_stub << Main_Key[i];                     // Зашифрованный основной ключ
        

        out_buf += std::string(reinterpret_cast<const char*>(&crypto_info), sizeof(crypto_info));                   // Данные структуры Crypto_Stub_info          
        std::string Information_for_crypto_stub_str = Information_for_crypto_stub.str();
        out_buf += Information_for_crypto_stub_str;
        out_buf += std::string(reinterpret_cast<const char*>(&HS), sizeof(HS));                                     // Данные структуры Hash_STR         
    }



                                                // ПОДГОТОВКА К СОЗДАНИЮ НОВОГО PE ФАЙЛА
//===========================================================================================================================================



        // ****************************** ЭТАП I: СОЗДАНИЕ ЗАГОЛОВКОВ СЕКЦИЙ В НОВОМ PE ФАЙЛЕ ****************************** //
                

    
    std::cout << "[INFO] Creating Sections Header..."  << std::endl;
    memset(&compres_data_section, 0, sizeof(IMAGE_SECTION_HEADER));                                       // Затирание структуры compres_data_section нулями
    std::strcpy(reinterpret_cast<char*>(compres_data_section.Name), ".rsrc");                             // Имя секции .rsrc
    compres_data_section.VirtualAddress                    = 0x00001000;                                  // Виртуальный адрес
    compres_data_section.Misc.VirtualSize                  = NT_header.OptionalHeader.SizeOfImage         // Виртуальный размер
                                                           - compres_data_section.VirtualAddress;                          
    compres_data_section.PointerToRawData                  = 0x00000200;                                  // Физический адрес
    compres_data_section.PointerToRelocations              = 0x00000000;                                  // Не используется --- NULL
    compres_data_section.PointerToLinenumbers              = 0x00000000;                                  // Не используется --- NULL    
    compres_data_section.NumberOfRelocations               = 0x00000000;                                  // Не используется --- NULL
    compres_data_section.NumberOfLinenumbers               = 0x00000000;                                  // Не используется --- NULL
    compres_data_section.Characteristics                   = IMAGE_SCN_MEM_READ  |                        // Читать
                                                             IMAGE_SCN_MEM_WRITE |                        // Писать
                                                             IMAGE_SCN_MEM_EXECUTE;                       // Исполнять


    memset(&stubloader_section, 0, sizeof(IMAGE_SECTION_HEADER));
    std::strcpy(reinterpret_cast<char*>(stubloader_section.Name), ".text");                               // Имя секции .text
    stubloader_section.Misc.VirtualSize                  = 0x00001000 + (0x00003000 * Encryption_option); // Код распаковщика умещается в 1 страницу, код Декриптора умещается в 3 страницы
    stubloader_section.VirtualAddress                    = NT_header.OptionalHeader.SizeOfImage;
    stubloader_section.SizeOfRawData                     = sizeof(Unpacker_STUB) + (sizeof(Decryptor_STUB) * Encryption_option);
    stubloader_section.PointerToRelocations              = 0x00000000;   
    stubloader_section.PointerToLinenumbers              = 0x00000000;   
    stubloader_section.NumberOfRelocations               = 0x00000000;   
    stubloader_section.NumberOfLinenumbers               = 0x00000000;   
    stubloader_section.Characteristics                   = IMAGE_SCN_MEM_READ | 
                                                           IMAGE_SCN_MEM_EXECUTE;

    
    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::://
    //::                                                                                                                                             :://
    //:: Физический (выровненный) размер СЕКЦИИ [compres_data_section] Будет записан позже, так как физическая часть секции будет дополняться.       :://
    //:: Физический Адрес СЕКЦИИ [stubloader_section] будет записан позже, так как физическая часть секции [compres_data_section] будет дополняться. :://
    //::                                                                                                                                             :://
    //::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::://
    
    
    std::cout << "       [*] Sections Header has been created. "  << std::endl;


        // ********************************* ЭТАП II: СОЗДАНИЕ ФАЛЬШИВОЙ ТАБЛИЦЫ ИМПОРТА ********************************** //
    

    std::vector<uint8_t> Imports_Buffer_Data;                                      // Результирующий вектор, в котором будет находится данные IMPORT_DIRECTORY
    std::vector<std::string> DLL_NAMES = {"Kernel32.dll", "User32.dll"};           // Имена импортируемых DLL
    std::vector<DWORD> For_DLL_NAMES_Position;                                     // Вектор, в котором будут храниться RVA на имена DLL
    
    std::vector<std::string> fn_names_Kernel32_dll = {"GetLastError",              // Имена, импортируемых функций из KERNEL32.DLL
                                                      "GetCommandLineA", 
                                                      "ExitProcess", 
                                                      "lstrcmpA"};

    std::vector<std::string> fn_names_User32_dll =   {"GetWindowContextHelpId",    // Имена, импортируемых функций из USER32.DLL
                                                      "GetMenu", 
                                                      "MessageBoxA", 
                                                      "GetWindowInfo", 
                                                      "UpdateWindow"};
    std::vector <ULONGLONG> RVA_array_names_Kernel32_dll;                          // Вектор, в котором будут храниться RVA на имена импортируемых функций из KERNEL32.DLL
    std::vector <ULONGLONG> RVA_array_names_User32_dll;                            // Вектор, в котором будут храниться RVA на имена импортируемых функций из USER32.DLL
                                                                                
    int Sz_RVA_array_names_Kernel32_dll = (fn_names_Kernel32_dll.size() + 1) * 8;  // Переменные для дальнейшего подсчета структур IMAGE_IMPORT_DESCRIPTOR
    int Sz_RVA_array_names_User32_dll = (fn_names_User32_dll.size() + 1) * 8;      

    
    
    
    DWORD RVA_to_IMAGE_DIRECTORY_ENTRY_IMPORT =                                    // Подсчет RVA на указание начала Таблицы Имппорта [RVA = RAW + VirtualAddress - RAW_Offset]
                                        (0x200 + out_buf.size()) +                 // PE headers и Размер выходного буфера
                                        compres_data_section.VirtualAddress -      // VirtualAddress
                                        compres_data_section.PointerToRawData;     // RAW_Offset
                      
                      
    // Переменная для шага RVA импортируемых функций из DLL в Вектор, в который будут хранить RVA имен импортируемых функций                  
    int RVA_FN_step = RVA_to_IMAGE_DIRECTORY_ENTRY_IMPORT   +                      // RVA на начало Таблицы Имппорта
                      (sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3) +                      // Размер структур IMAGE_IMPORT_DESCRIPTOR + обозначение конца IMAGE_IMPORT_DESCRIPTOR
                      Sz_RVA_array_names_Kernel32_dll       +                      // Размер Вектора, в котором лежат RVA на имена импортируемых функций из KERNEL32.DLL
                      Sz_RVA_array_names_User32_dll;                               // Размер Вектора, в котором лежат RVA на имена импортируемых функций из USER32.DLL
                      

    
                                                                                  
    for(int i=0; i < fn_names_Kernel32_dll.size(); i++)                            // Заполненяем Imports_Buffer_Data, RVA_array_names_Kernel32_dll для дальнейшей записи в новый PE файл
    {                                                                                      
        RVA_array_names_Kernel32_dll.push_back(RVA_FN_step);                       // Заполняем вектор RVA_array_names_Kernel32_dll в котором будут лежать RVA На имена импортируемых функций
        RVA_FN_step += (fn_names_Kernel32_dll[i].size() + 3);

        for (int j = 0; j < fn_names_Kernel32_dll[i].size() + 3; j++)
        {
            if(j < 2 || j == fn_names_Kernel32_dll[i].size() + 2)
            {
                Imports_Buffer_Data.push_back(0);
                continue;
            }
            Imports_Buffer_Data.push_back(fn_names_Kernel32_dll[i][j-2]);           
        }
    }
                                                    
    RVA_array_names_Kernel32_dll.push_back(0);                                    // Для того чтобы загрузчик понял что идет конец RVA имен импортируемых функций из KERNEL32.DLL
                                                                                  
    for(int i=0; i < fn_names_User32_dll.size();i++)                              // Заполненяем Imports_Buffer_Data, RVA_array_names_User32_dll для дальнейшей записи в новый PE файл
    {                                                                                     
        RVA_array_names_User32_dll.push_back(RVA_FN_step);                        // Заполняем вектор RVA_array_names_User32_dll в котором будут лежать RVA На имена импортируемых функций 
        RVA_FN_step += (fn_names_User32_dll[i].size() + 3);

        for (int j = 0; j < fn_names_User32_dll[i].size() + 3; j++)
        {
            if(j < 2 || j == fn_names_User32_dll[i].size() + 2)
            {
                Imports_Buffer_Data.push_back(0);
                continue;
            }
            Imports_Buffer_Data.push_back(fn_names_User32_dll[i][j-2]);        
        }   
    }

    RVA_array_names_User32_dll.push_back(0);                                      // Для того чтобы загрузчик понял что идет конец RVA имен импортируемых функций из KERNEL32.DLL

    for(int i=0; i < DLL_NAMES.size();i++)
    {   
        For_DLL_NAMES_Position.push_back(RVA_FN_step);                            // Заполненяем Imports_Buffer_Data, DLL_NAMES для дальнейшей записи в новый PE файл
        RVA_FN_step += (DLL_NAMES[i].size() + 1);                                 // Заполняем вектор DLL_NAMES в котором будут лежать RVA на имена импортируемых DLL

        for (int j = 0; j < DLL_NAMES[i].size() ; j++)
        {
            Imports_Buffer_Data.push_back(DLL_NAMES[i][j]);
        }
        Imports_Buffer_Data.push_back(0);   
    }

                                                                                  
    image_import_descriptor__KERNEL32__DLL.OriginalFirstThunk = 0;                // Инициализация IMAGE_IMPORT_DESCRIPTOR (KERNEL32.DLL)
    image_import_descriptor__KERNEL32__DLL.TimeDateStamp = 0;
    image_import_descriptor__KERNEL32__DLL.ForwarderChain = 0;
    image_import_descriptor__KERNEL32__DLL.Name = For_DLL_NAMES_Position[0];      // RVA на имя импортируемой DLL (KERNEL32.DLL)
    image_import_descriptor__KERNEL32__DLL.FirstThunk =                           // RVA на массив с именами на RVA импортируемых функций (KERNEL32.DLL)
                                        sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3 +     
                                        RVA_to_IMAGE_DIRECTORY_ENTRY_IMPORT;
    
    image_import_descriptor__USER32__DLL.OriginalFirstThunk = 0;                  // Инициализация IMAGE_IMPORT_DESCRIPTOR (USER32.DLL)
    image_import_descriptor__USER32__DLL.TimeDateStamp = 0;
    image_import_descriptor__USER32__DLL.ForwarderChain = 0;
    image_import_descriptor__USER32__DLL.Name = For_DLL_NAMES_Position[1];        // RVA на имя импортируемой DLL (USER32.DLL)
    image_import_descriptor__USER32__DLL.FirstThunk =                             // RVA на массив с именами на RVA импортируемых функций (USER32.DLL)
                                        sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3 + 
                                        Sz_RVA_array_names_Kernel32_dll + 
                                        RVA_to_IMAGE_DIRECTORY_ENTRY_IMPORT;

    image_import_descriptor__END__ = {0};                                         // Обозначение конец структур IMAGE_IMPORT_DESCRIPTOR

    std::cout << "[INFO] Create Fake Import Table..."  << std::endl;
    std::cout << "       [*] Fake Import Table has been created. "  << std::endl;
 

        // ***************************************** ЭТАП III: ОБРАБОТКА РЕСУРСОВ ***************************************** //

    
    std::cout << "[INFO] Repacking resources..."  << std::endl;
    DWORD RVA_to_IMAGE_DIRECTORY_ENTRY_RESOURCE = 0;                             // Подсчет RVA на указание начала Таблицы Ресурсов
    std::string recycled_resources;                                             
    if(basic_info.Original_rva_resource_directory != 0)                          // Если есть ресурсы
    {   
        std::cout << "       [*] Resources Found."  << std::endl;
        RVA_to_IMAGE_DIRECTORY_ENTRY_RESOURCE = RVA_to_IMAGE_DIRECTORY_ENTRY_IMPORT + 
                                                      (3 * sizeof(IMAGE_IMPORT_DESCRIPTOR)) + 
                                                      Sz_RVA_array_names_Kernel32_dll + 
                                                      Sz_RVA_array_names_User32_dll + 
                                                      Imports_Buffer_Data.size();            

        recycled_resources = GetResource(reinterpret_cast<BYTE*>(const_cast<char*>(resource_buff.data())), 
                             basic_info.Original_rva_resource_directory, 
                             RVA_to_IMAGE_DIRECTORY_ENTRY_RESOURCE);
    }

    else
    {
        std::cout << "       [*] Resources don't Found."  << std::endl;
    }


     
//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

    // Так как в секции .rsrc будут кроме упакованных данных оригинального файла, Импорты и ресурсы(если они есть) то данный элемент структуры будет редактировать в конце
    int RAW_size = out_buf.size() +                             
                   (3 * sizeof(IMAGE_IMPORT_DESCRIPTOR)) +
                   Sz_RVA_array_names_Kernel32_dll +            
                   Sz_RVA_array_names_User32_dll + 
                   Imports_Buffer_Data.size() + 
                   recycled_resources.size();
    compres_data_section.SizeOfRawData = align(RAW_size, NT_header.OptionalHeader.FileAlignment, 0);   // Физический (выровненный) размер
    stubloader_section.PointerToRawData = 0x200 + compres_data_section.SizeOfRawData;                  // Физический адрес секции в которой будет лежать распаковщик

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------                  
//''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''





        // ************************************ ЭТАП IV: ПОДГОТОВКА ЗАГОЛОВКОВ НОВОГО PE ФАЙЛА ************************************ //

    
    DOS_header.e_lfanew = 0x40;                                                                         // Корректирование DOS заголовка
    NT_header.FileHeader.NumberOfSections = 2;                                                          // Корректирование NT заголовка

    
    NT_header.OptionalHeader.SizeOfImage = align(stubloader_section.Misc.VirtualSize,                   // Пересчет размера образа (нового PE файла) в памяти
                                                                              0x1000, 
                                                  stubloader_section.VirtualAddress);
                                                  
    NT_header.OptionalHeader.AddressOfEntryPoint = stubloader_section.VirtualAddress;                   // Новая точка входа
    IMAGE_DATA_DIRECTORY* dataDirectories = NT_header.OptionalHeader.DataDirectory;                     // Назначение новых значений для IMAGE_DATA_DIRECTORY


//===========================================================================================================================================
    dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = basic_info.Original_rva_export_directory;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = basic_info.Original_size_export_directory;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = RVA_to_IMAGE_DIRECTORY_ENTRY_IMPORT; 
    dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x3c;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = RVA_to_IMAGE_DIRECTORY_ENTRY_RESOURCE;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = recycled_resources.size();
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = basic_info.Original_rva_exceptions_directory;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = basic_info.Original_size_exceptions_directory;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress = 0;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size = 0;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
    //--------------------------------------------------------------
    dataDirectories[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    dataDirectories[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
//===========================================================================================================================================

    


    std::string base_file_name(Input_PE_file);
    std::string dir_name;
    std::string::size_type slash_pos;
    if((slash_pos = base_file_name.find_last_of("/\\")) != std::string::npos)
    {
        dir_name = base_file_name.substr(0, slash_pos + 1);                                             // Директория исходного файла
        base_file_name = base_file_name.substr(slash_pos + 1);                                          // Имя исходного файла
    }

    base_file_name = dir_name + "PAKED_" + base_file_name;

    std::ofstream out_file(base_file_name, std::ios::binary);


            // ************************************ ЭТАП V: ЗАПИСЬ ДАННЫХ В НОВЫЙ PE ФАЙЛ ************************************ //


    out_file.write(reinterpret_cast<char*>(&DOS_header), sizeof(IMAGE_DOS_HEADER));                     // Запись DOS загаловка в новый PE файл
    out_file.write(reinterpret_cast<char*>(&NT_header), sizeof(IMAGE_NT_HEADERS64));                    // Запись NT загаловка в новый PE файл

    out_file.write(reinterpret_cast<char*>(&compres_data_section), sizeof(IMAGE_SECTION_HEADER));       // Запись загаловка секций в новый PE файл
    out_file.write(reinterpret_cast<char*>(&stubloader_section), sizeof(IMAGE_SECTION_HEADER));         // Запись загаловка секций в новый PE файл

    while (out_file.tellp() != compres_data_section.PointerToRawData) out_file.put(0x0);                // Выравнивание до начала записи секции compres_data_section (.rsrc)
    for (size_t i = 0; i < out_buf.size(); i++) out_file.put(out_buf[i]);                               // Запись данных секции compres_data_section в новый PE файл
                                                                                                        // Запись таблицы импорта (Kernel32) в новый PE файл
    out_file.write(reinterpret_cast<char*>(&image_import_descriptor__KERNEL32__DLL), sizeof(IMAGE_IMPORT_DESCRIPTOR));
                                                                                                        // Запись таблицы импорта (User32) в новый PE файл
    out_file.write(reinterpret_cast<char*>(&image_import_descriptor__USER32__DLL),   sizeof(IMAGE_IMPORT_DESCRIPTOR));
                                                                                                        // Запись таблицы импорта (конец таблицы) в новый PE файл
    out_file.write(reinterpret_cast<char*>(&image_import_descriptor__END__),         sizeof(IMAGE_IMPORT_DESCRIPTOR));
                                                                                                        // Запись данных таблицы импорта (Kernel32) в новый PE файл
    out_file.write(reinterpret_cast<const char*>(RVA_array_names_Kernel32_dll.data()), RVA_array_names_Kernel32_dll.size() * sizeof(ULONGLONG));
                                                                                                        // Запись данных таблицы импорта (User32) в новый PE файл
    out_file.write(reinterpret_cast<const char*>(RVA_array_names_User32_dll.data()), RVA_array_names_User32_dll.size() * sizeof(ULONGLONG));
                                                                                                        // Запись имен функций таблицы импорта
    for (size_t i = 0; i < Imports_Buffer_Data.size(); i++) out_file.put(Imports_Buffer_Data[i]);

    if (recycled_resources.size() != 0)                                                                 // Если у входного файла были ресурсы
    {
        for (size_t i = 0; i < recycled_resources.size(); i++) out_file.put(recycled_resources[i]);     // Запись в новый PE файл, ресурсов входного файла
    }

    while (out_file.tellp() != stubloader_section.PointerToRawData) out_file.put(0x0);                  // Выравнивание до начала записи секции stubloader_section (.text)

    if(Encryption_option == 0) *reinterpret_cast<ULONGLONG*>(&Unpacker_STUB[IMAGE_BASE_BEFORE_RELOC]) = NT_header.OptionalHeader.ImageBase;
                                                                                                        // Запись данных секции stubloader_section в новый PE файл
    for (size_t i = 0; i < (sizeof(Decryptor_STUB) * Encryption_option); i++) out_file.put(Decryptor_STUB[i]);
    for (size_t i = 0; i < sizeof(Unpacker_STUB); i++) out_file.put(Unpacker_STUB[i]);

    CloseHandle(hMapping);
    CloseHandle(hFile);
    out_file.close();

    CONSOLE_COLOR_GREEN;
    
    std::cout << "" << std::endl;
    std::cout << "[INFO] PE File Packed Successfully " << std::endl;
    CONSOLE_COLOR_WHITE;
     


}



DWORD align(DWORD size, DWORD align, DWORD addr){
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}


std::string GetResource(BYTE* pBase, DWORD img_res_directory_rva_old, DWORD img_res_directory_rva_new)
{
    size_t S_for_copy_structs = 0;              // Размер корневой структуры IMAGE_RESOURCE_DIRECTORY
    size_t new_offset_for_structs_data = 0;
    bool for_check = true;
    std::string FOR_structs;
    std::string FOR_data_structs;

    IMAGE_RESOURCE_DIRECTORY* pResourceDir = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(pBase);
    IMAGE_RESOURCE_DIRECTORY_ENTRY* pTypeEntries = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(pResourceDir + 1);

    for (uint64_t ti = 0; ti < pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries; ti++)
    {
        IMAGE_RESOURCE_DIRECTORY_ENTRY* pTypeEntry = &pTypeEntries[ti];
        IMAGE_RESOURCE_DIRECTORY* pNamesDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(pBase + (pTypeEntry->OffsetToDirectory & 0x7FFFFFFF));
        for (uint64_t ni = 0; ni < pNamesDirectory->NumberOfNamedEntries + pNamesDirectory->NumberOfIdEntries; ni++)
        {
            IMAGE_RESOURCE_DIRECTORY_ENTRY* pNamesEntries = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(pNamesDirectory + 1);
            IMAGE_RESOURCE_DIRECTORY_ENTRY* pNameEntry = &pNamesEntries[ni];
            IMAGE_RESOURCE_DIRECTORY* pLangsDirectory = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(pBase + (pNameEntry->OffsetToDirectory & 0x7FFFFFFF));

            for (uint64_t li = 0; li < pLangsDirectory->NumberOfNamedEntries + pLangsDirectory->NumberOfIdEntries; li++)
            {
            
                IMAGE_RESOURCE_DIRECTORY_ENTRY* pLangsEntries = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(pLangsDirectory + 1);
                IMAGE_RESOURCE_DIRECTORY_ENTRY* pLangEntry = &pLangsEntries[li];
                IMAGE_RESOURCE_DATA_ENTRY* pDataEntry = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY*>(pBase + 0 + pLangEntry->OffsetToData);
                if (for_check and (0x7FFFFFFF & pTypeEntry->Name) <= 24)
                {
                    S_for_copy_structs = pDataEntry->OffsetToData - img_res_directory_rva_old;
                    new_offset_for_structs_data = S_for_copy_structs;
                    for_check = false;
                }

                if(pTypeEntry->Name == 0x3 || pTypeEntry->Name == 0xE || pTypeEntry->Name == 0x10 || pTypeEntry->Name == 0x18)
                {
                    FOR_data_structs += std::string(reinterpret_cast<char*>(pBase + pDataEntry->OffsetToData - img_res_directory_rva_old), pDataEntry->Size);
                    pDataEntry->OffsetToData = new_offset_for_structs_data + img_res_directory_rva_new;
                    new_offset_for_structs_data += pDataEntry->Size;
                }
            }
        }
    }
    FOR_structs += std::string (reinterpret_cast<char*>(pBase), S_for_copy_structs);
    FOR_structs += FOR_data_structs;
    return FOR_structs;
}


