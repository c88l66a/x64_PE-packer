include /masm32/include64/masm64rt.inc



;============================================================================================================================
extern GetModuleHandleA_HASH_Version    : proto                 ; Функция для получения адреса Kernel32.dll и ImageBase
extern GetProcAddress_HASH_VERSION      : proto                 ; Функция для получения адреса дополнительных функций
extern lzo1z_decompress                 : proto                 ; Функция для декомпрессии сжатых данных
extern memset                           : proto                 
extern memcpy                           : proto
extern Fix_Import_Table                 : proto                 ; Функция для восстановления таблицы импорта
extern Fix_relocation_Table             : proto                 ; Функция для восстановления таблицы релокаций
;============================================================================================================================





;============================================================================================================================
PAGE_READ_WRITE                         equ 4h                  ; Атрибут для изменения прав страницы (VirtualProtect)        
MEM_COMMIT                              equ 1000h               ; Параметр для выделения памяти (VirtualAlloc)
MEM_RELEASE                             equ 8000h               ; Параметр для освобождения выделенной памяти (VirtualFree)
;...............................................................................................................................................................
sz_Original_File_Info_structe           equ 51h                 ; Размер вспомогательной структуры, нужна для распаковки
sz_Packed_Section                       equ 1Ch                 ; Размер упакованной структуры
sz_PE_signature                         equ 4h                  ; Размер поля PE_signature
sz_Image_NT_Headers                     equ 108h                ; Размер NT_Header
sz_Image_File_Header                    equ 14h                 ; Размер структуры IMAGE_FILE_HEADER
sz_Image_Data_Directory                 equ 8h                  ; Размер структуры IMAGE_DATA_DIRECTORY
sz_Image_Section_Headers                equ 28h                 ; Размер структуры IMAGE_SECTION_HEADERS
;...............................................................................................................................................................
p__e_lfanew__                           equ 3Ch                 ; Указатель на elfanew
p__FileHeader_Machine__                 equ 2h                  ; Указатель на поле структуры IMAGE_FILE_HEADER
p__SizeOptionalHeader__                 equ 10h                 ; Указатель на размер Опционального заголовка в FileHeader
;...............................................................................................................................................................
IMAGE_NUMBEROF_DIRECTORY_ENTRIES        equ 10h                 ; Общее кол-во структур IMAGE_DATA_DIRECTORY
IMAGE_DIRECTORY_ENTRY_IMPORT            equ 1h                  ; Указатель от начала Таблицы Дерикторий на IMAGE_DIRECTORY_ENTRY_IMPORT
IMAGE_DIRECTORY_ENTRY_RESOURCE          equ 2h                  ; Указатель от начала Таблицы Дерикторий на IMAGE_DIRECTORY_ENTRY_RESOURCE
IMAGE_DIRECTORY_ENTRY_EXCEPTION         equ 3h                  ; Указатель от начала Таблицы Дерикторий на IMAGE_DIRECTORY_ENTRY_EXCEPTION
IMAGE_DIRECTORY_ENTRY_BASERELOC         equ 5h                  ; Указатель от начала Таблицы Дерикторий на IMAGE_DIRECTORY_ENTRY_BASERELOC
IMAGE_DIRECTORY_ENTRY_EXPORT            equ 0h                  ; Указатель от начала Таблицы Дерикторий на IMAGE_DIRECTORY_ENTRY_EXPORT
IMAGE_IMPORT_DESCRIPTOR                 equ 14h                 ; Размер структуры IMAGE_IMPORT_DESCRIPTOR
;============================================================================================================================





;============================================================================================================================
Image_Section_Headers struct
    neim                    qword ?                             ; Имя секции (почему не Name а neim, с Name не компилировалось)
    Virtual_Size            dword ?                             ; Виртуальный размер секции
    Virtual_Address         dword ?                             ; Виртуальный адрес секции
    Raw_size                dword ?                             ; Физический размер секции
    Raw_Address             dword ?                             ; Физический адрес секции                                               
    Reloc_Address           dword ?                             ; Не используется --- NULL
    Linenumbers             dword ?                             ; Не используется --- NULL
    Relocation_Nubmers      word  ?                             ; Не используется --- NULL
    Linenumbers_Numbers     word  ?                             ; Не используется --- NULL
    Characteristics         dword ?                             ; Характеристики секции (READ, WRITE, EXECUTE)
    
                                                                
Image_Section_Headers ends
;============================================================================================================================


.code
start:


Main proc

    ;*******************************
        mov rcx, 0AAAAAAAAAAAAAAAAh
        call STUBLOADER
    ;*******************************

    ret
Main endp


;****************
STUBLOADER proc

;============================================================================================================================
    ;######## ПЕРЕМЕННЫЕ ВСПОМОГАТЕЛЬНОЙ СТРУКТУРЫ ##########
    LOCAL Number_of_sections                  : byte            ; Кол-во секций в исходном PE файле
    LOCAL Size_of_packed_data                 : dword           ; Размер упакованных данных
    LOCAL Size_of_source_data                 : dword           ; Размер исходных данных
    LOCAL Total_virtual_size_of_sections      : dword           ; Виртуальный размер всех секций исходного PE файла
    LOCAL Original_entry_point                : dword           ; Оригинальная точка входа
    LOCAL Original_rva_import_directory       : dword           ; RVA директории импорта
    LOCAL Original_size_import_directory      : dword           ; Размер директории импорта
    LOCAL Original_rva_resource_directory     : dword           ; RVA директории ресурсов   
    LOCAL Original_size_resource_directory    : dword           ; Размер директории ресурсов
    LOCAL Original_rva_relocations_directory  : dword           ; RVA директории релокаций
    LOCAL Original_size_relocations_directory : dword           ; Размер директории релокаций

    LOCAL Original_rva_exceptions_directory   : dword           ; RVA директории исключений
    LOCAL Original_size_exceptions_directory  : dword           ; Размер директории исключений

    LOCAL Original_rva_export_directory       : dword           ; RVA директории экспорта
    LOCAL Original_size_export_directory      : dword           ; Размер директории экспорта

    LOCAL HASH_string__Kernel32DLL__          : dword           ; Хэш строка для получения адреса Kernel32.DLL
    LOCAL HASH_string__VirtualAlloc__         : dword           ; Хэш строка для получения адреса функции VirtualAlloc
    LOCAL HASH_string__VirtualProtect__       : dword           ; Хэш строка для получения адреса функции VirtualProtect
    LOCAL HASH_string__VirtualFree__          : dword           ; Хэш строка для получения адреса функции VirtualFree
    LOCAL HASH_string__LoadLibrary__          : dword           ; Хэш строка для получения адреса функции LoadLibrary
    LOCAL HASH_string__GetProcAddress__       : dword           ; Хэш строка для получения адреса функции GetProcAddress
    
    ;########### УКАЗАТЕЛЬ НА УПАКОВАННЫЕ ДАННЫЕ ###########
    LOCAL pPacked_Data                        : qword           ; Указатель на Вспомогательную структуру
    LOCAL RVA_first_section                   : dword           ; RVA первой секции
    LOCAL pBase                               : qword           ; Указатель на начало образа в процессе
    LOCAL ImageBase_Before_reloc              : qword           ; Указатель для проверки на релокацию pBase

    ;########### УКАЗАТЕЛЬ НА ВЫДЕЛЕННУЮ ПАМЯТЬ ############
    LOCAL pUnpacked_Memory                    : qword           ; Указатель на выделенную память VirtualAlloc

    ;############# ПЕРЕМЕННЫЕ ДЛЯ ДЕКОМПРЕСИИ ##############    
    LOCAL output_length_for_decompression     : qword   		; Для выходного размера кол-во расжатых данных
    LOCAL last_variable                       : qword           

    ;############# ПЕРЕМЕННЫЕ ДЛЯ ПАРСИНГА PE ##############
    LOCAL DOS__e_lfanew__                     : dword           ; указатель на NT_Header
    LOCAL File_Header__szOptionalHeader__     : word            ; Размер Опционального заголовка
    LOCAL Section_Header_offset               : qword           ; Указатель на начало заголовка секций
    LOCAL current_section_structure_position  : qword           ; Параметр для циклов по восстановлению заголовков секций а также данных секций
    LOCAL current_RAW_data_pointer            : qword           ; Параметр для циклов по восстановлению физических данных секций
    LOCAL offset_to_Directories               : qword           ; Указатель на Таблицу Директорий
    LOCAL Section_Headers_structure: Image_Section_Headers

    ;############ ПЕРЕМЕННАЯ ДЛЯ VirtualAlloc ##############
    LOCAL OldProtect                          : dword           ; Параметр для хранения атрибута после вызова функции VirtualProtect

    ;############## ПЕРЕМЕННЫЕ ДЛЯ АДРЕСОВ #################
    LOCAL KERNEL32DLL_address                 : qword           ; Адрес Библиотеки Kernel32.dll
    LOCAL Function_VirtualAlloc_address       : qword           ; Адрес Функции VirtualAlloc
    LOCAL Function_VirtualProtect_address     : qword           ; Адрес Функции VirtualProtect
    LOCAL Function_VirtualFree_address        : qword           ; Адрес Функции VirtualFree
    LOCAL Function_LoadLibrary_address        : qword           ; Адрес Функции LoadLibrary
    LOCAL Function_GetProcAddress_address     : qword           ; Адрес Функции GetProcAddress
;============================================================================================================================


    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ЕСЛИ ПРОИЗОЙДЕТ РЕЛОКАЦИЯ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov ImageBase_Before_reloc, rcx

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧАЕМ pBASE ОБРАЗА В ПРОЦЕССЕ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, NULL

        ;************************************
        call GetModuleHandleA_HASH_Version ;*
        ;************************************

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ УКАЗАТЕЛЬ НА ЗАПАКОВАННЫЕ ДАННЫЕ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov RVA_first_section, 1000h
    xor rcx, rcx
    xor ecx, RVA_first_section 
    add rax, rcx
    mov pPacked_Data, rax

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ КОЛ-ВО СЕКЦИЙ В ОРИГИНАЛЕ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov cl, byte ptr[rax]
    mov Number_of_sections, cl

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ РАЗМЕР УПАКОВАННЫХ ДАННЫХ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov ebx, dword ptr[rax + 1]
    mov Size_of_packed_data, ebx

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ РАЗМЕР НЕУПАКОВАННЫХ ДАННЫХ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov edx, dword ptr[rax + 5]
    mov Size_of_source_data, edx

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВИРУТАЛЬНЫЙ РАЗМЕР СЕКЦИЙ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov r8d, dword ptr[rax + 9]
    mov Total_virtual_size_of_sections, r8d

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ OEP ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov r9d, dword ptr[rax + 13]
    mov Original_entry_point, r9d

    ;¤¤¤¤¤¤¤¤¤¤¤¤ RVA И РАЗМЕР ОРИГИНАЛЬНОЙ ТАБЛИЦЫ ИМПОРТА ¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov r10d, dword ptr[rax + 17]
    mov Original_rva_import_directory, r10d
    
    mov r11d, dword ptr[rax + 21]
    mov Original_size_import_directory, r11d

    ;¤¤¤¤¤¤¤¤¤¤¤¤ RVA И РАЗМЕР ОРИГИНАЛЬНОЙ ТАБЛИЦЫ РЕСУРСОВ ¤¤¤¤¤¤¤¤¤¤¤¤
    mov edx, dword ptr[rax + 25]
    mov Original_rva_resource_directory, edx
    
    mov ecx, dword ptr[rax + 29]
    mov Original_size_resource_directory, ecx

    ;¤¤¤¤¤¤¤¤¤¤¤ RVA И РАЗМЕР ОРИГИНАЛЬНОЙ ТАБЛИЦЫ РЕЛОКАЦИЙ ¤¤¤¤¤¤¤¤¤¤¤¤
    mov r8d, dword ptr[rax + 33]
    mov Original_rva_relocations_directory, r8d

    mov r11d, dword ptr[rax + 37]
    mov Original_size_relocations_directory, r11d

    ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ХЭШ СТРОКИ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov r10d, dword ptr[rax + 41]
    mov HASH_string__Kernel32DLL__, r10d

    mov r9d, dword ptr[rax + 45]
    mov HASH_string__VirtualAlloc__, r9d

    mov ecx, dword ptr[rax + 49]
    mov HASH_string__VirtualProtect__, ecx

    mov edx, dword ptr[rax + 53]
    mov HASH_string__VirtualFree__, edx

    mov r11d, dword ptr[rax + 57]
    mov HASH_string__LoadLibrary__, r11d
    
    mov r8d, dword ptr[rax + 61]
    mov HASH_string__GetProcAddress__, r8d

    ;¤¤¤¤¤¤¤¤¤¤¤ RVA И РАЗМЕР ОРИГИНАЛЬНОЙ ТАБЛИЦЫ ИСКЛЮЧЕНИЙ ¤¤¤¤¤¤¤¤¤¤¤¤
    mov r11d, dword ptr[rax + 65]
    mov Original_rva_exceptions_directory, r11d

    mov r8d, dword ptr[rax + 69]
    mov Original_size_exceptions_directory, r8d


    ;¤¤¤¤¤¤¤¤¤¤¤ RVA И РАЗМЕР ОРИГИНАЛЬНОЙ ТАБЛИЦЫ ЭКСПОРТА ¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov r11d, dword ptr[rax + 73]
    mov Original_rva_export_directory, r11d

    mov r8d, dword ptr[rax + 77]
    mov Original_size_export_directory, r8d


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВЫЗОВ ФУНКИИ ДЛЯ ПОЛУЧЕНИЯ АДРЕСА KERNEL32.DLL ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov ecx, HASH_string__Kernel32DLL__

        ;************************************
        call GetModuleHandleA_HASH_Version ;*
        ;************************************

    mov KERNEL32DLL_address, rax

;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВОССТАНОВЛЕНИЕ АДРЕСА KERNEL32.DLL ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    not KERNEL32DLL_address
    mov eax, HASH_string__Kernel32DLL__
    xor KERNEL32DLL_address, rax


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЯ АДРЕСА ФУНКЦИИ [VirtualAlloc] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, KERNEL32DLL_address
    mov edx, HASH_string__VirtualAlloc__

        ;**********************************
        call GetProcAddress_HASH_VERSION ;*
        ;**********************************

    mov Function_VirtualAlloc_address, rax

;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВОССТАНОВЛЕНИЕ АДРЕСА ФУНКЦИИ [VirtualAlloc] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    not Function_VirtualAlloc_address
    mov r8d, HASH_string__VirtualAlloc__
    xor Function_VirtualAlloc_address, r8



;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВЫДЕЛЕНИЕ ПАМЯТИ ДЛЯ РАСПАКОВКИ ДАННЫХ [VirtualAlloc] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    xor rcx, rcx                            ; lpAddress
    xor rdx, rdx
    add edx, Size_of_source_data            ; Сколько выделить памяти
    xor r8d, r8d
    add r8d, MEM_COMMIT                     ; MEM_COMMIT 0x1000
    xor r9d, r9d
    add r9d, PAGE_READ_WRITE                ; PAGE_READWRITE 0x4

        ;************************************
        call Function_VirtualAlloc_address ;*
        ;************************************

    mov pUnpacked_Memory, rax

;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤  ДЕКОМПРЕСИЯ СЖАТЫХ ДАННЫХ В ВЫДЕЛЕННУЮ ПАМЯТЬ [lzo1z_decompress] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, pPacked_Data 
    add rcx, sz_Original_File_Info_structe      ; Указатель на начало запакованных данных + размер структуры (73 байт)
    xor rdx, rdx
    mov edx, Size_of_packed_data                ; Размер упакованных данных
    xor r8, r8
    mov r8, pUnpacked_Memory                    ; Адрес выделенной памяти (VirtualAlloc)
    mov output_length_for_decompression, 0      ; Размер распакованной памяти
    lea r9, output_length_for_decompression     
    mov last_variable, 0                        ; NULL

    ;***********************
    call lzo1z_decompress ;*                        
    ;***********************


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ УКАЗАТЕЛЯ НА ЗАГОЛОВОК СЕКЦИЙ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rax, pPacked_Data                          ; pBase + 0x1000
    and r11, 0
    mov r11d, RVA_first_section
    sub rax, r11

    add rax, p__e_lfanew__                         ; Указатель на e_lfanew 

    mov ecx, dword ptr [rax]
    mov DOS__e_lfanew__, ecx                       ; Значение e_lfanew

    sub rax, p__e_lfanew__

    add ecx, sz_PE_signature                          ; PE Signature
    add ecx, p__SizeOptionalHeader__               ; Указатель на SizeOptionalHeader

    add rax, rcx
    mov dx, word ptr [rax]
    mov File_Header__szOptionalHeader__ , dx       ; Значение SizeOptionalHeader

    mov rax, pPacked_Data
    sub rax, r11

    and rcx, 0
    add ecx, DOS__e_lfanew__
    add rax, rcx                                   ; e_lfanew
    add rax, sz_PE_signature                       ; PE Signature
    add rax, sz_Image_File_Header                  ; szImage_File_Header
    add ax, File_Header__szOptionalHeader__        ; SizeOptionalHeader
    mov Section_Header_offset, rax


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ОБНУЛЕНИЕ УПАКОВАННЫХ ДАННЫХ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    xor rcx, rcx
    add rcx, pPacked_Data                   ; Указатель откуда начать заполнять
    xor rdx, rdx                            ; Чем заполнить
    and r8, 0
    or r8d, Total_virtual_size_of_sections  ; Сколько раз заполнить
    sub r8d, RVA_first_section

        ;*************
        call memset ;*
        ;*************


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА ФУНКЦИИ [VirtualProtect] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

    mov rcx, KERNEL32DLL_address
    xor edx, edx
    mov edx, HASH_string__VirtualProtect__

        ;**********************************
        call GetProcAddress_HASH_VERSION ;*
        ;**********************************

    mov Function_VirtualProtect_address, rax


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВОССТАНОВЛЕНИЕ АДРЕСА ФУНКЦИИ [VirtualProtect] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    not Function_VirtualProtect_address
    and r8, 0
    xor r8d, HASH_string__VirtualProtect__
    xor Function_VirtualProtect_address, r8



;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ РЕДАКТИРОВАНИЕ ПРАВ СТРАНИЦЫ ПАМЯТИ [VirtualProtect] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, Section_Header_offset ; Указатель на начало заголовка секций
    xor rax, rax
    mov al, Number_of_sections
    and rdx, 0
    xor rdx, sz_Image_Section_Headers                    ; Размер региона, атрибуты защиты доступа которого необходимо изменить, в байтах. (Кол-во секций * размер заголовка секций)
    mul rdx
    mov rdx, rax

    xor r8, r8                     
    add r8, PAGE_READ_WRITE                              ; PAGE_READWRITE

    lea r9, OldProtect                                   ; Указатель на переменную куда попадут старые права страницы

        ;**************************************
        call Function_VirtualProtect_address ;*
        ;**************************************



;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: ПОДГОТОВКА К ЗАГРУЗКИ ИСХОДНОГО PE :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::




;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ЭТАП I:ВОССТАНОВЛЕНИЕ ЧИСЛА СЕКЦИЙ В ИСХОДНОМ PE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    mov rax, pPacked_Data 
    xor r11, r11
    or r11d, RVA_first_section
    sub rax, r11                         ; pBase
    xor rbx, rbx
    xor ebx, DOS__e_lfanew__
    add rax, rbx                         ; e_lfanew
    add al,  sz_PE_signature                ; PE Signature
    add al,  p__FileHeader_Machine__     ; FileHeader.Machine
    xor rdx, rdx
    add dl, Number_of_sections
    mov word ptr [rax], dx


;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ЭТАП II: ВОССТАНОВЛЕНИЕ ЗАГОЛОВКА СЕКЦИЙ А ТАКЖЕ ДАННЫХ ЭТИХ СЕКЦИЙ  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    and r10, 0
    or r10, Section_Header_offset

    xor current_section_structure_position, r10     ; Подготовка указателя на секции, для дальнейшего шага
    

    mov bl, Number_of_sections
    and r11, 0
    add r11, pUnpacked_Memory

    ; Обнуляем регистры
    xor rax, rax
    xor rcx, rcx
    xor rsi, rsi
    xor rdi, rdi
    xor r8, r8
    xor r9, r9
    xor r13, r13

    ; Получаем Базу
    mov rdx, pPacked_Data 
    xor r12, r12
    or r12d, RVA_first_section
    sub rdx, r12                         
    mov pBase, rdx

    ; Указатель на данные, для последующего копирования
    mov current_RAW_data_pointer, 0

_RESTORING_SECTION_HEADERS_:
    cmp bh, bl
    jz _End_RSH

    imul rdi, rsi, sz_Packed_Section

    mov r8, qword ptr[r11 + rdi]                            ; Name 8 Байт
    mov Section_Headers_structure.neim, r8
    add rdi, 8

    mov r8d, dword ptr[r11 + rdi]                           ; Virtual_Size
    mov Section_Headers_structure.Virtual_Size, r8d
    add rdi, 4

    mov r8d, dword ptr[r11 + rdi]                           ; Virtual_Address
    mov Section_Headers_structure.Virtual_Address, r8d
    add rdi, 4

    mov r8d, dword ptr[r11 + rdi]                           
    mov Section_Headers_structure.Raw_size, r8d             ; Raw_size
    add rdi, 4

    mov r8d, dword ptr[r11 + rdi]                           
    mov Section_Headers_structure.Raw_Address, r8d          ; Raw_Address

    mov Section_Headers_structure.Reloc_Address, 0           ; Reloc_Address
    mov Section_Headers_structure.Linenumbers, 0             ; Linenumbers
    mov Section_Headers_structure.Relocation_Nubmers, 0      ; Relocation_Nubmers
    mov Section_Headers_structure.Linenumbers_Numbers, 0     ; Linenumbers_Numbers

    add rdi, 4
    mov r8d, dword ptr[r11 + rdi]
    mov Section_Headers_structure.Characteristics, r8d       ; Characteristics

    ;``````````````````````````````` КОПИРУЕМ ЗАГОЛОВКИ СЕКЦИЙ ```````````````````````````````


    imul rax, rsi, sz_Image_Section_Headers                  ; Размер скопированных данных для передвижения current_section_structure_position
    add r10, rax
    mov rcx, r10                                             ; начало куда копировать 
    lea rdx, Section_Headers_structure                       ; Какие байты копировать 
    mov r8, sz_Image_Section_Headers                         ; Сколько байт считать

        ;*************
        call memcpy ;*
        ;*************

    mov r10, current_section_structure_position

    ;````````````````````````````````` КОПИРУЕМ ДАННЫЕ СЕКЦИЙ ````````````````````````````````

    mov rcx, pBase
    and r12, 0
    xor r12d, Section_Headers_structure.Virtual_Address 
    add rcx, r12                                             ; (pBase + Virtual_Address)

    mov rdx, pUnpacked_Memory
    xor rax, rax
    inc al
    mul Number_of_sections
    imul rax, rax, sz_Packed_Section
    add rax, current_RAW_data_pointer
    add rdx, rax                                             ; (pUnpacked_Memory + Number_of_sections * sz_Packed_Section + current_RAW_data_pointer)
    mov r13d, Section_Headers_structure.Raw_size             ; current_RAW_data_pointer = current_RAW_data_pointer + Raw_size
    add current_RAW_data_pointer, r13                        ; Raw_size
    mov r8, r13             

        ;*************
        call memcpy ;*
        ;*************   

    inc rsi
    inc bh
    jmp _RESTORING_SECTION_HEADERS_

_End_RSH:

    xor rdx, rdx
    xor r8, r8

;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЯ АДРЕСА ФУНКЦИИ [VirtualFree] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, KERNEL32DLL_address
    mov edx, HASH_string__VirtualFree__

        ;**********************************
        call GetProcAddress_HASH_VERSION ;*
        ;**********************************

    mov Function_VirtualFree_address, rax


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВОССТАНОВЛЕНИЕ АДРЕСА ФУНКЦИИ [VirtualFree] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    not Function_VirtualFree_address
    mov r8d, HASH_string__VirtualFree__
    xor Function_VirtualFree_address, r8



;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ОСВОБОЖДЕНИЕ ВЫДЕЛЕННОЙ ПАМЯТЯ [VirtualFree] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, pUnpacked_Memory
    mov rdx, 0
    mov r8, MEM_RELEASE

        ;***********************************
        call Function_VirtualFree_address ;*
        ;***********************************


;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ЭТАП III: ВОССТАНОВЛЕНИЕ ТАБЛИЦЫ ДЕРИКТОРИЙ ИСХОДНОГО PE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    
    mov rax, pBase
    and rdx, 0
    add edx, DOS__e_lfanew__
    add rax, rdx                    
    add rax, sz_Image_NT_Headers        
    xor rcx, rcx
    xor rcx, sz_Image_Data_Directory
    imul rcx, rcx, IMAGE_NUMBEROF_DIRECTORY_ENTRIES         
    sub rax, rcx                                            ; pBase + DOS__e_lfanew__ + sz_Image_NT_Headers - (sz_Image_Data_Directory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    mov offset_to_Directories, rax

    ;````````````````` ТАБЛИЦА ИМПОРТА ``````````````````
    mov rcx, rax
    mov rbx, sz_Image_Data_Directory
    imul rax, rbx, IMAGE_DIRECTORY_ENTRY_IMPORT
    add rcx, rax

    xor r8, r8
    mov r8d, Original_rva_import_directory
    mov dword ptr [rcx], r8d
    mov r8d, Original_size_import_directory
    mov dword ptr [rcx + 4], r8d

    ;````````````````` ТАБЛИЦА РЕСУРСОВ `````````````````
    mov rcx, offset_to_Directories
    mov rbx, sz_Image_Data_Directory
    imul rax, rbx, IMAGE_DIRECTORY_ENTRY_RESOURCE
    add rcx, rax

    xor r8, r8
    mov r8d, Original_rva_resource_directory     
    mov dword ptr [rcx], r8d
    mov r8d, Original_size_resource_directory    
    mov dword ptr [rcx + 4], r8d


    ;```````````````` ТАБЛИЦА ИСКЛЮЧЕНИЙ `````````````````
    mov rcx, offset_to_Directories
    mov rbx, sz_Image_Data_Directory
    imul rax, rbx, IMAGE_DIRECTORY_ENTRY_EXCEPTION
    add rcx, rax

    xor r8, r8
    mov r8d, Original_rva_exceptions_directory     
    mov dword ptr [rcx], r8d
    mov r8d, Original_size_exceptions_directory    
    mov dword ptr [rcx + 4], r8d


    ;````````````````` ТАБЛИЦА РЕЛОКАЦИЙ `````````````````
    mov rcx, offset_to_Directories
    mov rbx, sz_Image_Data_Directory
    imul rax, rbx, IMAGE_DIRECTORY_ENTRY_BASERELOC
    add rcx, rax

    xor r8, r8
    mov r8d, Original_rva_relocations_directory       
    mov dword ptr [rcx], r8d
    mov r8d, Original_size_relocations_directory     
    mov dword ptr [rcx + 4], r8d

    
    ;````````````````` ТАБЛИЦА ЭКСПОРТА `````````````````
    mov rcx, offset_to_Directories
    mov rbx, sz_Image_Data_Directory
    imul rax, rbx, IMAGE_DIRECTORY_ENTRY_EXPORT
    add rcx, rax

    xor r8, r8
    mov r8d, Original_rva_export_directory   
    mov dword ptr [rcx], r8d
    mov r8d, Original_size_export_directory
    mov dword ptr [rcx + 4], r8d
                        
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ЭТАП IV: ВОССТАНОВЛЕНИЕ ИМПОРТОВ ИСХОДНОГО PE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    xor rax, rax
    xor rcx, rcx
    xor rbx, rbx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11

;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА ФУНКЦИИ [LoadLibraryA] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, KERNEL32DLL_address
    mov edx, HASH_string__LoadLibrary__

        ;**********************************
        call GetProcAddress_HASH_VERSION ;*
        ;*********************************

    mov Function_LoadLibrary_address, rax

;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВОССТАНОВЛЕНИЕ АДРЕСА ФУНКЦИИ [LoadLibraryA] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    not Function_LoadLibrary_address
    mov r8d, HASH_string__LoadLibrary__
    xor Function_LoadLibrary_address, r8


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА ФУНКЦИИ [GetProcAddress] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, KERNEL32DLL_address
    mov edx, HASH_string__GetProcAddress__
    
        ;**********************************
        call GetProcAddress_HASH_VERSION ;*
        ;**********************************
    
    mov Function_GetProcAddress_address, rax


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВОССТАНОВЛЕНИЕ АДРЕСА ФУНКЦИИ [GetProcAddress] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    not Function_GetProcAddress_address
    mov r8d, HASH_string__GetProcAddress__
    xor Function_GetProcAddress_address, r8



;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ВОССТАНОВЛЕНИЕ ИМПОРТОВ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov ecx, Original_rva_import_directory
    mov rdx, pBase
    mov r8, Function_LoadLibrary_address
    mov r9, Function_GetProcAddress_address

        ;********************************
        call Fix_Import_Table          ;*
        ;********************************



;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  ЭТАП V: ВОССТАНОВЛЕНИЕ РЕЛОКАЦИЙ ИСХОДНОГО PE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    mov rcx, pBase
    and rdx, 0
    mov rdx, ImageBase_Before_reloc

    xor rax, rax
    mov rax, sz_Image_Data_Directory
    imul rax, rax, IMAGE_DIRECTORY_ENTRY_BASERELOC
    add rax, offset_to_Directories
    and r8, 0
    mov r8, rax

        ;********************************
        call Fix_relocation_Table      ;*
        ;********************************


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ МЕНЯЕМ ОБРАТНО АТРИБУТЫ ПАМЯТИ [VirtualProtect] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rcx, Section_Header_offset ; Указатель на начало заголовка секций
    xor rax, rax
    mov al, Number_of_sections
    and rdx, 0
    xor rdx, sz_Image_Section_Headers                    ; Размер региона, атрибуты защиты доступа которого необходимо изменить, в байтах. (Кол-во секций * размер заголовка секций)
    mul rdx
    mov rdx, rax
    xor r8, r8
    mov r8d, OldProtect
    lea r9, OldProtect                                   ; Указатель на переменную куда попадут старые права страницы

        ;**************************************
        call Function_VirtualProtect_address ;*
        ;**************************************


;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ОБРАЗ ИСХОДНОГО PE ВОССТАНОВЛЕН, ПЕРЕХОД НА OEP ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    mov rax, pBase
    xor r10, r10
    mov r10d, Original_entry_point
    add rax, r10

    leave

    jmp rax


    ret
STUBLOADER endp
;****************

end