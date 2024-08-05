extern GetProcAddress_HASH_VERSION   : proto                            ; Функция, для получения адреса функции, по ее хэшу
extern GetModuleHandleA_HASH_VERSION : proto                            ; Функция, для получения ImageBase DLL, по ее хэшу
extern Exit                          : proto                            ; Необходима для выхода должным образом
extern Factorize                     : proto                            ; Функция для факторизации простого числа






offset_to_PEB                                     equ     60h           ; Смещение, для получение адреса PEB
;------------------------------------------------------------
offset_to_LDR                                     equ     18h           ; Смещение на структуру PEB_LDR_DATA
offset_to_InMemoryOrderModuleList                 equ     20h           ; Смещение на структуру LIST_ENTRY
offset_to_ModuleBase                              equ     20h           ; Смещение в структуре LDR_DATA_TABLE_ENTRY на поле с адресом модуля
;------------------------------------------------------------
offset_to__e_lfanew__                             equ     3Ch           ; Смещение на elfanew
offset_to__SizeOptionalHeader__                   equ     10h           ; Смещение на поле структуры IMAGE_FILE_HEADER
;------------------------------------------------------------
sz_PE_signature                                   equ     4h            ; Размер поля PE_signature
sz_Image_File_Header                              equ     14h           ; Размер структуры IMAGE_FILE_HEADER
sz_Image_Data_Directory                           equ     8h            ; Размер структуры IMAGE_DATA_DIRECTORY
sz_Image_Section_Headers                          equ     28h           ; Размер структуры IMAGE_SECTION_HEADERS
;------------------------------------------------------------
IMAGE_NUMBEROF_DIRECTORY_ENTRIES                  equ     10h           ; Общее кол-во структур IMAGE_DATA_DIRECTORY
IMAGE_DIRECTORY_ENTRY_IMPORT                      equ     1h            ; Смещение от начала Таблицы Дерикторий на IMAGE_DIRECTORY_ENTRY_IMPORT
;------------------------------------------------------------
MAIN_KEY_LENGHT                                   equ     40h           ; Длинна ключа расшифрования 
sz_Hint_Bytes_array                               equ     8h            ; Длинна массива Hint_Bytes  (encrypted)
sz_HB_position_array                              equ     8h            ; Длинна массива HB_position (encrypted)
sz_Prime_Mult                                     equ     8h            ; Размер числа для дальнейшей факторизации
sz_2_HASH_string                                  equ     8h            ; Размер 2 хэш-строк KERNAL32.DLL и VirtualProtect
sz_Enc_Data                                       equ     4h            ; Размер зашифрованных (сжатых) данных



.code
start:
Main proc
;####################### АДРЕС PEB ########################
LOCAL PEB_address                         : qword                       ; Адрес Блока окружения процесса (Process Environment Block)
;################# АДРЕС ЗАГРУЗКИ ОБРАЗА ##################
LOCAL pBase                               : qword                       ; Адрес по которому загрузиться образ в память (ImageBase)
;############## ПЕРЕМЕННЫЕ ДЛЯ ПАРСИНГА PE ################
LOCAL Import_Table                        : qword                       ; Адрес Таблицы Импортов
LOCAL Section_Header                      : qword                       ; Адрес заголовков секций
;############ ПЕРЕМЕННЫЕ Virtual Protect ##################
LOCAL OldProtect                          : dword                       ; Параметр для хранения прошлых атрибутов страницы памяти (VirtualProtect)
;############## ПЕРЕМЕННЫЕ ДЛЯ ХЭШ СТРОК ##################
LOCAL Kernel32Dll_HASH                    : dword                       ; хэш строки KERNEL32.DLL
LOCAL VirtualProtect_HASH                 : dword                       ; хэш строки VirtualProtect
LOCAL CheckRemoteDebuggerPresent_HASH     : dword                       ; хэш строки CheckRemoteDebuggerPresent
;############# ПЕРЕМЕННЫЕ ДЛЯ РАСШИФРОВАНИЯ ###############
LOCAL ptr_on_anti_debug_hash_str          : qword                       ; Указатель на хэш строку функции CheckRemoteDebuggerPresent и размера заглушки Декриптора
LOCAL Sz_Encryption_Data                  : dword                       ; Размер зашифрованных (сжатых) данных
LOCAL Sz_Decryptor_Stubloader             : dword                       ; Размер заглушки декриптора
LOCAL Prime_Mult                          : qword                       ; Число для факторизации
;########## ПЕРЕМЕННЫЕ ДЛЯ БАЙТОВ ПОДСКАЗОК ###############
LOCAL HB_POS                              : qword                       ; Позиции Hint_Bytes относительно факторизованного Prime_Mult
LOCAL ENCRYPTED_HINT_BYTES                : qword                       ; Зашифрованные Hint_Bytes
LOCAL Factor_HB_1                         : byte                        ; 1 Hint_Byte полученный в результате факторизации Prime_Mult
LOCAL Factor_HB_2                         : byte                        ; 2 Hint_Byte полученный в результате факторизации Prime_Mult
LOCAL Factor_HB_3                         : byte                        ; 3 Hint_Byte полученный в результате факторизации Prime_Mult
LOCAL Factor_HB_4                         : byte                        ; 4 Hint_Byte полученный в результате факторизации Prime_Mult
LOCAL Factor_HB_5                         : byte                        ; 5 Hint_Byte полученный в результате факторизации Prime_Mult
LOCAL Factor_HB_6                         : byte                        ; 6 Hint_Byte полученный в результате факторизации Prime_Mult
LOCAL Factor_HB_7                         : byte                        ; 7 Hint_Byte полученный в результате факторизации Prime_Mult
LOCAL Factor_HB_8                         : byte                        ; 8 Hint_Byte полученный в результате факторизации Prime_Mult
;########## ПЕРЕМЕННЫЕ ДЛЯ ОСНОВНОГО КЛЮЧА ################
LOCAL MAIN_KEY_ADDRESS                    : qword                       ; Адрес начала зашифрованного MAIN_KEY
LOCAL MAIN_KEY_PART_0                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 0
LOCAL MAIN_KEY_PART_1                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 1
LOCAL MAIN_KEY_PART_2                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 2
LOCAL MAIN_KEY_PART_3                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 3
LOCAL MAIN_KEY_PART_4                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 4
LOCAL MAIN_KEY_PART_5                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 5
LOCAL MAIN_KEY_PART_6                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 6
LOCAL MAIN_KEY_PART_7                     : qword                       ; Часть основного ключа для расшифрования заглушки распаковщика и шифрованных (сжатых) данных под № 7
LOCAL MAIN_KEY_STACK[64]                  : byte                        ; Массив в котором будут находится адреса, по которым будут лежать части основного ключа {№ 0...№ 7}
;########## ПЕРЕМЕННАЯ ДЛЯ ВТОРИЧНОГО КЛЮЧА ###############
LOCAL SECOND_KEY                          : qword                       ; Для вторичного ключа, при помощи которого будет расшифрованние MAIN_KEY
;######## ПЕРЕМЕННАЯ ДЛЯ ФАКТОРИЗИРОВАННОГО ЧИСЛА #########
LOCAL FACTOR_RESULT                       : qword                       ; Результат факторизации числа Prime_Mult
;######### ПЕРЕМЕННЫЕ ДЛЯ АДРЕСОВ DLL И ФУНКЦИЙ ###########
LOCAL KERNEL32_address                    : qword                       ; Адрес KERNEL32.DLL
LOCAL VirtualProtect_address              : qword                       ; Адрес Функции VirtualProtect
LOCAL CheckRemoteDebuggerPresent_address  : qword                       ; Адрес Функции CheckRemoteDebuggerPresent
LOCAL CheckRemoteDebuggerPresent_RESULT   : qword                       ; Переменная под функцию CheckRemoteDebuggerPresent, куда попадет результат проверки на отладку
;###### ПЕРЕМЕННЫЕ ДЛЯ ПОЛУЧЕНИЯ ИНДЕКСОВ {0...7} #########
LOCAL INDEX_COUNTER                       : qword                       ; Сохранение результата так как всего будет 8 итераций i = {0,...7}
LOCAL BIT_FOR_XOR                         : qword                       ; Расшифрования каждого бита VALUE_TWO
LOCAL VALUE_ONE                           : qword                       ; Будет сравниваться с VALUE_TWO
LOCAL VALUE_TWO                           : qword                       ; Число которое будет циклически сдвигаться
;############## ПЕРЕМЕННЫЕ ДЛЯ ПРОВЕРКИ INT3 ##############
LOCAL Check_INT3_0                        : byte
LOCAL Check_INT3_1                        : byte
LOCAL Check_INT3_2                        : byte
LOCAL Check_INT3_3                        : byte
LOCAL Check_INT3_4                        : byte
LOCAL Check_INT3_5                        : byte
LOCAL Check_INT3_6                        : byte
LOCAL Check_INT3_7                        : byte
LOCAL Check_INT3_8                        : byte
LOCAL Check_INT3_9                        : byte
LOCAL Check_INT3_10                       : byte
LOCAL Check_INT3_11                       : byte
LOCAL Check_INT3_12                       : byte
LOCAL Check_INT3_13                       : byte
LOCAL INT3_SUM_CHECK                      : qword
;############### ПЕРЕМЕННЫЕ ДЛЯ ЗАПУТЫВАНИЯ ###############
LOCAL garbarage_division_0                : byte
LOCAL garbarage_division_1                : byte
LOCAL garbarage_division_2                : byte
LOCAL garbarage_division_3                : byte
LOCAL garbarage_division_4                : byte
LOCAL garbarage_division_5                : byte
LOCAL garbarage_division_6                : byte
LOCAL garbarage_division_7                : byte
LOCAL garbarage_1                         : qword
LOCAL garbarage_2                         : qword
LOCAL garbarage_3                         : qword
LOCAL garbarage_4                         : qword
LOCAL garbarage_5                         : qword
LOCAL garbarage_6                         : qword
LOCAL garbarage_7                         : qword
LOCAL garbarage_8                         : qword
LOCAL garbarage_9                         : qword
LOCAL garbarage_10                        : qword
LOCAL garbarage_11                        : qword
LOCAL garbarage_12                        : qword
LOCAL garbarage_13                        : qword
LOCAL garbarage_14                        : qword
LOCAL garbarage_15                        : qword
LOCAL garbarage_16                        : qword
LOCAL garbarage_17                        : qword
LOCAL garbarage_18                        : qword
LOCAL garbarage_19                        : qword
LOCAL garbarage_20                        : qword
LOCAL garbarage_21                        : qword
LOCAL garbarage_22                        : qword
LOCAL garbarage_23                        : qword
LOCAL garbarage_24                        : qword
LOCAL garbarage_25                        : qword
LOCAL garbarage_26                        : qword
LOCAL garbarage_27                        : qword
LOCAL garbarage_28                        : qword
LOCAL garbarage_29                        : qword


;   //-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
;  // Sz_Decryptor_Stubloader | CHECK_REMOTE_DEBUGGER_PRESENT_HASH | Sz_Enc_Data | Prime_Mult | HB_position | Hint_Bytes(encrypted) | Main_Key(encrypted) | KERNEL32_HASH | VP_HASH //   
; //-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//





;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 0 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
mov rax, 1754272FC3AB1893h
mov r8, rax
rdtsc
shl rdx, 15
xor rdx, rax
rol r8, 34
sub r8, rdx
push r8
lea rdx, Trash_continue_2
jmp Trash_continue_1
Trash_continue_0:
clc
jnc TRASH_FUNC_ROL
Trash_continue_1:
sub r8, rdx
pop r9
cmp r8, r9                      ; Прыжка не будет
jnc MAIN_Label___3___
lea r8, Trash_continue_0
push r8
db 0C3h
Trash_continue_2:
pop rdx
mov garbarage_1, rax            ; кокое-то число        garbarage_1 == garbarage_2
mov garbarage_2, rcx            
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 0 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА СТРУКТУРЫ PEB ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rax, gs:[offset_to_PEB]                                 
                            mov PEB_address, rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 1 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


                                                        ;---------------------------|
                                                        INT_3_CHECK__0__BEGIN:;     |    Адрес начала проверки на INT3
                                                        ;---------------------------|

rdtsc
xchg rax, rcx
mov rdx, PEB_address
mov rax, 8548CB12h
rol rax, 19
xor rdx, rax
inc rdx
sub rax, rax
inc rax
mul rdx
dec rdx
rdtsc
sub rax, rcx
cmp rax, 10000h                 ; rax > 10000h то происходит отладка
ja MAIN_Label___1___            ; прыжок произойдет если ZF = 0 & CF = 0
lea rax, Trash_continue_4
push rax
db 0C3h
Trash_continue_4:
mov rax, garbarage_1
xor rax, rcx
mov garbarage_1, rax            
clc
jc MAIN_Label___1___
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 1 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ pBASE ОБРАЗА ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rax, PEB_address
                            ;********************* CALL *********************
                                lea rcx, MAIN_Label___0___
                                push rcx
                                jmp Get_ImageBase_from_PEB
                            ;********************* CALL *********************
                        MAIN_Label___0___:
                            mov pBase, rcx
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

                                                        ;---------------------------|                
                                                        INT_3_CHECK__0__END:;       |     Адрес конца проверки на INT3
                                                        ;---------------------------|

;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 2 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
push rax
mov rcx, 94B12CB841AA3410h
xchg rax, rbx
xor rdx, rcx
push rcx
xor rcx, rdx
mov rdx, rbx
inc rbx
cmp rdx, rbx
pushfq
pop rax
and rax, 1
pop rcx
lea rdx, Trash_continue_5
lea r8, TRASH_FUNC_HASH
push r8
db 0C3h
Trash_continue_5:
pop rax
pop rcx
rdtsc
sub rax, rcx
btr rax, 63
cmp rax, 20000h            ; Проверка на отладку
ja Trash_continue_6
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 2 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 0 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            lea rax, INT_3_CHECK__0__BEGIN              ; Адрес начала
                            push 0
                            pop rcx
                            lea rbx, INT_3_CHECK__0__END                ; Адрес конца
                            sub rbx, rax                                 
                            @@loop_0:
                                movzx rdx, byte ptr[rax + rbx] 
                                xor dl, -1                              ; 0xCC xor -1 = 0x33
                                sub dl, 33h
                                pushfq
                                pop rdx
                                and rdx, 64
                                shr rdx, 6
                                add rcx, rdx
                                dec rbx
                                jne @@loop_0
                            shl rcx, 2
                            mov Check_INT3_0, cl
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                                                        ;---------------------------|
                                                        INT_3_CHECK__1__BEGIN:    ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА ТАБЛИЦЫ ИМПОРТА ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rbx, pBase
                            ;********************* CALL *********************
                                lea rax, MAIN_Label___1___
                                jmp Get_Offset_Directory_Table
                            ;********************* CALL *********************
                        MAIN_Label___1___:
                            pop rax
                            mov rax, sz_Image_Data_Directory
                            mov Section_Header, rdx
                            add r10, rax
                            mov ecx, dword ptr [r10]
                            sub rdx, rdx
                            mov edx, ecx
                            mov r10, pBase
                            add r10, rdx
                            xchg rcx, r10
                            mov Import_Table, rcx
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 3 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
xchg rax, rbx                           
stc
jc Trash_continue_6
Trash_continue_7:
lea rdx, Trash_continue_8
dec rdx
add rdx, 2 
mov rax, garbarage_1
mov rbx, garbarage_2
dec rdx
push rdx
db 0C3h
Trash_continue_6:
inc rax
add rax, 5
inc rax
add rax, 5
inc rax
add rax, 5
inc rax
add rax, 5
sub rax, 24
jmp Trash_continue_7
Trash_continue_8:
cmp rax, rbx                    ; Если происходит отладка, то garbarage_1 != garbarage_2
jz Trash_continue_9
jmp Trash_continue_10
Trash_continue_9:
mov dh,    byte ptr[rcx - 6]
movzx rax, byte ptr[rcx - 3]    
movzx rbx, byte ptr[rcx - 5]
mov ah,    byte ptr[rcx - 4]
mov r8, PEB_address
xor r8, -1
mov r9, r8
mov r10, 64
@@invert_for:
    btc r9, r10
    dec r10
    jne @@invert_for
xor r8, r9
push r8
inc r8                          ; r8 = 0
mov r8b, al                     
shl r8, 16
mov r8b, bl                     
shl r8, 8
pop r9
xor r9, -1
mov al, ah
mov r9b, al                     
shl r9, 16
mov al, dh
mov r9b, al
xor r8, r9                      
mov garbarage_3, r8
Trash_continue_10:
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 3 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__1__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|


                                                        ;---------------------------|
                                                        INT_3_CHECK__2__BEGIN:    ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ ХЭШ СТРОКИ Virtual_Protect ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov al, byte ptr[rcx - 1]       ; 1 Байт Хэша
                            mov bl, byte ptr[rcx - 4]       ; 4 Байт Хэша
                            mov ah, byte ptr[rcx - 2]       ; 2 Байт Хэша
                            mov bh, byte ptr[rcx - 3]       ; 3 Байт Хэша

                            sub r8, r8
                            mov r8b, al
                            shl r8, 24
                            mov r8b, bl

                            xor rdx, rdx
                            mov dl, ah
                            shl rdx, 16
                            mov dh, bh

                            xor r8, rdx
                            mov VirtualProtect_HASH, r8d
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 4 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
mov rbx, rax
bswap rax
shr rax, 32
and rax, 7
btc rax, 0
pushfq
pop r8
shl r8, 63
rol r8, 1                       ; r8 = 0 | 1
or rax, r8                      ; 0 Бит rax всегда равен 1
ror rax, 1
mov r8, 8000000000000000h
and rax, r8
rol rax, 2                      ; rax всегда равен 2
Trash_JMP_Start:
cmp rax, 0
jz Trash_continue_12
cmp rax, 1
jz Trash_continue_13
cmp rax, 3
jz Trash_continue_14
cmp rax, 5
jz Trash_continue_15
cmp rax, 2
jz Trash_continue_11
cmp rax, 4
jz Trash_continue_16
cmp rax, 6
                                                        ;---------------------------|
                                                        INT_3_CHECK__2__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|
jz Trash_continue_17
cmp rax, 7
jz Trash_continue_18
jmp Trash_continue_19
Trash_continue_11:
cmp rax, rbx
sbb rdx, rdx
inc rdx
movzx rdx, byte ptr [rcx - 10]
mov dh,    byte ptr [rcx - 8]
movzx r8,  byte ptr [rcx - 7]
imul r9, 0
mov r9b, r8b                    ; 1 по счету Байт
shl r9, 8
mov r8b,  byte ptr [rcx - 9]
mov al, dh
mov r9b, al                     ; 2 по счету Байт
shl r9, 8
mov r9b, r8b                    ; 3 по счету Байт
shl r9, 8
mov r9b, dl
mov garbarage_4, r9
mov rax, 100
jmp Trash_JMP_Start
Trash_continue_12:
mov rax, garbarage_3
inc rax
xor rcx, rax
lea rdx, Trash_continue_18
call rdx
Trash_continue_13:
lea rdx, Trash_continue_17
call rdx
Trash_continue_14:
pop rdx
call Trash_continue_15
Trash_continue_15:
pop rdx
jmp Trash_JMP_Start
Trash_continue_16:
rdtsc
xor rax, rdx
bswap rdx
shr rdx, 10
inc rdx
neg rdx
call Trash_continue_14
Trash_continue_17:
pop rdx
lea rax, Trash_continue_16
lea rdx, Trash_continue_14
sub rax, rdx
bswap rax
rol rax, 51
jmp Trash_continue_16
Trash_continue_18:
pop rdx
inc rdx
xor rcx, rdx
dec rcx
lea rdx, Trash_continue_13
push rdx
db 0C3h
Trash_continue_19:
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 4 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------

                                                        ;---------------------------|
                                                        INT_3_CHECK__3__BEGIN:    ; |      Адрес начало проверки на INT3                      
                                                        ;---------------------------|

                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 1 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        lea rbx, INT_3_CHECK__1__BEGIN
                        push rcx
                        imul r9, 0
                        or rcx, -1
                        inc rcx
                        lea rax, INT_3_CHECK__1__END
                        sub rax, rbx
                        @@loop_1:
                        mov r9b, byte ptr[rbx + rax]
                        shr r9, 2
                        sub r9, 33h
                        pushfq
                        pop r9
                        bt r9, 6
                        pushfq
                        pop r9
                        and r9, 1
                        add rcx, r9
                        dec rax
                        jne @@loop_1
                        shl rcx, 3
                        mov Check_INT3_1, cl
                        pop rcx
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤





                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ ХЭШ СТРОКИ KERNEL32.DLL ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov al, byte ptr[rcx - 6]       ; 2 Байт Хэша
                            mov bl, byte ptr[rcx - 5]       ; 1 Байт Хэша
                            mov ah, byte ptr[rcx - 8]       ; 4 Байт Хэша
                            mov bh, byte ptr[rcx - 7]       ; 3 Байт Хэша

                            or rdx, -1
                            xor rdx, -1
                            mov dl, bl
                            shl rdx, 24
                            mov dh, bh

                            push 0
                            pop r9
                            mov r9b, al
                            shl r9, 16
                            mov al, ah
                            mov r9b, al

                            xor rdx, r9
                            mov Kernel32Dll_HASH, edx
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 2 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        lea r9, INT_3_CHECK__2__BEGIN
                        mov rax, garbarage_1
                        btc rax, 0
                        btc rax, 63
                        inc rax
                        not rax
                        or rax, -1
                        xor rax, -1
                        lea r10, INT_3_CHECK__2__END
                        imul rbx, rax
                        sub r10, r9
                        @@loop_2:
                        mov al, byte ptr[r9 + r10]                  ; Если al = 0xCC - > 11x11xx , где x = 1
                        btc rax, 0
                        btc rax, 4
                        btc rax, 5
                        btc rax, 1
                        inc rax
                        add bl, ah
                        dec r10
                        jne @@loop_2
                        mov Check_INT3_2, bl
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 5 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
mov rbx, rax
mov rcx, 0C18412BA16981134h
inc rcx
cmp rax, rcx
sbb rdx, rdx
xor rdx, -1
push rcx
shl rcx, 32
bswap rcx
shl rcx, 32
xor rcx, rax
inc rcx
rol rcx, 13
lea rdx, MAIN_Label___6___
xor rax, rdx
shr rax, 40
cmp rax, rdx
jnc MAIN_Label___6___
pop rcx
rdtsc
sub rax, rbx
btr rax, 63
cmp rax, 20000h
ja OVERLAPPED_TRASH_INSTRUCTION_0
mov garbarage_4, rcx
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 5 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__3__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|


                                                        ;---------------------------|
                                                        INT_3_CHECK__4__BEGIN:    ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА KERNEL32.DLL ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            or rcx, -1
                            not rcx
                            ;********************* CALL *********************
                                mov ecx, Kernel32Dll_HASH
                                mov rdx, PEB_address
                                lea rbx, MAIN_Label___KERNEL32___
                                push rbx 
                                lea rax, GetModuleHandleA_HASH_Version                            
                                push rax
                                db 0C3h
                            ;********************* CALL *********************
                        MAIN_Label___KERNEL32___:
                            mov KERNEL32_address, rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 3 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        lea r10, INT_3_CHECK__3__END
                        lea r8, INT_3_CHECK__3__BEGIN
                        cmp r8, r10
                        pushfq
                        pop rcx
                        and rcx, 1
                        dec rcx
                        sub r10, r8
                        @@loop_3:
                            mov al, byte ptr[r10 + r8]
                            xor al, 0A9h
                            or r9, -1
                            add r9, 9                       ; r9 = 8
                            @@loop_33:
                                shr rax, 1
                                rcl rcx, 1
                                dec r9
                                jne @@loop_33
                            cmp rcx, 0A6h                   ; mirror (0xCC ^ 0xA9) = 0xA6
                            pushfq
                            pop rcx
                            shr rcx, 6
                            and rcx, 1
                            add Check_INT3_3, cl
                            shr rcx, 1
                            dec r10
                        jne @@loop_3
                        shl Check_INT3_3, 2
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                                                        ;---------------------------|
                                                        INT_3_CHECK__4__END:      ; |      Адрес конца проверки на INT3
                                                        ;---------------------------|
                                                        

;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 6 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


                                                        ;---------------------------|
                                                        INT_3_CHECK__5__BEGIN:    ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|
rdtsc
shl rax, 20
cmp rax, rdx
jnc Trash_continue_21
OVERLAPPED_TRASH_INSTRUCTION_0:
mov rax, 28C8C148h              ; rol rcx, 40
jmp Trash_continue_31
Trash_continue_21:
shr rax, 20
mov rcx, rax
mov rax, garbarage_1
xor rax, rcx
mov garbarage_1, rax            
bswap rdx
shr rdx, 32
mov rax, garbarage_2
xor rax, rdx
mov garbarage_1, rax            
rol rcx, 40
ror rdx, 40
push rcx
push rdx
inc rax
add rax, rcx
inc rcx
shl rcx, 2
shl rcx, 2
shl rcx, 2
shl rcx, 2
xor rcx, -1
inc rcx
rol rax, 6
rol rax, 6
rol rax, 6
rol rax, 6
dec rax
cmp rax, rcx
lea rdx, Trash_continue_25
xor rax, rcx
rol rcx, 5
jmp rdx
Trash_continue_22:
mov rcx, qword ptr[rsp + 8]
not rcx

                                                        ;---------------------------|
                                                        INT_3_CHECK__5__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|

jmp Trash_continue_26
Trash_continue_23:
pop rax
jmp Trash_continue_29
Trash_continue_24:
pop rax
@@trash_for_0:
    btc rax, rcx
    dec rcx
    jne @@trash_for_0
xor rax, -1
push rax
lea r9, Trash_continue_22
push r9
db 0C3h
Trash_continue_25:
pop rax
inc rax
rol rax, 14
inc rax
bswap rax
xor rax, rdx
call Trash_continue_30
Trash_continue_26:
call Trash_continue_23
Trash_continue_27:
pop rcx
bsf rcx, rcx
bsf rcx, rcx
bsf rcx, rcx
bsf rcx, rcx
bsf rcx, rcx
or rcx, 64
jmp Trash_continue_24
Trash_continue_28:
mov rcx, qword ptr[rsp + 8]
rol rcx, 20
sub rcx, 50
inc rcx
call Trash_continue_27
Trash_continue_29:
pop rax
pop rcx
jmp OVERLAPPED_TRASH_INSTRUCTION_0 + 3
Trash_continue_30:
pop rbx
add rbx, rax
xor rdx, rax
bswap rdx
dec rdx
ror rdx, 14
dec rdx
xchg rdx, rax
push rax
lea r8, Trash_continue_28
push r8
db 0C3h
Trash_continue_31:
mov garbarage_1, rax
mov garbarage_2, rcx
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 6 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 4 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        lea r10, INT_3_CHECK__4__BEGIN
                        lea rax, INT_3_CHECK__4__END
                        sub rax, r10
                        @@loop_4:
                        mov r9b, byte ptr[r10 + rax]
                        xor r9b, 84h                ; 0xCC ^ 0x84 = 0x48
                        btc r9, 6
                        btc r9, 3
                        test r9, r9
                        pushfq
                        pop r9
                        bt r9, 6
                        pushfq
                        pop r9
                        and r9, 1
                        add Check_INT3_4, r9b
                        dec rax
                        jne @@loop_4
                        shl Check_INT3_4, 1
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ РАЗМЕРА ЗАШИФРОВАННЫХ ДАННЫХ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, Import_Table
                            ;********************* CALL *********************
                                lea rax, MAIN_Label___2___
                                push rax
                                jmp Get_Encrypted_data_size
                            ;********************* CALL *********************
                        MAIN_Label___2___:
                            mov Sz_Encryption_Data, edx
                            pop rdx
                            mov MAIN_KEY_ADDRESS, r10   ; Адрес начала зашифрованного основного ключа
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 7 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
push rdx
mov rax, garbarage_3
mov r10, 2817958AC93241FCh
add rax, r10
mov r8, 20
@@fake_roll:
    mov r9, r10
    and r9, 1
    ror r9, 1
    shr r10, 1
    xor r10, r9
    dec r8
    jne @@fake_roll
rol r10, 20
sub rax, r10
pop rbx
rdtsc
sub rax, rbx
cmp rax, 300000h
ja Trash_continue_32
jmp Trash_continue_33
Trash_continue_32:
xor rax, r10
mov garbarage_3, rax
;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! НЕ ЗАБЫТЬ ВКЛЮЧИТЬ АНТИОТЛАДКУ !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
; inc rcx           <- включить, если отлаживают то собьются все константы для правильной расшифровки переделать блок cmp rax, 30000h так чтобы можно было вытащить CF и прибавить к rcx
Trash_continue_33:
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 7 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------

                                                        
                                                        ;---------------------------|
                                                        INT_3_CHECK__6__BEGIN:    ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 5 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        push rcx
                        lea r8, INT_3_CHECK__5__END
                        lea rdx, INT_3_CHECK__5__BEGIN
                        mov r9, 0FEh
                        sub r8, rdx
                        @@loop_5:
                        mov al, byte ptr[rdx + r8]  
                        xor al, 33h                     ; 0xCC ^ 0x33 = 0xFF
                        cmp r9b, al                     ; 0xFF > 0xFE -> CF = 1
                        pushfq
                        pop rax
                        and rax, 1
                        add Check_INT3_5, al
                        dec r8
                        jne @@loop_5
                        pop rcx
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤




                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Prime_Mult ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov al,   byte ptr[rcx]               ; 8 Байт числа
                            mov bl,   byte ptr[rcx + 7]           ; 1 Байт числа
                            mov ah,   byte ptr[rcx + 6]           ; 2 Байт числа
                            mov bh,   byte ptr[rcx + 4]           ; 4 Байт числа
                            mov r10b, byte ptr[rcx + 1]           ; 7 Байт числа
                            mov r11b, byte ptr[rcx + 5]           ; 3 Байт числа
                            mov dl,   byte ptr[rcx + 3]           ; 5 Байт числа
                            mov dh,   byte ptr[rcx + 2]           ; 6 Байт числа
                            ; 8_6_4_2_ -> _2_4_6_8 ^ 1_3_5_7 = 12345678
                            push 0
                            pop r8
                            mov r8b, al
                            shl r8, 16
                            xchg dh, al
                            mov r8b, al
                            shl r8, 16
                            xor bh, al
                            xor al, bh
                            mov r8b, al
                            shl r8, 16
                            mov al, ah
                            mov r8b, al
                            shl r8, 8
                            bswap r8
                            and r9, 0
                            mov r9b, bl
                            ror r9, 48
                            mov r9b, r11b
                            ror r9, 48
                            mov r9b, dl
                            shl r9, 16
                            mov r9b, r10b
                            shl r9, 8
                            xor r9, r8
                            mov Prime_Mult, r9
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 8 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
push rax
mov al,   byte ptr[rcx + 4]           ; 8 Байт числа
mov bl,   byte ptr[rcx + 11]          ; 1 Байт числа
mov ah,   byte ptr[rcx + 10]          ; 2 Байт числа
mov bh,   byte ptr[rcx + 8]           ; 4 Байт числа
mov r10b, byte ptr[rcx + 5]           ; 7 Байт числа
mov r11b, byte ptr[rcx + 9]           ; 3 Байт числа
mov dl,   byte ptr[rcx + 7]           ; 5 Байт числа
mov dh,   byte ptr[rcx + 6]           ; 6 Байт числа
push 0
pop r8
mov r8b, al
shl r8, 16
xchg dh, al
mov r8b, al
shl r8, 16
xor bh, al
xor al, bh
mov r8b, al
shl r8, 16
mov al, ah
mov r8b, al
shl r8, 8

                                                        ;---------------------------|
                                                        INT_3_CHECK__6__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|



                                                        ;---------------------------|
                                                        INT_3_CHECK__7__BEGIN:    ; |      Адрес начала проверки на INT3
                                                        ;---------------------------|
bswap r8
and r9, 0
mov r9b, bl
ror r9, 48
mov r9b, r11b
ror r9, 48
mov r9b, dl
shl r9, 16
mov r9b, r10b
shl r9, 8
xor r9, r8
bswap r9
mov garbarage_5, r9
rdtsc
pop r8
sub rax, r8
cmp rax, 30000h
ja Trash_continue_34
jmp Trash_continue_35
Trash_continue_34:
xor garbarage_5, rdx
Trash_continue_35:
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 8 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 6 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        lea rdx, INT_3_CHECK__6__BEGIN
                        push -1
                        pop r9
                        inc r9
                        imul r10, r9
                        lea r8, INT_3_CHECK__6__END
                        sub r8, rdx
                        @@loop_6:
                        mov r10b, byte ptr[rdx + r8]        ; r10b = 0xCC
                        mov r9b, r10b                       ; r9b = r10b
                        shl r9b, 4                          
                        shr r9b, 4                          ; r9b = 00001100
                        xor r9b, 53h                        
                        shr r10b, 4
                        shl r10b, 4                         ; r10b = 11000000
                        xor r10b, 7Bh
                        xor r10b, r9b
                        cmp r10b, 0E4h
                        pushfq
                        pop r10
                        and r10, 40h
                        shr r10, 6
                        add Check_INT3_6, r10b
                        sub r8, 1
                        jne @@loop_6
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


                            
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ HB_position ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                lea rdx, MAIN_Label___3___
                                xor r10, r10
                                @@b:
                                stc
                                sbb rax, rax
                                inc rax
                                cmp rax, r10
                                jne @@b
                                je Get_HINT_BYTE_POSITION
                            ;********************* CALL *********************
                        MAIN_Label___3___:
                            pop rax
                            mov HB_POS, r8              
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤                        



                                                        ;---------------------------|
                                                        INT_3_CHECK__7__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 9 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
lea rbx, Trash_continue_36
jmp TRASH_GET_CONST
Trash_continue_36:
mov garbarage_6, r8
pop r8
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 9 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------




                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Encrypted_Hint_Bytes ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                lea r8, MAIN_Label___4___
                                push r8
                                lea r8, Get_ENC_HINT_BYTES 
                                jmp r8
                            ;********************* CALL *********************
                        MAIN_Label___4___:
                            mov ENCRYPTED_HINT_BYTES, r11
                            pop rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤




;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 10 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
lea r8, TRASH_GET_CONST_1
rdtsc 
shr rax, 15
cmp rax, r8
jc Trash_continue_37
Trash_continue_38:
jmp OVERLAPPED_TRASH_INSTRUCTION_1 + 3
Trash_continue_37:
inc rdx
bswap rdx
shr rdx, 23
jmp Trash_continue_38
OVERLAPPED_TRASH_INSTRUCTION_1: 
cmp rax, 0D0FF41B3h                 ; начиная с 3 байта идет [call r8]
mov garbarage_7, r11
pop rax
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 10 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 7 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        lea r9, INT_3_CHECK__7__BEGIN
                        lea r8, INT_3_CHECK__7__END
                        sub r8, r9
                        @@loop_7:
                        mov r11b, byte ptr[r8 + r9]
                        xor r11b, 97h                       ; 0xCC ^ 0x97 = 0x5B
                        btc r11, 7                          ; r11b =0xDB
                        rol r11b, 4                         
                        ror r11b, 2
                        rol r11b, 3
                        ror r11b, 7                         ; r11b = 0xF6
                        push 0A0h
                        pop rax
                        xor rax, 56h                        ; rax = F6
                        div r11b                            ; al / r11b -> ah = 0 & al = 1
                        inc ah                              ; ah + 1
                        or al, ah                           ; Если был байт 0xCC -> al = 1
                        cmp al, 2
                        pushfq
                        pop rax
                        and rax, 1
                        add Check_INT3_7, al
                        sub r8, 1
                        jne @@loop_7
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤





                                                        ;---------------------------|
                                                        INT_3_CHECK__8__BEGIN:    ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Factor_HB_1 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            sub rcx, 4
                            mov rax, rcx
                            mov ptr_on_anti_debug_hash_str, rax ; Текущее значение rcx которое указывает на начало sz_Enc_Data
                            ;********************* CALL *********************
                                mov rcx, Prime_Mult
                                lea rax, MAIN_Label___5___
                                push rax
                                jmp Factorize
                            ;********************* CALL *********************    
                        MAIN_Label___5___:
                            mov Factor_HB_1, al       ; Получение первого Байта подсказки из числа Prime_Mult
                            mov rcx, Prime_Mult
                            mov rax, rcx
                            or rdx, -1
                            not rdx
                            movzx rcx, Factor_HB_1
                            div rcx
                            mov r11, rax
                            mov Prime_Mult, r11
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ ХЭШ СТРОКИ CheckRemoteDebuggerPresent ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rax, ptr_on_anti_debug_hash_str ; Указывает на начало sz_Enc_Data
                            sub rax, 4
                            mov ecx, dword ptr[rax]
                            mov CheckRemoteDebuggerPresent_HASH, ecx
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 11 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
lea rdx, Trash_continue_39
push rax
push rdx
mov rcx, garbarage_5
shl rdx, 1
inc rdx
and rdx, 1
lea r8, TRASH_DIVISION
push r8
db 0C3h
Trash_continue_39:
mov garbarage_division_0, al
mov garbarage_5, rdx
rdtsc
pop rcx
sub rax, rcx
cmp rax, 30000h
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 11 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;-------------------------------------------------------------------------------------------------------------------------------------------------------



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА CheckRemoteDebuggerPresent ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, KERNEL32_address
                            mov edx, CheckRemoteDebuggerPresent_HASH
                            lea rax, @@return
                            push rax
                            jmp GetProcAddress_HASH_VERSION
                            @@return:
                            mov CheckRemoteDebuggerPresent_address, rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤




                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_3 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, MAIN_KEY_ADDRESS
                            mov r8, 1
                            shl r8, 5
                            sub r8, 8                           ; r8 = 24
                            xadd rcx, r8                    
                            movzx r9, byte ptr[rcx]             ; 0 Байт
                            mov rbx, r9
                            shl rbx, 8
                            movzx r9, byte ptr[rcx + 1]         ; 1 Байт
                            xor rbx, r9
                            movzx r10, byte ptr[rcx + 4]        ; 4 Байт
                            shl r10, 8
                            shl rbx, 8
                            movzx r9, byte ptr[rcx + 2]         ; 2 Байт
                            xor rbx, r9
                            shl rbx, 8
                            mov r10b, byte ptr[rcx + 5]         ; 5 Байт
                            shl r10, 16
                            mov r10b, byte ptr[rcx + 7]         ; 7 Байт
                            movzx r9, byte ptr[rcx + 3]         ; 3 Байт
                            xor rbx, r9
                            shl rbx, 8
                            shl rbx, 16
                            mov bl, byte ptr[rcx + 6]           ; 6 Байт
                            shl rbx, 8
                            xor rbx, r10
                            bswap rbx
                            mov MAIN_KEY_PART_3, rbx
                            ; rbx = 0123__6_
                            ; r10 = ____45_7
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 8 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            lea rax, INT_3_CHECK__8__BEGIN
                            cmp r11, r11
                            pushfq
                            pop r11
                            and r11, 40h
                            sub r11, 40h
                            lea rdx, INT_3_CHECK__8__END
                            sub rdx, rax
                            @@loop_8:
                                mov r11b, byte ptr[rdx + rax]       ; Если r11b = 0xCC
                                btc r11, 5
                                btc r11, 3
                                rol r11b, 4
                                xor r11, 3Bh                        ; 0x75
                                sub r11, 73h                        ; r11 = 0x2
                                btr r11, 63
                                cmp r11, 3
                                pushfq
                                pop r11
                                and r11, 1
                                add Check_INT3_8, r11b
                                dec rdx
                            jne @@loop_8

                        ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              ; PID текушего процесса
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rax, CheckRemoteDebuggerPresent_RESULT
                        ;++++++++++++++++++++++++++++++++++++++++++++++
                        
                            add MAIN_KEY_ADDRESS, rax                ; Если процесс отлаживается то смещение для получения зашифрованного основного ключа будет не правильным
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                                                        ;---------------------------|
                                                        INT_3_CHECK__8__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|


                                                        ;---------------------------|
                                                        INT_3_CHECK__9__BEGIN:    ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_5 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, MAIN_KEY_ADDRESS
                            cmp rcx, rcx
                            pushfq                              ; ZF 6 бит
                            pop r10
                            and r10, 64
                            sub r10, 24                         ; r10 = 40
                            add rcx, r10    
                            movzx rax, byte ptr[rcx]            ; 0 Байт
                            shl rax, 8
                            movzx rbx, byte ptr[rcx + 4]        ; 4 Байт
                            shl rbx, 8
                            mov al, byte ptr[rcx + 1]           ; 1 Байт
                            movzx rdx, byte ptr[rcx + 2]        ; 2 Байт
                            shl rdx, 8
                            mov bl, byte ptr[rcx + 5]           ; 5 Байт
                            shl rbx, 8
                            mov dl, byte ptr[rcx + 3]           ; 3 Байт
                            mov bl, byte ptr[rcx + 6]           ; 6 Байт
                            xchg r10, rcx
                            or rcx, -1
                            and rcx, 16
                            shl rbx, 8
                            shl rdx, cl
                            mov bl, byte ptr[r10 + 7]             ; 7 Байт
                            shl rdx, cl
                            shl rcx, 1
                            push rcx
                            shr rcx, 1
                            pop r11
                            add rcx, r11
                            shl rax, cl
                            xor rax, rdx
                            xor rax, rbx
                            bswap rax
                            mov MAIN_KEY_PART_5, rax
                            ; rax = 01______
                            ; rdx = __23____
                            ; rbx = ____4567

                        ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                                 ; PID текушего процесса
                            lea rdx, CheckRemoteDebuggerPresent_RESULT  ; Переменная, где будет храниться результат функции
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rax, CheckRemoteDebuggerPresent_RESULT
                        ;++++++++++++++++++++++++++++++++++++++++++++++

                            add ptr_on_anti_debug_hash_str, rax         ; Если процесс отлаживается то смещения для получения РАЗМЕРА ЗАГЛУШКИ ДЕШИФРАТОРА будет не правильным
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ РАЗМЕРА ЗАГЛУШКИ ДЕШИФРАТОРА ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rax, ptr_on_anti_debug_hash_str ; Указывает на начало sz_Enc_Data
                            sub rax, 8
                            mov edx, dword ptr[rax]
                            mov Sz_Decryptor_Stubloader, edx
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤




                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 9 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

                        ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                                     ; PID текушего процесса
                            lea rdx, CheckRemoteDebuggerPresent_RESULT      ; Переменная, где будет храниться результат функции
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rax, CheckRemoteDebuggerPresent_RESULT      
                        ;++++++++++++++++++++++++++++++++++++++++++++++

                            rol rax, 4                                      ; IF rax = 1 -> rax = 16,       ELSE rax = 0 -> rax = 0
                            mov rcx, rax
                            ror MAIN_KEY_PART_3, cl                         ; IF rcx = 16 -> смещение 16,   ELSE rcx = 0 -> смещение 0

                            lea rcx, INT_3_CHECK__9__BEGIN
                            lea rdx, INT_3_CHECK__9__END
                            sub rdx, rcx
                            mov r9, 0
                            @@loop_9:
                                mov r9b, byte ptr[rcx + rdx]
                                inc r9b
                                xor r9b, -1
                                btc r9, 3
                                btc r9, 7
                                xor r9b, 73h
                                mov r8, r9
                                shl r8b, 4
                                shr r8b, 4
                                xor r8b, 43h
                                inc r8
                                shr r9b, 4
                                shl r9b, 4
                                xor r9b, 6Fh
                                inc r9b
                                xor r9b, r8b
                                cmp r9b, 0FBh
                                pushfq
                                pop rax
                                shr rax, 6
                                and rax, 1
                                add Check_INT3_9, al
                                dec rdx
                            jne @@loop_9
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 12 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
mov rdi, rax                                    ; Для проверки на отладку

;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
mov rcx, -1                                     ; PID текушего процесса
lea rdx, CheckRemoteDebuggerPresent_RESULT      ; Переменная, где будет храниться результат функции
mov qword ptr[rdx], 1
call CheckRemoteDebuggerPresent_address
mov rax, CheckRemoteDebuggerPresent_RESULT
;++++++++++++++++++++++++++++++++++++++++++++++

add garbarage_5, rax
mov rcx, garbarage_5

or rdx, -1
add rdx, 3
lea r8, Trash_continue_40
push r8
lea r8, TRASH_DIVISION
push r8
db 0C3h
Trash_continue_40:
mov garbarage_division_1, al
mov garbarage_5, rdx
rdtsc
sub rax, rdi                                    
cmp rax, 30000h                                 
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 12 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__9__END:      ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_2 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

                        ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                                     ; PID текушего процесса
                            lea rdx, CheckRemoteDebuggerPresent_RESULT      ; Переменная, где будет храниться результат функции
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rax, CheckRemoteDebuggerPresent_RESULT
                        ;++++++++++++++++++++++++++++++++++++++++++++++

                            mov rcx, rax
                            mov rax, MAIN_KEY_ADDRESS
                            shl rax, cl                                     ; IF rcx = 1 -> MAIN_KEY_ADDRESS измениться, ELSE rcx = 0 -> MAIN_KEY_ADDRESS не измениться
                            xchg rax, rcx                                   ; Кладем MAIN_KEY_ADDRESS в rcx
                            neg rax
                            or rax, -1
                            not rax
                            or rdx, -1
                            inc rdx
                            bts rdx, 4                                      ; rdx = 16
                            add rcx, rdx
                            movzx r10, byte ptr[rcx]                        ; 0 Байт
                            xor rax, r10
                            shl rax, 8
                            or r11, -1
                            clc
                            pushfq
                            pop r9
                            and r9, 1
                            and rbx, r9
                            movzx r9,  byte ptr[rcx + 4]                    ; 4 Байт
                            xor rbx, r9
                            shl rbx, 8
                            dec r11
                            xor r11, -1
                            movzx r9,  byte ptr[rcx + 5]                    ; 5 Байт
                            xor rbx, r9
                            shl rbx, 8
                            movzx r10, byte ptr[rcx + r11]                  ; 1 Байт
                            xor rax, r10
                            shl rax, 8
                            inc r11
                            movzx r10, byte ptr[rcx + r11]                  ; 2 Байт
                            xor rax, r10
                            movzx r9,  byte ptr[rcx + 6]                    ; 6 Байт
                            xor rbx, r9
                            shl rbx, 8
                            shl rax, 8
                            movzx r9,  byte ptr[rcx + 7]                    ; 7 Байт
                            xor rbx, r9
                            inc r11
                            movzx r10, byte ptr[rcx + r11]                  ; 3 Байт
                            xor rax, r10
                            shl rax, 32
                            xor rax, rbx
                            ; rax = 0123____
                            ; rbx = ____4567
                            bswap rax
                            mov MAIN_KEY_PART_2, rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤





                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Factor_HB_2 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                mov rdx, Prime_Mult
                                xchg rcx, rdx
                                lea rbx, MAIN_Label___6___
                                push rbx
                                lea rbx, Factorize
                                push rbx
                                db 0C3h
                            ;********************* CALL *********************
                        MAIN_Label___6___:
                            mov Factor_HB_2, al       ; Получение второго Байта подсказки из числа Prime_Mult
                            mov rcx, Prime_Mult
                            xchg rax, rcx
                            xor rdx, rdx
                            imul rcx, 0
                            mov cl, Factor_HB_2
                            div rcx
                            mov Prime_Mult, rax

                        ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                                     ; PID текушего процесса
                            lea rdx, CheckRemoteDebuggerPresent_RESULT      ; Переменная, где будет храниться результат функции
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rax, CheckRemoteDebuggerPresent_RESULT
                        ;++++++++++++++++++++++++++++++++++++++++++++++

                            add Factor_HB_2, al
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


                        
                                                        ;---------------------------|
                                                        INT_3_CHECK__10__BEGIN:   ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|

;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 13 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
push rax
lea r9, Trash_continue_41
push r9
mov rdx, garbarage_5
xchg rcx, rdx
stc
sbb rdx, rdx
and rdx, 3
lea r8, TRASH_DIVISION
push r8
db 0C3h
Trash_continue_41:
mov garbarage_division_2, al
mov garbarage_5, rdx

;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
mov rcx, -1                              
lea rdx, CheckRemoteDebuggerPresent_RESULT
mov qword ptr[rdx], 1
call CheckRemoteDebuggerPresent_address
mov rax, CheckRemoteDebuggerPresent_RESULT
;++++++++++++++++++++++++++++++++++++++++++++++

add garbarage_division_2, al
rdtsc
pop rdx
sub rax, rdx
cmp rax, 30000h
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 13 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                       ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_6 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, MAIN_KEY_ADDRESS
                            mov r8, 1
                            shl r8, 5
                            sub r8, 8                           
                            shl r8, 1                           ; r8 = 48
                            xadd rcx, r8                    
                            movzx r9, byte ptr[rcx]             ; 0 Байт
                            mov rbx, r9
                            shl rbx, 8
                            movzx r9, byte ptr[rcx + 1]         ; 1 Байт
                            xor rbx, r9
                            movzx r10, byte ptr[rcx + 4]        ; 4 Байт
                            shl r10, 8
                            shl rbx, 8
                            movzx r9, byte ptr[rcx + 2]         ; 2 Байт
                            xor rbx, r9
                            shl rbx, 8
                            mov r10b, byte ptr[rcx + 5]         ; 5 Байт
                            shl r10, 16
                            mov r10b, byte ptr[rcx + 7]         ; 7 Байт
                            movzx r9, byte ptr[rcx + 3]         ; 3 Байт
                            xor rbx, r9
                            shl rbx, 8
                            shl rbx, 16
                            mov bl, byte ptr[rcx + 6]           ; 6 Байт
                            shl rbx, 8
                            xor rbx, r10
                            bswap rbx
                            mov MAIN_KEY_PART_6, rbx
                            ; rbx = 0123__6_
                            ; r10 = ____45_7
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 10 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rax, CheckRemoteDebuggerPresent_RESULT
                            ;++++++++++++++++++++++++++++++++++++++++++++++

                            lea rcx, INT_3_CHECK__10__BEGIN
                            lea rdx, INT_3_CHECK__10__END
                            sub rdx, rcx
                            or r11, -1
                            inc r11
                            @@loop_10:
                                mov r11b, byte ptr[rdx + rcx]
                                inc r11
                                cmp r11, 0CDh
                                pushfq
                                pop r11
                                shr r11, 6
                                and r11, 1
                                add Check_INT3_10, r11b
                                dec rdx
                            jne @@loop_10
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ АДРЕСА Virtual_Protect ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                mov rcx, KERNEL32_address
                                sub rcx, rax          ; IF rax = 0 -> rcx = KERNEL32_address, ELSE rcx = KERNEL32_address - 1
                                mov edx, VirtualProtect_HASH
                                or r11, -1
                                xor r11, -1
                                lea rax, MAIN_Label___Y___
                                push rax
                                lea rax, GetProcAddress_HASH_VERSION
                                push rax
                                sub r11, r11
                                jz @@a
                                jmp MAIN_Label___7___ ; Прыжка никогда не будет
                                @@a:
                                db 0C3h
                            ;********************* CALL *********************
                        MAIN_Label___Y___:
                            mov VirtualProtect_address, rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


                                                        ;---------------------------|
                                                        INT_3_CHECK__10__END:     ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|


;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 14 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
mov rsi, rax

;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
mov rcx, -1                              
lea rdx, CheckRemoteDebuggerPresent_RESULT
mov qword ptr[rdx], 1
call CheckRemoteDebuggerPresent_address
mov rax, CheckRemoteDebuggerPresent_RESULT
;++++++++++++++++++++++++++++++++++++++++++++++

shl rax, 5
mov rcx, garbarage_5
xor rcx, rax

push 4
pop rdx
lea r8, Trash_continue_42
push r8
lea r8, TRASH_DIVISION
jmp r8
Trash_continue_42:
mov garbarage_division_3, al
mov garbarage_5, rdx
rdtsc
sub rax, rsi
cmp rax, 30000h
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 14 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__11__BEGIN:   ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_7 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, MAIN_KEY_ADDRESS
                            bts rax, 0
                            and rax, 1
                            shl rax, 5                          ; rax = 32
                            btc rax, 4                          ; rax = 48
                            bts rax, 3                          ; rax = 56
                            add rcx, rax
                            lea rax, NUM_BYTE_0_OVERLAPED
                            rol rdx, 3
                            or rdx, 3
                            and rdx, 3
                            add rax, rdx
                            jmp rax
                            NUM_BYTE_1_OVERLAPED:
                            cmp r9, 01518A44h                   ; mov r10b, byte ptr[rcx + 1] - 1 Байт
                            jmp NUM_BYTE_2_and_3
                            NUM_BYTE_4_and_5_OVERLAPED:
                            mov rbx, 0459B60F485819C3h          ; movzx rbx, byte ptr[rcx + 4]  - 4 Байт
                            shl rbx, 8
                            mov bl, byte ptr[rcx + 5]           ; 5 Байт
                            shl rbx, 16
                            xor r10, rbx
                            jmp NUM_BYTE_6_and_7
                            NUM_BYTE_0_OVERLAPED: 
                            cmp r10, 11B60F4Ch                  ; movzx r10, byte ptr[rcx]    - 0 Байт
                            shl r10, 8
                            lea r8, NUM_BYTE_1_OVERLAPED
                            add r8, 3
                            push r8
                            db 0C3h
                            NUM_BYTE_2_and_3:
                            movzx rax, byte ptr[rcx + 2]                          ; 2 Байт
                            shl rax, 8
                            mov al, byte ptr[rcx + 3]                             ; 3 Байт
                            shl r10, 16
                            lea r8, NUM_BYTE_4_and_5_OVERLAPED
                            xor r10, rax
                            xor r11, r11
                            or r11, 5
                            add r8, r11
                            shl r10, 32
                            jmp r8
                            NUM_BYTE_6_and_7:
                            movzx rdx, byte ptr[rcx + 6]                          ; 6 Байт
                            shl rdx, 8
                            mov dl, byte ptr[rcx + 7]                             ; 7 Байт
                            xor r10, rdx
                            ; r10 = 01_______
                            ; rax = __23_____
                            ; rbx = ____45___
                            ; rdx = _______67
                            bswap r10
                            mov MAIN_KEY_PART_7, r10
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Factor_HB_3 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                mov r10, Prime_Mult
                                xor r10, rcx
                                xor rcx, r10
                                lea r8, MAIN_Label___7___
                                push r8
                                sub rdx, rdx
                                jz Factorize
                            ;********************* CALL *********************
                        MAIN_Label___7___:
                            mov Factor_HB_3, al                     ; Получение третьего Байта подсказки из числа Prime_Mult
                            mov rax, Prime_Mult
                            movzx rcx, Factor_HB_3
                            mov rdx, 0
                            div rcx
                            xchg rax, r9
                            mov Prime_Mult, r9

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rax, CheckRemoteDebuggerPresent_RESULT
                            ;++++++++++++++++++++++++++++++++++++++++++++++

                            add Prime_Mult, rax                     ; IF rax = 0, то Prime_Mult и MAIN_KEY_PART_7 не измениться,    ELSE изменяться
                            xor MAIN_KEY_PART_7, rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 11 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            lea rcx, INT_3_CHECK__11__BEGIN
                            lea rax, INT_3_CHECK__11__END
                            sub rax, rcx
                            mov r8, 0
                            @@loop_11:
                                mov r8b, byte ptr[rcx + rax]        ; Если r8b = 0xCC
                                push r8
                                btc r8, 0
                                btc r8, 5
                                btc r8, 1
                                btc r8, 4                           ; r8 = 0xFF
                                pop r11
                                cmp r8b, 0FFh
                                pushfq
                                pop r11
                                bts r11, 6
                                pushfq
                                pop r11
                                and r11, 1
                                add Check_INT3_11, r11b
                                dec rax
                            jne @@loop_11
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤




                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_1 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, MAIN_KEY_ADDRESS
                            or rax, -1
                            and rax, 2
                            shl rax, 2
                            xor r8, r8
                            mov r8b, byte ptr[rcx + rax]                    ; 0 Байт
                            mov r11, -2
                            xor r11, -1
                            inc r11                                         ; r11 = 2
                            shl r8, 16
                            movzx rax, byte ptr[rcx + 1 + rax]              ; 1 Байт
                            mov r10, rax
                            shl r10, 16
                            xor r9, r9
                            bts r9, 3
                            add rcx, r9
                            mov r8b, byte ptr[rcx + r11]                    ; 2 Байт
                            shl r8, 16
                            add r11, 2                                      ; r11 = 4
                            mov r8b, byte ptr[rcx + r11]                    ; 4 Байт
                            not r11
                            movzx rax, byte ptr[rcx + 3]                    ; 3 Байт
                            xor r10, rax
                            shl r10, 16
                            sub r11, 2
                            xor r11, -1                                     ; r11 = 6
                            movzx rax, byte ptr[rcx + 5]                    ; 5 Байт
                            xor r10, rax
                            shl r10, 16
                            shl r8, 16
                            mov r8b, byte ptr[rcx + r11]                    ; 6 Байт
                            shl r8, 8
                            movzx rax, byte ptr[rcx + 7]                    ; 7 Байт
                            xor r10, rax
                            xor r8, r10
                            ; r8  = 0_2_4_6_
                            ; r10 = _1_3_5_7
                            bswap r8
                            mov MAIN_KEY_PART_1, r8

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rcx, CheckRemoteDebuggerPresent_RESULT
                            ;++++++++++++++++++++++++++++++++++++++++++++++

                            mov rax, 9234953h
                            xor rdx, rdx
                            mul rcx
                            xor MAIN_KEY_PART_1, rax                        ; IF rcx = 1 -> MAIN_KEY_PART_1 измениться, ELSE rcx = 0 -> MAIN_KEY_PART_1 не измениться
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                                                        ;---------------------------|
                                                        INT_3_CHECK__11__END:     ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 15 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
mov rsi, rax

;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
mov rcx, -1                              
lea rdx, CheckRemoteDebuggerPresent_RESULT
mov qword ptr[rdx], 1
call CheckRemoteDebuggerPresent_address
mov rcx, CheckRemoteDebuggerPresent_RESULT
;++++++++++++++++++++++++++++++++++++++++++++++

mov rax, 24834ACh
xor rdx, rdx
mul rcx
mov rcx, garbarage_5
add rcx, rax
mov rdx, 5
call TRASH_DIVISION 
jz INT_3_CHECK__12__END                 ; Так как в конце функции TRASH_DIVISION стоит проверка адреса возврата на 0xCC, то есть вероятность что при сравнение ZF = 1
mov garbarage_division_4, al
mov garbarage_5, rdx
rdtsc
sub rax, rsi
cmp rax, 30000h
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 15 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------




                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Factor_HB_4 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                mov rcx, Prime_Mult
                                lea rax, MAIN_Label___8___
                                push rax
                                lea rax, Factorize
                                push rax
                                db 0C3h
                            ;********************* CALL *********************
                        MAIN_Label___8___:
                            mov Factor_HB_4, al       ; Получение четвертого Байта подсказки из числа Prime_Mult
                            mov rdx, Prime_Mult
                            xor rdx, rax
                            xor rax, rdx
                            push 0
                            pop rdx
                            movzx rcx, Factor_HB_4          
                            div rcx
                            lea rdx, Prime_Mult
                            mov qword ptr[rdx], rax

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rcx, CheckRemoteDebuggerPresent_RESULT
                            ;++++++++++++++++++++++++++++++++++++++++++++++

                            shl rcx, 3               ; IF rcx = 1 -> rcx = 8 -> Prime_Mult измениться, ELSE rcx = 0 -> rcx = 0 -> Prime_Mult не измениться
                            lea rdx, Prime_Mult
                            rol qword ptr[rdx], cl
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            

;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 16 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
mov r12, rax
mov rcx, garbarage_5
mov rdx, 6
call TRASH_DIVISION
jz INT_3_CHECK__13__BEGIN   ; Так как в конце функции TRASH_DIVISION стоит проверка адреса возврата на 0xCC, то есть вероятность что при сравнение ZF = 1
mov garbarage_division_5, al
mov garbarage_5, rdx
rdtsc
sub rax, r12
cmp rax, 30000h
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 16 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__12__BEGIN:   ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_4 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, MAIN_KEY_ADDRESS
                            or r9, -1
                            and r9, -1
                            btc r9, 5
                            xor r9, -1
                            add rcx, r9                                 ; r9 = 32
                            movzx rdx, byte ptr[rcx + 7]                ; 7 Байт
                            shl rdx, 16
                            movzx r10, byte ptr[rcx + 6]                ; 6 Байт
                            mov rax, r10
                            shl rax, 16
                            mov dl, byte ptr[rcx + 5]                   ; 5 Байт
                            shl rdx, 16
                            movzx r10, byte ptr[rcx + 4]                ; 4 Байт
                            xor rax, r10
                            shl rax, 24
                            mov dl, byte ptr[rcx + 3]                   ; 3 Байт
                            movzx r10, byte ptr[rcx + 1]                ; 1 Байт
                            xor rax, r10
                            shl rax, 8
                            shl rdx, 8
                            mov dl, byte ptr[rcx + 2]                   ; 2 Байт
                            shl rdx, 8
                            movzx r10, byte ptr[rcx]                    ; 0 Байт
                            xor rax, r10
                            shl rdx, 8
                            xor rax, rdx
                            mov MAIN_KEY_PART_4, rax
                            ; rax = _6_4__10
                            ; rdx = 7_5_32__

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rcx, CheckRemoteDebuggerPresent_RESULT
                            ;++++++++++++++++++++++++++++++++++++++++++++++

                            rdtsc                                       ; rax = какое-то число
                            and rdx, 1                      
                            btr rdx, 0                                  ; Всегда rdx = 0  
                            mul rcx                                     ; IF rcx = 1 -> rax = rax,  ELSE rcx = 0 -> rax = 0
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤





                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Factor_HB_5 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                mov rcx, Prime_Mult
                                lea rdx, MAIN_Label___9___
                                push rdx
                                lea rdx, Factorize
                                add rdx, rax                            ; IF rax = rax -> Адрес Factorize измениться, ELSE rax = 0 -> Адрес Factorize не измениться
                                push rdx
                                db 0C3h
                            ;********************* CALL *********************
                        MAIN_Label___9___:
                            mov Factor_HB_5, al       ; Получение пятого Байта подсказки из числа Prime_Mult
                            mov rax, Prime_Mult
                            or rcx, -1
                            inc rcx
                            sub rdx, rdx
                            mov cl, Factor_HB_5
                            div rcx
                            mov Prime_Mult, rax
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 12 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rcx, CheckRemoteDebuggerPresent_RESULT
                            ;++++++++++++++++++++++++++++++++++++++++++++++
                            
                            mov rdi, rcx                        ; IF rdi = 1 -> ПОЛУЧЕНИЕ Factor_HB_6  измениться , ELSE rdi = 0 -> ПОЛУЧЕНИЕ Factor_HB_6 не измениться 
                            lea r10, INT_3_CHECK__12__END
                            lea r8, INT_3_CHECK__12__BEGIN
                            cmp r8, r10
                            pushfq
                            pop rcx
                            and rcx, 1
                            dec rcx
                            sub r10, r8
                            @@loop_12:
                                mov al, byte ptr[r10 + r8]
                                xor al, 0A9h
                                or r9, -1
                                add r9, 9                       ; r9 = 8
                                @@loop_122:
                                    shr rax, 1
                                    rcl rcx, 1
                                    dec r9
                                    jne @@loop_122
                                cmp rcx, 0A6h                   ; mirror (0xCC ^ 0xA9) = 0xA6
                                pushfq
                                pop rcx
                                shr rcx, 6
                                and rcx, 1
                                add Check_INT3_12, cl
                                shr rcx, 1
                                dec r10
                            jne @@loop_12
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 17 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
mov r11, rax
mov rcx, garbarage_5
push 7
pop rdx
lea r8, Trash_continue_45
push r8
lea r8, TRASH_DIVISION
jmp r8
Trash_continue_45:
mov garbarage_division_6, al
mov garbarage_5, rdx
rdtsc
sub rax, r11
cmp rax, 30000h
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 17 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__12__END:     ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Factor_HB_6 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                mov rcx, Prime_Mult
                                lea rbx, MAIN_Label___10___
                                add rbx, rdi          ; IF rdi = 1 -> ПОЛУЧЕНИЕ Factor_HB_6  измениться , ELSE rdi = 0 -> ПОЛУЧЕНИЕ Factor_HB_6 не изменитьс     
                                push rbx
                                jmp Factorize
                            ;********************* CALL *********************
                        MAIN_Label___10___:
                            mov Factor_HB_6, al       ; Получение шестого Байта подсказки из числа Prime_Mult
                            mov rcx, Prime_Mult
                            xchg rax, rcx
                            bsf rdx, rdx
                            imul rcx, 0
                            mov cl, Factor_HB_6
                            div rcx
                            mov Prime_Mult, rax



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 18 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rdtsc
push rax
lea r9, Trash_continue_50
push r9
mov rdx, garbarage_5
xchg rcx, rdx
stc
sbb rdx, rdx
and rdx, 8
lea r8, TRASH_DIVISION
push r8
db 0C3h
Trash_continue_50:
mov garbarage_division_7, al
mov garbarage_5, rdx
rdtsc
pop rdx
sub rax, rdx
cmp rax, 30000h
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 18 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__13__BEGIN:   ; |      Адрес начала проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ Factor_HB_7 и Factor_HB_8 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            ;********************* CALL *********************
                                mov rcx, Prime_Mult
                                lea rbx, MAIN_Label___11___
                                push rbx
                                lea rbx, Factorize
                                push rbx
                                db 0C3h
                            ;********************* CALL *********************
                        MAIN_Label___11___:
                            mov Factor_HB_7, al       ; Получение седьмого Байта подсказки из числа Prime_Mult
                            mov rcx, Prime_Mult
                            mov rax, rcx
                            or rdx, -1
                            not rdx
                            movzx rcx, Factor_HB_7
                            div rcx
                            mov r11, rax
                            mov Factor_HB_8, r11b     ; Получение восьмого Байта подсказки из числа Prime_Mult



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОЛУЧЕНИЕ MAIN_KEY_PART_0 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, MAIN_KEY_ADDRESS
                            mov r9b, byte ptr[rcx]                  ; 0 Байт 
                            shl r9, 56
                            rdtsc
                            xor rax, rdx
                            and rax, 7
                            btc rax, 0
                            pushfq
                            pop r8
                            ror r8, 1
                            shr r8, 63                              ; r8 = 1 | 0
                            xor rax, r8                             ; Нулевой бит rax = 1
                            ror rax, 1
                            or rax, 1
                            ror rax, 1
                            bts rax, 0
                            rol rax, 2                              ; rax = 7
                            mov r9b, byte ptr[rcx + rax]            ; 7 Байт
                            sub r10, r10 
                            mov r10b, byte ptr[rcx + 1]             ; 1 Байт
                            shl r10, 40
                            mov r10b, byte ptr[rcx + 6]             ; 6 Байт
                            shl r10, 8
                            or rax, -1
                            add rax, 3
                            or r11, -1
                            xor r11, -1                            
                            mov r11b, byte ptr[rcx + rax]           ; rax = 2  
                            shl r11, 8
                            mov r11b, byte ptr[rcx + 3]             ; 3 Байт
                            shl r11, 8
                            mov r11b, byte ptr[rcx + 4]             ; 4 Байт
                            shl r11, 8
                            mov r11b, byte ptr[rcx + 5]             ; 5 Байт
                            shl r11, 16
                            xor r9, r11
                            xor r9, r10
                            ; r9 =  0______7
                            ; r10 = _1____6_
                            ; r11 = __2345__
                            bswap r9
                            mov MAIN_KEY_PART_0, r9
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 [ РАУНД 13 ] ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            lea rdx, INT_3_CHECK__13__BEGIN
                            push -1
                            pop r9
                            inc r9
                            imul r10, r9
                            lea r8, INT_3_CHECK__13__END
                            sub r8, rdx
                            @@loop_13:
                            mov r10b, byte ptr[rdx + r8]        ; r10b = 0xCC
                            mov r9b, r10b                       ; r9b = r10b
                            shl r9b, 4                          
                            shr r9b, 4                          ; r9b = 00001100
                            xor r9b, 53h                        
                            shr r10b, 4
                            shl r10b, 4                         ; r10b = 11000000
                            xor r10b, 7Bh
                            xor r10b, r9b
                            cmp r10b, 0E4h
                            pushfq
                            pop r10
                            and r10, 40h
                            shr r10, 6
                            add Check_INT3_13, r10b
                            sub r8, 1
                            jne @@loop_13
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



;--------------------------------------------------------------------------------------------------------------------------------------------------------
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 19 ] МУСОРНЫЕ ИНСТРУКЦИИ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
and r10, 0
mov al, garbarage_division_1
movzx r11, al
xor r10, r11
lea r11, TRASH_RET_0
jmp TRASH_SHL_0
TRASH_RET_0:
mov al, garbarage_division_2
movzx r11, al
xor r10, r11
lea r11, TRASH_RET_1
jmp TRASH_SHL_0
TRASH_RET_1:
mov bl, garbarage_division_3
movzx r11, bl
lea r11, TRASH_RET_2
jmp TRASH_SHL_0
TRASH_RET_2:
mov bl, garbarage_division_4
movzx r11, bl
xor r10, r11
lea r11, TRASH_RET_3
jmp TRASH_SHL_0
TRASH_RET_3:
mov dl, garbarage_division_5
movzx r11, dl
xor r10, r11
lea r11, TRASH_RET_4
jmp TRASH_SHL_0
TRASH_RET_4:
mov dl, garbarage_division_6
movzx r11, dl
xor r10, r11
lea r11, TRASH_RET_5
jmp TRASH_SHL_0
TRASH_RET_5:
mov cl, garbarage_division_7
movzx r11, cl
xor r10, r11
shl r10, 8
jmp Trash_continue_51
TRASH_SHL_0:
shl r10, 8
push r11
db 0C3h
Trash_continue_51:
mov garbarage_8, r10
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ [ РАУНД 19 ] КОНЕЦ МУСОРА ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;--------------------------------------------------------------------------------------------------------------------------------------------------------


                                                        ;---------------------------|
                                                        INT_3_CHECK__13__END:     ; |      Адрес конца проверки на INT3                      
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА FACTOR_RESULT ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov bl, Factor_HB_7
                            mov r8b, Factor_HB_2
                            mov r10b, Factor_HB_6                            
                            mov r9b, Factor_HB_4
                            mov al, Factor_HB_3
                            mov cl, Factor_HB_5
                            mov dl, Factor_HB_1
                            mov dh, Factor_HB_8
                            mov r11b, dl
                            shl r11, 8
                            mov r11b, r8b
                            shl r11, 8
                            mov r11b, al
                            shl r11, 8
                            mov r11b, r9b
                            shl r11, 8
                            mov r11b, cl
                            shl r11, 8
                            mov r11b, r10b
                            shl r11, 8
                            mov r11b, bl
                            shl r11, 8
                            xchg bl, dh
                            mov r11b, bl
                            ; r11 = 12345678
                            bswap r11
                            mov FACTOR_RESULT, r11
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПРОВЕРКА НА INT3 А ТАКЖЕ СУММЫ  ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            rdtsc                   
                            push rax                            ; Для анти-отладки
                            sbb rax, rdx                        ; Мусор
                            cmp rax, 2895914h                   ; Мусор
                            xor rdx, -1                         ; Мусор
                            push rdx
                            xor rdx, qword ptr[rsp]             ; rdx = 0
                            pop r8                              ; восстановление стека
                            lea r8, INT_3_CHECK__SUM__BEGIN     ; Адрес начала отсчета суммы
                            jmp @@Trash_continue_45             ; Прыжок на @@Trash_continue_45
                            @@Trash_continue_47:
                            mov rax, 48C35398A30C128Dh          ; Мусор
                            lea r11, OVERLAPPED_INSTRUCTION_17  ; Адрес перекрываемой инструкции
                            and r9, 3
                            or r9, 3                            
                            lea r10, INT_3_CHECK__SUM__END      ; Адрес конца отсчета суммы
                            add r11, r9                         ; Адрес + 3 начинается [sub r10, r8]
                            jmp r11                             ; Прыжок на перекрытую инструкцию
                            @@SUMMURY_FOR:
                            mov rbx, qword ptr [r10 + r8]       ; 8 байт куска кода
                            add rdx, rbx                        ; Суммирование проиходит в rdx
                            sub r10, 8
                            bt r10, 63                          
                            pushfq
                            pop r9
                            and r9, 1                           
                            cmp r9, 1                           ; Проверка на то что число стало отрицательным
                            jne @@SUMMURY_FOR
                            lea rbx, @@Continue_sum
                            push rbx
                            db 0C3h
                            @@Trash_continue_45:
                            lea rcx, @@Trash_continue_47        ; Адрес метки @@Trash_continue_47
                            ror rcx, 2                          ; Мусор
                            ror rcx, 62                         ; Мусор
                            jmp rcx                             ; Прыжок на @@Trash_continue_47
                            OVERLAPPED_INSTRUCTION_17:
                            cmp rax, 0D02B4D73h                 ; 0x4D2BD0 [sub r10, r8]
                            lea r9, @@SUMMURY_FOR               ; Адрес цикла где будет происходить подсчет суммы куска кода
                            push r9
                            db 0C3h                             ; Прыжок на @@SUMMURY_FOR
                            @@Continue_sum:
                            mov INT3_SUM_CHECK, rdx
                            pop rcx                             ; Начало отсчета, инстркуции rdtsc
                            rdtsc                       
                            sub rax, rcx                        ; Проверка на отладку
                            cmp rax, 30000h
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤






                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ИНИЦИАЛИЗАЦИЯ ПЕРЕБОРА КЛЮЧА ДЛЯ РАСШИФРОВАНИЯ Main_Key ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rax, 14CB917A835CFFFEh
                            mov r10, 95AA86CA6E1A4C78h

                                        ; |================================================================|
                                        ; | 95AAAEE2267BBFF3 = (FC00B18312C39B49 >> 2) ^ AAAAAAAAAAAAAAAA  |
                                        ; |================================================================|
                                        
                            mov VALUE_ONE, rax
                            mov VALUE_TWO, r10
                            mov BIT_FOR_XOR, 1
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА MAIN_INDEX_0 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        MAIN_INDEX_0:
                            rdtsc                               ; Для рандомизации RAX
                            bswap rax
                            shr rax, 32
                            lea rdx, OVERLAPPED_INSTRUCTION_0   ; адрес перекрываемой инструкции
                            lea rsi, ENCRYPTED_HINT_BYTES       ; адрес начала Encrypted_Hint_Bytes
                            xor dword ptr[rsi], eax             ; Шифрование 4 байтов Encrypted_Hint_Bytes

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, PEB_address                ; В данной структуре хранится NtGlobalFlag
                            add rcx, 60h            
                            mov rbx, rcx
                            add rbx, 55h
                            mov rbx, qword ptr[rbx]             ; Получаем значение NtGlobalFlag если отлаживают равен 0x70
                            shr rbx, 60                         ; IF процесс отлаживается -> rbx = 7, ELSE процесс не отлаживается -> rdx = 0
                            ;+++++++++++++++++++++++++++++++++++++++++++++
                            
                            xchg r9, rbx                        
                            inc r9                              ; IF процесс отлаживается -> r9 = 8,   ELSE процесс не отлаживается -> r9 = 1
                            add r9, 6                           ; IF процесс отлаживается -> rbx = 14, ELSE процесс не отлаживается -> rdx = 7
                            mov rbx, rdx
                            or rcx, -1
                            add rcx, 15                         ; rcx = 14
                        @@Trash_Init_Fake_Jmp:
                            add rdx, rcx    
                            sub rdx, r9                         ; Если происходит отладка NtGlobalFlag = 0x70
                            dec r9
                            dec rcx                                 
                            jne @@Trash_Init_Fake_Jmp
                            mov rcx, rdx                        ; Если отлаживают то rdx == rbx, иначе rdx > rbx
                            sub rcx, rbx                        ; IF процесс не отлаживается (rcx - rbx) > 0, ELSE (rcx - rbx) = 0
                        @@for:
                            cmp rcx, 7
                            jnc @@Continue_0
                            pushfq
                            pop r8
                            and r8, 1
                            add rcx, r8
                            sub rbx, r8
                            jmp @@for
                        @@Continue_0:
                            and rcx, 0
                            inc rcx                             ; rcx = 1
                            shl rcx, 2                          ; rcx = 4
                            xor rcx, 3                          ; rcx = 7
                            add rbx, rcx
                            sub rcx, rcx
                            jne @@_First_LOOP                   ; Никогда не выполниться 
                            jmp rbx                             ; Прыжок на перекрытую инструкцию
                            inc rcx                             ; Мусор
                            shl rcx, 2                          ; Мусор
                            xor rcx, 0D1874C34h                 ; Мусор
                            ror rcx, 16                         ; Мусор
                        OVERLAPPED_INSTRUCTION_0:               ; Перекрытая инструкция
                            mov rax, 0D88B48A383F01596h         ; Скрытый набор байт [mov rbx, rax]  начиная с 7 Байта
                            mov rbx, rax
                            xor dword ptr[rsi], ebx
                            lea rax, @@_First_LOOP
                            push rax
                            lea rdx, MAIN_INDEX_1
                            db 0C3h
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА MAIN_INDEX_2 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        ; (Весь блок MAIN_INDEX_2 мусорный)
                        MAIN_INDEX_2:
                            rdtsc
                            shl rax, 32
                            xor rdx, rax
                            ror rdx, 15
                            mov rcx, rax
                            bswap rcx
                            mov r11, 15
                            cmp rcx, rdx
                            jnc @@Trash_ROUND_6
                            @@Trash_ROUND_0:
                            pop rax
                            jmp @@Trash_ROUND_5
                            @@Trash_ROUND_1:
                            pop rax
                            lea r11, @@Trash_ROUND_7
                            db 0C3h
                            @@Trash_ROUND_2:
                            imul rcx, rdx
                            jmp @@Trash_ROUND_4
                            @@Trash_ROUND_3:
                            ror rcx, 2
                            rol rcx, 5
                            xor rdx, -1
                            shr rdx, 24
                            cmp rdx, rcx
                            call @@Trash_ROUND_1
                            @@Trash_ROUND_4:
                            call @@Trash_ROUND_0
                            @@Trash_ROUND_5:
                            call MAIN_Label___13___
                            @@Trash_ROUND_6:
                            mov r10, 0F141B56CB94124h
                            ror r10, 3
                            mov rcx, r10
                            mov rbx, r10
                            shl rcx, 10
                            ror rbx, 12
                            xor rcx, rbx
                            dec r11
                            jne @@Trash_ROUND_6
                            mov r10, rcx
                            lea rax, @@Trash_ROUND_3
                            push rax
                            db 0C3h
                            @@Trash_ROUND_7:
                            xadd rax, rcx
                            bsf rdx, rax
                            bsf rdx, rdx
                            bsf rdx, rdx
                            bsf rdx, rdx
                            bsf rdx, rdx
                            bsf rdx, rdx
                            jmp @@Trash_ROUND_2    
                        MAIN_Label___13___:
                            inc rax
                            pop r10
                            lea rdx, MAIN_INDEX_3
                            jmp @@_First_LOOP
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА MAIN_INDEX_4 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤                            
                        MAIN_INDEX_4:
                            mov rbx, 3                      ; Кол-во повторений
                            mov r9, 7                       ; Индекс байта который будет изменен
                            @@Trash_loop:
                                lea r8, HB_POS              ; Адрес начала массива
                                mov al, byte ptr[r8 + r9]
                                push rax                    ; Сохранение значения, так как rdtsc поменяет rax
                                rdtsc                       ; rax = Какое-то число
                                mov cl, Check_INT3_7        ; IF процесс отлаживается -> Check_INT3_7 > 0, ELSE Check_INT3_7 = 0
                                mul cl                      ; IF Check_INT3_7 = 0 -> rax = 0, ELSE rax > 0
                                pop rcx
                                xor rcx, rax                ; Восстановление byte ptr[r8 + r9]
                                mov byte ptr[r8 + r9], cl
                                sub r9, 2                   ; Изменение индекса
                                dec rbx
                                jne @@Trash_loop
                            lea rdx, @@_First_LOOP
                            push rdx
                            lea rdx, MAIN_INDEX_5
                            db 0C3h
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА MAIN_INDEX_6 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        MAIN_INDEX_6:
                        lea rax, INT_3_CHECK__SUM__BEGIN      ; Адрес начала проверки суммы
                        lea rbx, INT_3_CHECK__SUM__END        ; Адрес конца проверки суммы
                            mov r10, 0
                            sub rbx, rax
                            @@loop_X:
                            mov rcx, qword ptr [rax + rbx]
                            add r10, rcx
                            sub rbx, 8
                            bt rbx, 63
                            pushfq
                            pop r8
                            and r8, 1
                            cmp r8, 1
                            jne @@loop_X
                            cmp r10, INT3_SUM_CHECK           ; Если суммы не сходятся то значит происходит отладка, и нужно прыгнуть куда-нибудь
                            jne @@_Cyclic_Shift
                            lea rdx, @@_First_LOOP
                            push rdx
                            lea rdx, MAIN_INDEX_7
                            db 0C3h
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


                        MAIN_INDEX_7:
                            lea rdx, MAIN_INDEX_8
                            jmp @@_First_LOOP
                        MAIN_INDEX_8:
                            lea rdx, MAIN_INDEX_9
                            jmp @@_First_LOOP
                        MAIN_INDEX_9:
                            jmp @@_First_LOOP
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤




                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПЕРЕБОР SECOND_KEY (ПЕРВЫЙ ЦИКЛ {0...7}) ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

                        ; На 8-ом шаге rcx = 8 -> rax = 14CB917A835CFС00, r10 = 95AA86CA6E1AFC00

                        ; В результате на 8 шаге -> (ax = FC00) == (r10w = FC00)

                                                        ;---------------------------|
                                                        INT_3_CHECK__SUM__BEGIN:  ; |      Адрес начала проверки на INT3, а также начала суммы
                                                        ;---------------------------|
                        @@_First_LOOP:

                        ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                         ; PID процесса
                            xchg rdx, rdi                       ; так как, адреса INDEX_MAIN_X передаются через rdx, то нужно сохранить значение 
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1               ; Переменная в которую положиться результат функции
                            lea rbx, @@Debug_ret_X              ; Адрес возврата
                            push rbx                            ; Теперь в стеке
                            mov rax, CheckRemoteDebuggerPresent_address
                            push rax                            ; Адрес вызываемой функции в стеке
                            db 0C3h                             ; Прыжок на CheckRemoteDebuggerPresent_address
                        ;++++++++++++++++++++++++++++++++++++++++++++++

                            @@Debug_ret_X:
                            xchg rdx, rdi                       ; Восстановление INDEX_MAIN_X
                            mov rbx, BIT_FOR_XOR
                            mov rax, VALUE_ONE
                            mov r10, VALUE_TWO
                            mov r9, 0
                            bsf rcx, rax                        ; 1 2 3 4 5 6 7 8 9
                            btc rax, rcx    
                            dec rcx                             ; 0 1 2 3 4 5 6 7 8 -> на этом идет остановка
                            add rcx, CheckRemoteDebuggerPresent_RESULT
                        @@_Cyclic_Shift:
                            mov r8, r10
                            shr r8, 63
                            xor r8b, bl                         ; Так как происходил xor при помощи значения AA... то биты чередуются 
                            xor rbx, -1                         ; not rbx
                            shl rbx, 63   
                            shr rbx, 63                         ; bl 1 bit (0 or 1)
                            shl r10, 1
                            xor r10, r8
                            mov r8, 1
                            cmp r9, r8
                            jz @@_Continue_1
                            inc r9
                            jmp @@_Cyclic_Shift
                        @@_Continue_1:
                            mov r9, 0
                            mov INDEX_COUNTER, rcx
                            mov BIT_FOR_XOR, rbx
                            mov VALUE_ONE, rax
                            mov VALUE_TWO, r10
                            cmp r10w, ax
                            jz Continue_3

                            mov rsi, rcx                        ; Сохранение значения rcx, так как в rcx лежит индекс HB_enc
                            xchg rdi, rdx                       ; Сохранение значения rdx, так как в rdx лежит Адрес следующего MAIN_INDEX_x

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1                              
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            call CheckRemoteDebuggerPresent_address
                            mov rcx, CheckRemoteDebuggerPresent_RESULT
                            ;++++++++++++++++++++++++++++++++++++++++++++++

                            lea rax, INT_3_CHECK__SUM__BEGIN   ; Адрес начала проверки суммы
                            lea rbx, INT_3_CHECK__SUM__END     ; Адрес конца проверки суммы
                            mov r10, 0
                            sub rbx, rax
                            @@loop_Y:
                            mov r12, qword ptr [rax + rbx]
                            add r10, r12
                            sub rbx, 8
                            bt rbx, 63
                            pushfq
                            pop r8
                            and r8, 1
                            cmp r8, 1
                            jne @@loop_Y
                            add r10, rcx
                            cmp r10, INT3_SUM_CHECK            ; Если суммы не сходятся то значит происходит отладка, и нужно прыгнуть куда-нибудь
                            jne OVERLAPPED_INSTRUCTION_4

                            mov rcx, rsi                       ; Восстановление индекса HB_enc
                            xchg rdi, rdx                      ; Восстановление Адрес следующего MAIN_INDEX_x


                                                        ;---------------------------|
                                                        INT_3_CHECK__SUM__END:    ; |      Адрес конца проверки на INT3, а также конца суммы
                                                        ;---------------------------|


                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПЕРЕБОР SECOND_KEY (ВТОРОЙ ЦИКЛ {0...255}) ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        @@_Second_LOOP:
                            or r11 , -1                                     ; INC
                            push rdx                                        ; Сохранение Адреса следующего MAIN_INDEX_x
                            @@_Key_Brute_Force:                     

                                                ;|====================================================|
                                                ;| Данный Блок увеличивает r11 на 1 <=> INC = INC + 1 |
                                                ;|====================================================|

                            jmp MAIN_Label___14___

                            OVERLAPPED_INSTRUCTION_14:
                            sub rax, 03F88348h                              ; 0x4883F803 [cmp rax, 3]
                            jz TRASH_INC_3                                  ; Если rax = 3, то прыжок на TRASH_INC_3
                            jmp MAIN_Label___29___                          ; Иначе

                            OVERLAPPED_INSTRUCTION_7:                       ;                                   -----------------
                            add rax, 50C38349h                              ; 0x4983C301  [add r11, 50]   <=>   | INC = INC + 1 |
                            pop rbx                                         ; Мусорный адрес возврата           -----------------
                            sub r11, 4Fh                                    ; Так как к r11 прибовляется 50h то нужно вычесть 4Fh
                            lea r8, @@INC_
                            push r8
                            db 0C3h   
                            ;=========== TRASH_INC_1 ==========
                            TRASH_INC_1:                    
                            rdtsc
                            mov rbx, rax                                    
                            shl rax, 1                                      ; Мусор
                            inc rax                                         ; Мусор
                            shl rax, 2                                      ; Мусор
                            inc rax                                         ; Мусор
                            shl rax, 3                                      ; Мусор
                            inc rax                                         ; Мусор
                            shl rax, 4                                      ; Мусор
                            inc rax                                         ; Мусор
                            xor rax, rdx                                    ; Мусор
                            jmp MAIN_Label___21___

                            OVERLAPPED_INSTRUCTION_5:                       ;                                 -----------------
                            test rax, 0D8034D71h                            ; 0x4D030D  [add r11, r8]   <=>   | INC = INC + 1 |
                            lea rbx, @@INC_                                 ;                                 -----------------
                            push rbx
                            pop rbx
                            jmp rbx                                         ; Выход из блока

                            ;=========== TRASH_INC_7 ==========
                            TRASH_INC_7:
                            lea rax, TRASH_INC_1
                            push rax
                            db 0C3h                                         ; Переход на TRASH_INC_1

                            ;=========== TRASH_INC_1 ==========
                            MAIN_Label___21___:
                            mov r9, rax                                     ; Мусор
                            add r9, rdx                                     ; Мусор
                            xor r9, -1                                      ; Мусор
                            not r9                                          ; Мусор
                            lea rdx, OVERLAPPED_INSTRUCTION_5               ; Адрес перекрытой инструкции
                            and rax, 63                                     ; Мусор
                            btc r9, rax                                     ; Мусор
                            pushfq                                          
                            pop r8
                            or r8, 1
                            and r8, 1                                       ; r8 Всегда равен 1
                            push rdx                                        ; Адрес в стеке
                            rdtsc                                           
                            sub rax, rbx                                    
                            cmp rax, 30000h                                 ; Проверка на отладку
                            ja @@Trash_ROUND_1                              ; Прыжок не туда, куда нужно
                            xor rax, -1                                     ; Мусор
                            inc rax                                         ; Мусор
                            shl rax, 2                                      ; Мусор
                            or r10, -1
                            not r10
                            add r10b, Check_INT3_10                         ; IF процесс отлаживается -> Check_INT3_10 > 0, ELSE Check_INT3_10 = 0 
                            add r10, r9
                            cmp r10, r9
                            jne @@INC_                                      ; Прыжок не туда, куда нужно

                            add rax, 3                                      ; Мусор
                            ror rax, 2                                      ; Мусор
                            shr rax, 62                                     ; Мусор
                            add qword ptr[rsp], rax                         ; Адрес + 3 начинается [add r11, r8]
                            db 0C3h                                         ; Прыжок на перекрытую инструкцию OVERLAPPED_INSTRUCTION_5


                            MAIN_Label___14___:
                            rdtsc                                           ; Инициализация значения для рандомизации
                            xor rax, 4895681h                               ; Мусор
                            shl rdx, 32                                     ; Мусор
                            xor rdx, rax                                    ; Мусор
                            mov rbx, rdx                                    ; Мусор
                            lea r8, MAIN_Label___15___
                            push r8
                            db 0C3h


                            ;=========== TRASH_INC_0 ==========
                            TRASH_INC_0:                                    ; В результате всегда r11++
                            rdtsc                                           ; Мусор
                            mov r8, rax                                     ; Мусор
                            xor rdx, 3894593h                               ; Мусор
                            inc rdx                                         ; Мусор
                            bswap rdx                                       ; Мусор
                            mov r9, rax                                     ; Мусор
                            xor rax, 0AABB1CDDh                             ; Мусор
                            jmp MAIN_Label___22___                          ; Пропуск перекрытой инструкции

                            OVERLAPPED_INSTRUCTION_4:                       ;                             -----------------
                            mov rcx, 0C3FF49A14317AC42h                     ; 0x49FFC3  [inc r11]    <=>  | INC = INC + 1 |
                            lea rax, @@INC_                                 ;                             -----------------
                            push rax
                            db 0C3h                                         ; Выход из блока

                            ;=========== TRASH_INC_0 ==========
                            MAIN_Label___22___:
                            dec rax                                         ; Мусор
                            xor rax, rdx                                    ; Мусор
                            mov r9, rdx                                     ; Мусор
                            inc rdx                                         ; Мусор
                            sub rdx, r9                                     ; Мусор
                            lea r9, OVERLAPPED_INSTRUCTION_4                ; Адрес перекрытой инструкции
                            and rdx, 7                                      ; Число от 0 до 7
                            btr rdx, 0                                      
                            inc rdx
                            or rdx, 2
                            bts rdx, 2                                      ; rdx Всегда равняется 7
                            add rdx, r9                                     ; Адрес + 7 начинается [inc r11]
                            push rdx                                        ; Адрес в стеке
                            rdtsc                                           ; Мусор
                            sub rax, r8                                     ; Мусор
                            btr rax, 63
                            cmp rax, 20000h                                 ; Проверка на отладку, если время больше чем 20000h, то прыжок не туда куда нужно
                            ja OVERLAPPED_INSTRUCTION_6
                            xor r9, rax                                     ; Мусор
                            mov rdx, rax
                            movzx rdx, Check_INT3_4                         ; IF процесс отлаживается -> Check_INT3_4 > 0, ELSE Check_INT3_4 = 0
                            add rdx, rax                            
                            cmp rdx, rax                                    
                            jne MAIN_INDEX_7                                ; Прыжок не туда, куда нужно
                            mov r8, 67                                      ; Мусор
                            shl r8, 5                                       ; Мусор
                            sub rdx, r8                                     ; Мусор
                            db 0C3h                                         ; Прыжок на перекрытую инструкцию OVERLAPPED_INSTRUCTION_4


                            MAIN_Label___15___:
                            rdtsc                                           ; Мусор
                            xor rbx, rax                                    ; Мусор
                            bswap rdx                                       ; Мусор
                            rol rdx, 10                                     ; Мусор
                            xor rbx, rdx                                    ; Мусор
                            mov rdx, 0                                      ; Мусор
                            imul rax, rbx                                   ; Мусор
                            call MAIN_Label___16___                         ; Мусорный адрес возврата в стеке

                            ;=========== TRASH_INC_2 ==========
                            TRASH_INC_2:
                            rdtsc
                            xchg r8, rax                                    
                            add rax, r8                                     ; Мусор
                            bswap rdx                                       ; Мусор
                            xor rdx, r8                                     ; Мусор
                            shl rdx, 32                                     ; Мусор
                            xor rdx, 38945893h                              ; Мусор
                            ror rdx, 43                                     ; Мусор
                            lea rax, OVERLAPPED_INSTRUCTION_6               ; Адрес перекрытой инструкции
                            push rax                                        ; Адрес в стеке
                            lea rax, MAIN_Label___19___
                            push rax
                            db 0C3h                                         ; Прыжок на MAIN_Label___19___

                            ;=========== TRASH_INC_5 ==========
                            TRASH_INC_5:
                            rdtsc
                            mov r9, rax
                            lea rax, TRASH_INC_3                            ; Адрес перехода на TRASH_INC_3
                            push rax                                        ; Адрес в стеке
                            rol r8, 42                                      ; Мусор
                            inc r8                                          ; Мусор
                            bt r8, 63                                       ; Мусор
                            
                            xor rax, rdx                                    ; Мусор
                            shl r8, 3                                       ; Мусор
                            bsf rdx, rdx
                            bts r8, 1
                            bsf rdx, rdx
                            btc r8, 31
                            bsf rdx, rdx
                            bts r8, 34
                            bsf rdx, rdx
                            btc r8, 39
                            bsf rdx, rdx
                            bts r8, 54
                            bsf rdx, rdx
                            btc r8, 10
                            add dl, Check_INT3_5                            ; Если отлаживают Check_INT3_5 > 0 | Check_INT3_7 > 0
                            add dl, Check_INT3_7
                            add rdx, r8
                            cmp r8, rdx
                            jc @@Trash_continue_45
                            or r8, -1
                            shr r8, 63                                      ; Мусор
                            rdtsc
                            sub rax, r9
                            cmp rax, 20000h
                            ja MAIN_Label___10___
                            db 0C3h                                         ; Переход на TRASH_INC_3
                            inc r11                                         ; Мусор
                            jmp @@INC_                                      ; Мусор


                            OVERLAPPED_INSTRUCTION_6:                       ;                                 -----------------
                            push 0D9034D11h                                 ; 0x4D03D9  [add r11, r9]    <=>  | INC = INC + 1 |
                            pop rbx                                         ;                                 -----------------
                            lea rbx, @@INC_
                            push rbx                                        ; Адрес выхода из блока
                            pop rbx
                            jmp rbx                                         ; Выход из блока

                            ;=========== TRASH_INC_2 ==========
                            MAIN_Label___19___:
                            inc qword ptr[rsp]                              ; Адрес + 1
                            inc rdx                                         ; Мусор
                            bt rdx, 63                                      ; Проверка бита под номером 63 в r8
                            pushfq                                          ; Мусор
                            pop r9                                          ; Мусор
                            ror r9, 1                                       ; Мусор
                            or r9, -1
                            shr r9, 63                                      ; r9 Всегда равняется 1
                            push -1
                            pop rdx
                            xor rdx, -1                                     ; rdx = 0
                            add dl, Check_INT3_7                            ; IF процесс отлаживается -> Check_INT3_7 > 0, ELSE Check_INT3_7 = 0
                            add rdx, rax
                            cmp rax, rdx
                            jc OVERLAPPED_INSTRUCTION_0                     ; Прыжок не туда
                            rdtsc
                            sub rax, r8
                            bt rax, 63
                            cmp rax, 30000h                                 ; Проверка на отладку
                            ja @@Second_xor                                 ; Прыжок не туда
                            add qword ptr[rsp], r9                          ; Адрес + 1
                            jmp qword ptr[rsp]                              ; Прыжок на перекрытую инструкцию OVERLAPPED_INSTRUCTION_6

                            OVERLAPPED_INSTRUCTION_13:
                            mov rax, 01F88348FC915113h                      ; 0x4883F801 [cmp rax, 1]
                            jz TRASH_INC_1                                  ; Если rax = 1, то прыжок на TRASH_INC_1
                            jmp MAIN_Label___28___                          ; Иначе

                            MAIN_Label___16___:
                            inc rbx
                            sub rbx, 4895681h
                            xor rbx, -1
                            inc rbx                                         ; neg rbx
                            pop r9                                          ; Вытаскивание мусорного адреса возврата из стека
                            lea r9, MAIN_Label___17___
                            push r9                                         ; Мусорный адрес возврата в стеке
                            jmp qword ptr [rsp]

                            ;=========== TRASH_INC_4 ==========
                            TRASH_INC_4:
                            rdtsc
                            mov r9, rax
                            mov rax, r8                                     ; Мусор
                            inc rax                                         ; Мусор
                            inc r8                                          ; Мусор
                            add r8, rax                                     ; Мусор
                            rol rdx, 12                                     ; Мусор
                            xor rdx, r8                                     ; Мусор
                            lea rax, TRASH_INC_0                            ; Адрес начала TRASH_INC_0
                            shl rdx, 1
                            add rdx, 1
                            lea rbx, MAIN_Label___18___                     ; Адрес продолжение так как далее идет TRASH_INC_3
                            push rbx
                            db 0C3h                                         ; Переход на MAIN_Label___18___

                            OVERLAPPED_INSTRUCTION_12:
                            sub rax, 06F88348h                              ; 0x4883F806 [cmp rax, 6]
                            jz TRASH_INC_6                                  ; Если rax = 6, то прыжок на TRASH_INC_6
                            jmp MAIN_Label___27___                          ; Иначе

                            ;=========== TRASH_INC_3 ==========
                            TRASH_INC_3:
                            rdtsc
                            mov r9, rax
                            xor rax, 37578873h                              ; Мусор
                            add rax, 8388234h                               ; Мусор
                            add rdx, 1                                      ; Мусор
                            lea rbx, OVERLAPPED_INSTRUCTION_7               ; Адрес перекрытой инструкции
                            shl rdx, 1                                      ; Мусор
                            xor rdx, 1                                      ; Мусор
                            bswap rdx                                       ; Мусор
                            mov r8, rdx                                     ; Мусор
                            rol r8, 34                                      ; Мусор
                            xor r8, rax                                     ; Мусор
                            push rbx                                        ; Адрес в стеке
                            ror r8, 42                                      ; Мусор
                            xor r8, rdx                                     ; Мусор
                            shl r8, 1                                       ; Мусор
                            and r8, 1
                            btr r8, 0
                            add r8b, Check_INT3_2                           ; IF процесс отлаживается -> Check_INT3_2 > 0 | Check_INT3_9 > 0, ELSE Check_INT3_9 = 0 & Check_INT3_2 = 0
                            add r8b, Check_INT3_9
                            add r8, rdx
                            cmp rdx, r8
                            jc Continue_3                                   ; Прыжок не туда
                            inc r8                                          ; Мусор
                            and r8, 1                                       ; Мусор
                            add r11, r8                                     ; Мусор 
                            stc                                             ; Мусор
                            sbb rax, rax                                    ; Мусор
                            not rax                                         ; Мусор
                            or r8, rax                                      ; Мусор
                            sub r11, r8                                     ; Мусор
                            inc r11                                         ; Мусор
                            dec r11                                         ; Мусор
                            pop r8                                          
                            add r8, 2                                       ; Адрес + 2 начинается [add r11, 50]
                            xor r8, rax                                     ; Мусор
                            push r8                                         ; Адрес снова в стеке
                            rdtsc
                            sub rax, r9                                     
                            cmp rax, 30000h                                 ; Проверка на отладку
                            ja @@Trash_ROUND_7
                            jmp qword ptr[rsp]                              ; Прыжок на перекрытую инструкцию OVERLAPPED_INSTRUCTION_7

                            OVERLAPPED_INSTRUCTION_9:
                            mov rax, 07F88348AC561294h                      ; 0x4883F807 [cmp rax, 7]
                            jz TRASH_INC_7                                  ; Если rax = 7, то прыжок на TRASH_INC_7
                            jmp MAIN_Label___24___                          ; Иначе
                            
                            ;=========== TRASH_INC_4 ==========
                            MAIN_Label___18___:
                            inc rax                                         ; Мусор
                            rol rax, 32                                     ; Мусор
                            xor rax, 845623h                                ; Мусор
                            ror rdx, 1                                      ; Мусор
                            shr rdx, 63                                     ; Мусор
                            add rdx, r8                                     ; Мусор
                            xor rax, 845623h                                ; Мусор
                            ror rax, 32                                     ; Мусор
                            dec rax                                         ; Мусор
                            xchg rbx, rax                                   ; Сохранение TRASH_INC_0 так как после rdtsc значение rax изменется 
                            rdtsc                               
                            sub rax, r9                                     
                            cmp rax, 30000h                                 ; Проверка на отладку
                            ja @@Trash_FOR
                            push rbx
                            movzx rbx, Check_INT3_3                         ; IF процесс отлаживается -> Check_INT3_3 > 0 , ELSE Check_INT3_3 = 0
                            shl rbx, 3
                            add qword ptr[rsp], rbx                         ; Прыжок закончиться исключением
                            db 0C3h                                         ; Переход на TRASH_INC_0
                            jmp @@INC_
                            
                            OVERLAPPED_INSTRUCTION_10:
                            mov rax, 05F88348496AC004h                      ; 0x4883F805 [cmp rax, 5]
                            jz TRASH_INC_5                                  ; Если rax = 5, то прыжок на TRASH_INC_5
                            jmp MAIN_Label___25___                          ; Иначе

                            MAIN_Label___17___:
                            xchg rbx, rcx
                            and rcx, 63
                            rol rax, cl
                            xchg rbx, rcx
                            and rax, 7                                      ; rax => {0...7}
                            pop rbx                                         ; Вытаскивание мусорного адреса возврата из стека
                            jmp MAIN_Label___20___


                            OVERLAPPED_INSTRUCTION_8: 
                            cmp rax, 00F88348h                              ; 0x4883F800 [cmp rax, 0]
                            jz TRASH_INC_0                                  ; Если rax = 0, то прыжок на TRASH_INC_0
                            jmp MAIN_Label___23___                          ; Иначе


                            ;=========== TRASH_INC_6 ==========
                            TRASH_INC_6:
                            lea rax, TRASH_INC_2
                            push rax                                        ; Адрес перехода на TRASH_INC_2
                            inc r8
                            xor r8, 2934929h
                            xor rbx, rbx
                            add bl, Check_INT3_13
                            add bl, Check_INT3_12
                            add rbx, r8
                            cmp rbx, r8
                            jne @@Trash_ROUND_12
                            db 0C3h                                         ; Переход на TRASH_INC_2
                            
                            OVERLAPPED_INSTRUCTION_11:                      
                            cmp rax, 02F88348h                              ; 0x4883F802 [cmp rax, 2]
                            jz TRASH_INC_2                                  ; Если rax = 2, то прыжок на TRASH_INC_2
                            jmp MAIN_Label___26___                          ; Иначе

                            MAIN_Label___20___:
                            xchg r8, rax                                    ; Сохранение значения {0...7}
                            lea r9, OVERLAPPED_INSTRUCTION_8                ; Адрес перекрытой инструкции
                            push r9                                         ; Адрес в стеке
                            rdtsc                                           ; Мусор
                            xor rdx, 3845825h                               ; Мусор
                            inc rdx                                         ; Мусор
                            shl rdx, 1                                      ; Мусор
                            inc rdx                                         ; Мусор
                            and rdx, 1                                      ; rdx = 1
                            add rdx, 1                                      ; rdx = 2
                            xchg r8, rax                                    ; Возвращение значения {0...7}
                            add qword ptr[rsp], rdx                         ; Адрес + 2 начинается [cmp rax, 0]
                            db 0C3h                                         ; Переход на OVERLAPPED_INSTRUCTION_8

                            MAIN_Label___23___:
                            lea r8, OVERLAPPED_INSTRUCTION_9                ; Адрес перекрытой инструкции
                            mov r9, rax                                     ; Сохранение значения {0...7}
                            mov rax, 11F88349h                              ; Мусор
                            xor rax, rdx                                    ; Мусор
                            inc rax                                         ; Мусор
                            mov rbx, rax                                    ; Мусор
                            rol rbx, 34                                     ; Мусор
                            or rax, 3                                                  
                            and rax, 3                                      ; rax = 3
                            shl rax, 1                                      ; rax = 6
                            add rax, 1                                      ; rax = 7
                            add r8, rax                                     ; Адрес + 7 начинается [cmp rax, 7]
                            push r8                                         ; Адрес в стеке
                            xchg r9, rax                                    ; Возвращение значения {0...7}
                            db 0C3h                                         ; Переход на OVERLAPPED_INSTRUCTION_9

                            MAIN_Label___24___:
                            inc rdx                                         ; Мусор
                            shl rdx, 3                                      ; Мусор
                            xor r8, 5613264h                                ; Мусор
                            lea r9, OVERLAPPED_INSTRUCTION_10               ; Адрес перекрытой инструкции 
                            xor r8, 5613264h                                ; Мусор
                            bswap r8                                        ; Мусор
                            xor rbx, r8                                     ; Мусор
                            bswap rbx                                       ; Мусор
                            rol rbx, 23                                     
                            or rbx, 7                                       
                            ror rbx, 3                                      
                            shr rbx, 61                                     ; rbx = 7
                            add r9, rbx                                     ; Адрес + 7 начинается [cmp rax, 5]
                            jmp r9                                          ; Переход на OVERLAPPED_INSTRUCTION_10

                            MAIN_Label___25___:
                            stc                                             ; Мусор
                            sbb rbx, rbx                                    ; Мусор
                            rol rbx, 4                                      ; Мусор
                            lea rbx, OVERLAPPED_INSTRUCTION_11              ; Адрес перекрытой инструкции 
                            ror rbx, 14                                     ; Мусор
                            inc rbx                                         ; Мусор
                            xor rdx, rbx                                    ; Мусор
                            lea rdx, MAIN_Label___25___                     ; Мусор
                            push rdx                                        ; Мусор
                            shl rdx, 1                                      ; Мусор
                            and rdx, 0
                            bts rdx, 1                                      ; rdx = 2
                            pop r8                                          ; Мусор
                            dec rbx                                         ; Мусор
                            rol rbx, 14                                     ; Мусор
                            add rbx, rdx                                    ; Адрес + 2 начинается [cmp rax, 2]
                            jmp rbx                                         ; Переход на OVERLAPPED_INSTRUCTION_11
                            
                            MAIN_Label___26___:
                            lea rdx, OVERLAPPED_INSTRUCTION_12              ; Адрес перекрытой инструкции 
                            add rdx, 2                                      ; Адрес + 2 начинается [cmp rax, 6]
                            push rdx                                        ; Адрес в стеке
                            db 0C3h                                         ; Переход на OVERLAPPED_INSTRUCTION_12
                            
                            MAIN_Label___27___:
                            lea rdx, OVERLAPPED_INSTRUCTION_13
                            mov rbx, 39599125h
                            bts rbx, 2
                            and rbx, 4
                            add rbx, 3                                      ; rbx = 7
                            add rdx, rbx                                    ; Адрес + 2 начинается [cmp rax, 1]
                            push rdx                                        ; Адрес в стеке
                            db 0C3h                                         ; Переход на OVERLAPPED_INSTRUCTION_13

                            MAIN_Label___28___:
                            lea r8, OVERLAPPED_INSTRUCTION_14               ; Адрес перекрытой инструкции
                            inc r8
                            sub r8, 2
                            add r8, 3                                       ; Адрес + 2 начинается [cmp rax, 3]
                            push r8                                         ; Адрес в стеке
                            db 0C3h                                         ; Переход на OVERLAPPED_INSTRUCTION_14


                            MAIN_Label___29___:
                            cmp rax, 4                                      ; Если rax = 4, то прыжок на TRASH_INC_4
                            jz TRASH_INC_4


                                        ;|==============================================================|
                                        ;| Конец Блока, который  увеличивает r11 на 1 <=> INC = INC + 1 |
                                        ;|==============================================================|


                                                   ; |=========================================|
                                                   ; | Second_Key_Byte = INC ^ factor_prime[i] |
                                                   ; |=========================================|

                        @@INC_:
                            lea r14, FACTOR_RESULT
                            movzx rbx, byte ptr[r14 + rcx]      ; factor_prime[i]
                            mov rax, r11
                            stc
                            sbb rdx, rdx
                            xor rdx, -1                         ; rdx = 0

                            @@First_xor:
                            bt rbx, 0
                            pushfq
                            pop r10
                            shl r10, 63             
                            rol r10, 1                          ; r10 = CF = 0 | r10 = CF = 1
                            xchg rcx, rdx              
                            shl r10, cl
                            xor rax, r10
                            xchg rdx, rcx
                            inc rdx              
                            shr rbx, 1                          ; уменьшение factor_prime[i] чтобы получить значение следующего бита (bt rbx, 0)
                            cmp rbx, 0                          ; На выходе получается rax = rax ^ rbx
                            jne @@First_xor

                                                         ; |=============================|
                                                         ; | POS = HB_POS[i] ^ HB_ENC[i] |
                                                         ; |=============================|

                            ; X xor Y = (not X | not Y) & (X | Y)
                            lea rdi, HB_POS
                            movzx r12, Check_INT3_5             ; Если отлаживают, то Check_INT3_5 > 0
                            add rdi, r12                        ; IF Check_INT3_5 > 0 -> не правильный адрес HB_POS
                            movzx r12, byte ptr[rdi + rcx]      ; HB_POS[i] - зашифрованный         r12 = X
                            lea rsi, ENCRYPTED_HINT_BYTES
                            movzx rbx, byte ptr[rsi + rcx]      ; HB_ENC[i]                         rbx = Y
                            push rax                            ; Second_Key_Byte
                            xor rax, rax
                            mov rdx, 7
                            xchg rdx, rcx

                            @@Second_xor:
                            mov r9, r12
                            shr r9, cl                          ; Смещение для получения cl бита числа X
                            ror r9, 1
                            shr r9, 63
                            xor r9, -1                          ; not X
                            and r9, 1                           
                            mov r10, r9                         
                            mov r8, rbx 
                            shr r8, cl                          ; Смещение для получения cl бита числа Y
                            ror r8, 1
                            shr r8, 63
                            not r8                              ; not Y
                            and r8, 1                            
                            mov r13, r8
                            or r9, r8                           ; not X | not Y
                            xor r10, -1                         ; not not X == X
                            and r10, 1
                            not r13                             ; not not Y == Y
                            and r13, 1
                            or r10, r13
                            and r9, r10                         ; (not X | not Y) & (X | Y)
                            add rax, r9                         ; POS
                            shl rax, 1
                            dec rcx
                            cmp rcx, -1
                            jne @@Second_xor
                            shr rax, 1
                            xchg rdx, rcx
                                                        ; |================================|
                                                        ; | Second_Key_Byte == HB_ENC[POS] |
                                                        ; |================================|
                        
                            movzx r9, byte ptr[rsi + rax]       ; HB_ENC[POS]
                            mov r10, rax                        ; POS
                            pop rax                             ; Second_Key_Byte = INC ^ factor_prime[i]
                            or r15, -1
                            not r15                             ; r15 = 0
                            add r15b, Check_INT3_0
                            add r15b, Check_INT3_4
                            add r10, r15
                            lea r15, SECOND_KEY
                            mov byte ptr[r15 + r10], r11b       ; SECOND_KEY[POS] = Second_Key_Byte
                            cmp r9, rax
                            jne @@_Key_Brute_Force
                            db 0C3h                             ; Адрес следующего MAIN_INDEX_x




                       ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА MAIN_INDEX_1 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        MAIN_INDEX_1:
                        ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rcx, -1
                            lea rdx, MAIN_Label___12___
                            push rdx                            ; Адрес MAIN_Label___12___ в стеке
                            mov rdx, CheckRemoteDebuggerPresent_address
                            push rdx                            ; Адрес CheckRemoteDebuggerPresent_address в стеке 
                            lea rdx, CheckRemoteDebuggerPresent_RESULT
                            mov qword ptr[rdx], 1
                            db 0C3h
                        ;++++++++++++++++++++++++++++++++++++++++++++++

                        MAIN_Label___12___:

                                ;  |=========================================================|
                                ;  |  x = (HB_POS[i] & 0x55) << 1 | (HB_POS[i] & 0xAA) >> 1  |
                                ;  |  x = (x & 0x33) << 2         |         (x & 0xCC) >> 2  |
                                ;  |  x = (x & 0x0F) << 4         |         (x & 0xF0) >> 4  |
                                ;  |=========================================================|

                            mov r9, CheckRemoteDebuggerPresent_RESULT
                            mov r8, 6                           ; Кол-во повторений
                            @@Trash_FOR:
                            mov rax, 0A1983CB15F12183Dh         ; Мусор
                            dec rax                             ; Мусор
                            rol rax, 32                         ; Мусор
                            xor rax, 341A8351h                  ; Мусор
                            xchg rax, rbx                       ; Мусор
                            rdtsc                                
                            sub rbx, rax
                            xor rbx, rdx
                            lea rsi, HB_POS                     ; HB_POS
                            ror rbx, 3
                            shr rbx, 61                         ; rbx = 0 ... 7
                            mov r10, rbx                        ; Позиция байта, который будет зеркалиться
                            mov bl, byte ptr[rsi + rbx]         ; HB_POS[rbx]
                            mov rcx, 1                          ; для смещения на 1, 2, 4
                            add rcx, r9                         ; Здесь будет проверка на отладку
                            mov al, bl
                            and al, 55h                         
                            shl al, cl                          ; A = (HB_POS[rbx] & 0x55) << 1
                            and bl, 0AAh                        
                            shr bl, cl                          ; B = (HB_POS[rbx] & 0xAA) >> 1
                            or bl, al                           ; A | B
                            
                            mov rcx, 2
                            add rcx, r9                          ; Здесь будет проверка на отладку
                            mov al, bl
                            and al, 33h
                            shl al, cl                          ; A = (HB_POS[rbx] & 0x33) << 2
                            and bl, 0CCh
                            shr bl, cl                          ; B = (HB_POS[rbx] & 0xCC) >> 2
                            or bl, al                           ; A | B
                            
                            mov rcx, 4
                            add rcx, r9                          ; Здесь будет проверка на отладку
                            mov al, bl
                            and al, 0Fh
                            shl al, cl                          ; A = (HB_POS[rbx] & 0x0F) << 4
                            and bl, 0F0h
                            shr bl, cl                          ; B = (HB_POS[rbx] & 0F0x) >> 4
                            or bl, al                           ; A | B
                            mov byte ptr[rsi + r10], bl         ; Кладем отзеркаленный байт, на место по индексу r10
                            mov rcx, 1                          ; для смещения на 1, 2, 4
                            add rcx, r9                         ; Здесь будет проверка на отладку
                            mov al, bl
                            and al, 55h                         
                            shl al, cl                          ; A = (HB_POS[rbx] & 0x55) << 1
                            
                            and bl, 0AAh                        
                            shr bl, cl                          ; B = (HB_POS[rbx] & 0xAA) >> 1
                            or bl, al                           ; A | B
                            mov rcx, 2
                            add rcx, r9                         ; Здесь будет проверка на отладку
                            mov al, bl
                            and al, 33h
                            shl al, cl                          ; A = (HB_POS[rbx] & 0x33) << 2
                            
                            and bl, 0CCh
                            shr bl, cl                          ; B = (HB_POS[rbx] & 0xCC) >> 2
                            or bl, al                           ; A | B
                            mov rcx, 4
                            add rcx, r9                         ; Здесь будет проверка на отладку
                            mov al, bl
                            and al, 0Fh
                            shl al, cl                          ; A = (HB_POS[rbx] & 0x0F) << 4
                            
                            and bl, 0F0h
                            shr bl, cl                          ; B = (HB_POS[rbx] & 0F0x) >> 4
                            or bl, al                           ; A | B
                            mov byte ptr[rsi + r10], bl
                            dec r8
                            jne @@Trash_FOR
                            lea rdx, MAIN_INDEX_2
                            jmp @@_First_LOOP
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА MAIN_INDEX_3 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        MAIN_INDEX_3:
                            rdtsc
                            shl rdx, 32
                            xor rax, rdx
                            mov r11, rax
                            ror rax, 16                
                            and rax, 7                      ; Индекс байта который будет изменен
                            push rax                        ; Сохраняем индекс 
                            lea rdi, FACTOR_RESULT
                            push 50
                            pop r9
                            stc
                            sbb r9, r9
                            add r9, 5                       ; r9 = 4
                            movzx rcx, byte ptr[rdi + rax]  ; factor_prime[rax]
                            btc rcx, r9                     ; Изменяем r9 бит регистра rcx
                            mov byte ptr[rdi + rax], cl     ; Переписываем factor_prime[rax] = rcx
                            lea rdx, OVERLAPPED_INSTRUCTION_1
                            xor r11, 8243CB45h
                            inc r11
                            rol r11, 18
                            rol r11, 12
                            xchg rdx, rcx                   ; Адрес OVERLAPPED_INSTRUCTION_1 
                            rdtsc
                            xor rdx, r11
                            mov r12, rdx
                            and r12, 60
                            bts rdx, r12                    ; Меняем бит rdx под номером значения r12 на 1
                            btc rdx, r12                    ; Меняем бит rdx под номером значения r12 на 0, Всегда CF=1
                            pushfq              
                            pop r8      
                            shl r8, 63
                            rol r8, 1                       ; r8 = 1
                            add rcx, r8                     
                            xchg rcx, rdx
                            rol r11, 32
                            and r11, 45
                            cmp r11, rax
                            pushfq              
                            pop r8
                            and r8, 1                       ; r8 = 1
                            add rdx, r8
                            pop rax
                            push rax
                            movzx rcx, byte ptr[rdi + rax]  ; factor_prime[rax]
                            jmp @@Continue_2
                        @@_ret_0:
                            pop rdx
                            jmp rdx
                        @@Continue_2:
                            xor r9, rax
                            inc r9
                            shl r9, 15
                            xor r9, rdx
                            jmp @@Trash_ROUND_11
                            @@Trash_ROUND_8:
                            rol rax, 15
                            sub r9, rax
                            shl r9, 5
                            inc r9
                            jmp @@Trash_ROUND_10
                            @@Trash_ROUND_9:
                            xor r9, rcx
                            call @@Trash_ROUND_12
                            @@Trash_ROUND_10:
                            xor rcx, r9
                            lea r10, @@Trash_ROUND_12
                            push r10
                            pop rax
                            jmp @@Trash_ROUND_9
                            @@Trash_ROUND_11:
                            push rdx
                            rdtsc
                            add r9, rdx
                            lea rax, @@Trash_ROUND_8
                            push rax
                            db 0C3h
                            @@Trash_ROUND_12:
                            pop rax
                            xchg rcx, r9
                            xor r9, rax
                            shl r9, 1
                            bts r9, 0                       ; Нулевой бит r9 = 1
                            pushfq
                            pop rax
                            and rax, 1                      ; rax = 0 | rax = 1
                            shl r9, 63
                            rol r9, 1
                            or r9, rax                      ; r9 = 1
                            or rax, -1
                            add rax, 4                      ; rax = 3
                            add r9, rax                     ; r9 = 4

                            ;++++++++++++++ БЛОК АНТИОТЛАДКИ ++++++++++++++
                            mov rax, PEB_address            ; Адрес начала структуры PEB
                            mov rax, qword ptr[rax]         ; 8 Байт структуры PEB в rax
                            and rax, 10000h                 ; Так как поле beingDebug Находится по смещению PEB + 2, дабы глазами было тежялей зацепиться за эту константу
                            shr rax, 16                     ; IF процесс отлаживают -> rax = 1, ELSE rax = 0
                            and rax, 1                      ; rax = 0 | 1
                            ;++++++++++++++++++++++++++++++++++++++++++++++

                            add r9, rax                     ; IF rax = 0 -> r9 = 4, ELSE rax = 1 -> r9 = 5
                            jmp @@_ret_0
                        OVERLAPPED_INSTRUCTION_1:
                            cmp rax, 0C9BB0F4Ch             ; btc rcx, r9
                            pop rax
                            mov byte ptr[rdi + rax], cl     ; Переписываем factor_prime[rax] = rcx
                            lea rdx, MAIN_INDEX_4
                            jmp @@_First_LOOP



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ПОДГОТОВКА MAIN_INDEX_5 ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        MAIN_INDEX_5:
                            lea rdi, ENCRYPTED_HINT_BYTES    ; Адрес массива, где лежат зашифрованные байты подсказки
                            mov rcx, qword ptr[rdi]        
                            rdtsc                           
                            push rax                         ; Для проверки на отладку
                            bswap rax
                            xor rax, 8345145h
                            ror rax, 5
                            xor rax, rdx
                            rol rax, 8
                            xor rax, 1852914h
                            ror rax, 9
                            xor rcx, rax                     ; rcx зашифрован
                            jmp @@Trash_ROUND_13

                            OVERLAPPED_INSTRUCTION_15:
                            mov rdx, 0C83348F13491A394h      ; 0x4833C8 [xor rcx, rax]
                            pop r10                          ; Вытаскивание муссорного адреса из стека
                            mov qword ptr[rdi], rcx
                            jmp @@Trash_ROUND_14

                            OVERLAPPED_INSTRUCTION_16:
                            mov rdx, 0C23348A334958BD1h      ; 0x4833C2 [xor rax, rdx]
                            xor rcx, rax
                            pop r10                          ; Вытаскивание муссорного адреса из стека
                            mov qword ptr[rdi], rcx
                            jmp @@Trash_ROUND_14

                            @@Trash_ROUND_13:
                            and rdx, 7                       ; rdx = {0...7}
                            bt rdx, 0                       
                            pushfq
                            pop r9
                            and r9, 1
                            or r9, 1
                            or rdx, r9                       ; Нулевой бит rdx всегда равен 1
                            bts rdx, 1                       ; Первый бит rdx всегда равен 1
                            shl rdx, 4
                            bsf r8, rdx                      ; r8 всегда равен 4
                            shr rdx, 4      
                            btr rdx, 2              
                            xor rdx, r8                      ; rdx всегда равен 7
                            mov r8, rdx                      

                         lea rdx, OVERLAPPED_INSTRUCTION_16  ; Адрес перекрытой инструкции
                         lea rbx, OVERLAPPED_INSTRUCTION_15  ; Адрес перекрытой инструкции

                            movzx r10, Check_INT3_1          ; Если программу не отлаживают то Check_INT3_1 всегда равен 0, иначе он Check_INT3_1 > 0
                            add r10b, Check_INT3_9
                            add r10b, Check_INT3_4
                                                            ; |=================|
                                                            ; | IF (r10 == 0)   |  
                                                            ; |   r10 = rbx     |
                                                            ; | ELSE            |
                                                            ; |   r10 = rdx     |
                                                            ; |=================|

                            cmp r10, 1                       ; IF (r10 =  0)  -> CF = 1,       ELSE (r10 >  0)   -> CF = 0
                            sbb r10, r10                     ; IF (CF  =  1)  -> r10 = -1,     ELSE (CF  =  1)   -> r10 = 0
                            add rbx, r8                      ; Адрес + 7 начинается [xor rcx, rax]
                            and rbx, r10                     ; IF (r10 = -1)  -> rbx = rbx,    ELSE (r10 =  0)   -> rbx = 0
                            xor r10, -1                      ; IF (r10 = -1)  -> r10 = 0,      ELSE (r10 =  0)   -> r10 = -1
                            add rdx, r8                      ; Адрес + 7 начинается [xor rax, rdx]
                            and r10, rdx                     ; IF (r10 =  0)  -> r10 = 0,      ELSE (r10 = -1)   -> r10 = rdx
                            or r10, rbx                      ; IF (r10 =  0)  -> r10 = rbx,    ELSE (r10 =  rdx) -> r10 = rdx, так как ранее rbx стал равен 0
                            call r10                         ; Прыжок на одну из перекрытых функций
                            @@Trash_ROUND_14:
                            pop r10
                            rdtsc
                            sub rax, r10
                            btr rax, 63
                            lea rdx, MAIN_Label___11___
                            cmp rax, 30000h                  ; Если происходит отладка
                            ja @@_First_LOOP                 ; а там прыжок на MAIN_Label___11___, так как блок кода за @@_First_LOOP, после всех действий прыгает на значение rdx
                            lea rdx, @@_First_LOOP
                            push rdx
                            lea rdx, MAIN_INDEX_6
                            db 0C3h
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ СБОРКА MAIN_KEY ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
Continue_3:
                            movzx rbx, Check_INT3_2                 ; IF процесс отлаживается -> Check_INT3_2 > 0, ELSE Check_INT3_2 = 0

                            lea rcx, MAIN_KEY_STACK                 ; Массив с адресами, по которым лежат части ключа (по 8 байт)
                            add rcx, rbx

                            lea r8, MAIN_KEY_PART_0
                            movzx r9, Check_INT3_11                 ; IF процесс отлаживается -> Check_INT3_11 > 0, ELSE Check_INT3_11 = 0
                            add r8, r9
                            mov qword ptr[rcx], r8                  ; Адрес MAIN_KEY_PART_0

                            lea r8, MAIN_KEY_PART_1
                            movzx r10, Check_INT3_12                ; IF процесс отлаживается -> Check_INT3_12 > 0, ELSE Check_INT3_12 = 0
                            xor r8, r10
                            mov qword ptr[rcx + 8], r8              ; Адрес MAIN_KEY_PART_1

                            lea r8, MAIN_KEY_PART_2
                            movzx rax, Check_INT3_6                 ; IF процесс отлаживается -> Check_INT3_6 > 0, ELSE Check_INT3_6 = 0
                            add r8, rax
                            mov qword ptr[rcx + 16], r8             ; Адрес MAIN_KEY_PART_2

                            lea r8, MAIN_KEY_PART_3
                            movzx rdi, Check_INT3_10                ; IF процесс отлаживается -> Check_INT3_10 > 0, ELSE Check_INT3_10 = 0
                            add r8, rdi
                            mov qword ptr[rcx + 24], r8             ; Адрес MAIN_KEY_PART_3

                            lea r8, MAIN_KEY_PART_4
                            movzx rsi, Check_INT3_9                 ; IF процесс отлаживается -> Check_INT3_9 > 0, ELSE Check_INT3_9 = 0
                            sub r8, rsi
                            mov qword ptr[rcx + 32], r8             ; Адрес MAIN_KEY_PART_4

                            lea r8, MAIN_KEY_PART_5
                            movzx r12, Check_INT3_8                 ; IF процесс отлаживается -> Check_INT3_8 > 0, ELSE Check_INT3_8 = 0
                            add r8, r12
                            mov qword ptr[rcx + 40], r8             ; Адрес MAIN_KEY_PART_5

                            lea r8, MAIN_KEY_PART_6
                            movzx r11, Check_INT3_0                 ; IF процесс отлаживается -> Check_INT3_0 > 0, ELSE Check_INT3_0 = 0
                            xor r8, r11
                            mov qword ptr[rcx + 48], r8             ; Адрес MAIN_KEY_PART_6

                            lea r8, MAIN_KEY_PART_7
                            movzx rdx, Check_INT3_7                 ; IF процесс отлаживается -> Check_INT3_7 > 0, ELSE Check_INT3_7 = 0
                            sub r8, rdx
                            mov qword ptr[rcx + 56], r8             ; Адрес MAIN_KEY_PART_7

                            and r8, 1
                            bts r8, 0
                            rol r8, 3                               ; r8 Всегда равняется 8
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ РАСШИФРОВКА MAIN_KEY ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rax, SECOND_KEY                     ; Ключ для расшифрования MAIN_KEY
                        @@DECRYPT_MAIN_KEY:
                            mov r9, r8
                            dec r9
                            shl r9, 3                               ; r9 * 8
                            mov rbx, qword ptr[rcx + r9]            ; rbx равен значению по адресу MAIN_KEY_STACK + r9
                            mov rdx, qword ptr[rbx]                 ; Значение по адресу rbx, Это MAIN_KEY_PART_X
                            xor rdx, rax                            ; rdx = расшифрованный MAIN_KEY_PART_X
                            mov qword ptr[rbx], rdx
                            dec r8
                            jne @@DECRYPT_MAIN_KEY
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤



                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ РАСШИФРОВКА UNPACKER_STUB ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            mov rcx, pBase                          ; pBase
                            mov rdx, Section_Header                 ; Адрес Начала Заголовков Секции
                            add rdx, sz_Image_Section_Headers       ; Адрес следующего Заголовка секции
                            add rdx, 12                             ; Смещение указателя на поле Virtual Address
                            mov edx, dword ptr[rdx]                 ; RVA начала данных секции .text
                            shl rdx, 32                         
                            shr rdx, 32
                            add rcx, rdx                            ; VA начала данных секции .text
                            mov ebx, Sz_Decryptor_Stubloader        ; Размер заглушки декриптора
                            shl rbx, 32
                            shr rbx, 32
                            add rcx, rbx                       
                            mov rbx, rcx                            ; VA заглушки распаковщика
                            mov rdx, 1000h                     
                            mov r8, 40h                             ; PAGE_EXECUTE_READWRITE
                            lea r9, OldProtect
                            lea rax, MAIN_Label___DDD___
                            push rax
                            mov rax, VirtualProtect_address
                            push rax
                            db 0C3h
                        MAIN_Label___DDD___:
                            mov rax, rbx                            ; VA заглушки распаковщика
                            lea rsi, MAIN_KEY_STACK                 ; Адрес по которому храняться адреса, которые указывают на соответствующий MAIN_KEY_PART_X
                            xor r8, r8                                
                            xor r9, r9
                            mov r12, rax                            ; VA заглушки распаковщика
                            push 0D5Eh                              ; Размер заглушки распаковщика
                            @@DECRYPT_UNPACKER_STUB:
                                mov r10, qword ptr[rsi + r9]        ; r9 Увеличиваеться для получения следующего адреса, в массиве MAIN_KEY_STACK , r10 = адрес где лежит MAIN_KEY_PART_X
                                add r9, 8
                                and rdi, 0                          ; Счетчик селдующего байта MAIN_KEY_PART_X
                                cmp r9, 64                          ; Если r9 = 64 значит в r9 лежит последний адрес стека, по которому лежит значение MAIN_KEY_PART_7
                                jz NULL_R9
                                jmp @@XOR_DECRYPT_0
                                NULL_R9:
                                and r9, 0                   
                                @@XOR_DECRYPT_0:
            ; |--------------------------|------------------------------|--------------------------------------------------------------------------------------|
            ; | A = Байт ключа           |     byte ptr[r10 + rdi]      |   ; rdi Увеличивается для смещения указателя на другие байты ключа MAIN_KEY_PART_X   |
            ; | B = Защифрованный Байт   |     byte ptr[r12 + r8]       |   ; r8 Увеличивается для смещения указателя на другие зашифрованные байты            |
            ; |--------------------------|------------------------------|--------------------------------------------------------------------------------------|
                                        ; B xor A      <=>     (not((not(A & A)) & (not(B & B)))) & (not(A & B))
                                rdtsc
                                push rax                            ; проверка на отладку
                                jmp MAIN_Label___XXX___
                                MAIN_Label___YYY___:
                                mov rax, 28374123342h               ; Мусор
                                shr rax, 31                         ; Мусор
                                xor rax, rdx                        ; Мусор
                                xchg rax, rdx                       ; Мусор
                                xor rax, rdx                        ; Мусор
                                xchg rax, rdx                       ; Мусор
                                rdtsc                                                   
                                pop rdx
                                sub rax, rdx                         ; проверка на отладку
                                btr rax, 63
                                cmp rax, 30000h                     ; Если rax > 30000h То происходит отладка
                                mov ah, cl                          ; B = ah
                                and ah, ah                          ; B & B
                                lea rcx, MAIN_Label___ZZZ___
                                jmp rcx
                                jmp @@ret
                                OVERLAPPED_INSTRUCTION_2:
                                push 0D88A1111h                     ; опкод 0x8AD8 [mov bl, al]  A = bl
                                rdtsc
                                pop rdx
                                lea rcx, OVERLAPPED_INSTRUCTION_3
                                sub rax, rdx
                                inc rcx
                                btr rax, 63
                                inc rcx
                                cmp rax, 30000h                     ; Если rax > 30000h То происходит отладка
                                mov al, bl
                                add rcx, 6
                                jmp rcx                             ; Прыжок на OVERLAPPED_INSTRUCTION_3
                                MAIN_Label___XXX___:
                                mov al, byte ptr[r10 + rdi]         ; A = al = byte ptr[r10 + rdi]
                                lea rcx, OVERLAPPED_INSTRUCTION_2
                                add rcx, 3
                                jmp rcx                             ; Прыжок на OVERLAPPED_INSTRUCTION_2
                                OVERLAPPED_INSTRUCTION_3:
                                mov rax, 0C322567C488122CFh         ; опкод 0x22C3 [and al, bl]   A & A
                                xor rax, -1                         ; not (A & A)
                                push rax                            ; Сохраняем значение not (A & A) так как инструкция rdtsc изменит rax
                                movzx rcx, byte ptr[r12 + r8]       ; B = cl  = byte ptr[r12 + r8]
                                rdtsc
                                push rax                            ; проверка на отладку
                                jmp MAIN_Label___YYY___
                                MAIN_Label___ZZZ___:
                                xor ah, -1                          ; not (B & B)
                                mov cl, ah                          ; cl = ah
                                pop rax
                                shl rax, 56                         ; Так как мы клали в стек rax, а нам нужен только al, то обнуляем все кроме rax
                                rol rax, 8                          ; только al
                                and al, cl                          ; ((not (A & A)) & (not (B & B)))
                                xor al, -1                          ; not ((not (A & A)) & (not (B & B)))
                                push rax
                                movzx rax, byte ptr[r10 + rdi]      ; A = rax
                                movzx rcx, byte ptr[r12 + r8]       ; B = rcx
                                and rax, rcx                        ; A & B
                                xor rax, -1                         ; not (A & B)
                                pop rcx                             ; not ((not (A & A)) & (not (B & B)))
                                and rcx, rax                        ; (not ((not (A & A)) & (not (B & B)))) & not (A & B)
                                mov byte ptr[r12 + r8], cl
                                inc r8
                                inc rdi
                                pop r13                             ; Вытаскиваем из стека счетчик
                                dec r13
                                cmp r13, 0
                                jz @@Continue_4
                                cmp rdi, 8
                                push r13                            ; Закидываем счетчик обратно в стек
                                jne @@XOR_DECRYPT_0
                                jmp @@DECRYPT_UNPACKER_STUB
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤





                        @@Continue_4:
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ РАСШИФРОВКА УПАКОВАННЫХ ДАННЫХ ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                                mov rdx, Section_Header             ; Адрес Начала Заголовков Секции
                                add rdx, 12                         ; Смещение указателя на поле Virtual Address
                                and r9, 0
                                mov r9d , dword ptr[rdx]            ; RVA начала данных секции .rsrc
                                mov r10, pBase                      ; Адрес загрузки образа в память
                                add r10, r9                         ; rax = VA начало зашифрованно-запакованных данных
                                imul rcx, 0
                                mov ecx, Sz_Encryption_Data         ; Размер зашифрованно-заакованных данных
                                lea rsi, MAIN_KEY_STACK             ; Адрес по которому храняться адреса, которые указывают на соответствующий MAIN_KEY_PART_X
                                xor r8, r8
                                xor r9, r9
                                xor rdi, rdi
                                @@DECRYPT_ENCRYPTED_COMPRES_DATA:
                                    mov r11, qword ptr[rsi + rdi]   ; rdi += 8 для получения следующего адреса стека, в массиве MAIN_KEY_STACK       rdx = адрес где лежит MAIN_KEY_PART_X
                                    add rdi, 8
                                    and r9, 0                       ; Счетчик селдующего байта MAIN_KEY_PART_X
                                    cmp rdi, 64                     ; Если rdi = 64 значит в rdx лежит последний адрес стека, по которому лежит значение MAIN_KEY_PART_7
                                    jz RBX_NULL_1
                                    jmp @@XOR_DECRYPT_1
                                    RBX_NULL_1:
                                    or rdi, -1
                                    inc rdi
                                    @@XOR_DECRYPT_1:
            ; |--------------------------|------------------------------|--------------------------------------------------------------------------------------|
            ; | A = Защифрованный Байт   |     byte ptr[r10 + r8]       |   ; r8 Увеличивается для смещения указателя на другие зашифрованные байты            |
            ; | B = Байт ключа           |     byte ptr[r11 + r9]       |   ; r9 Увеличивается для смещения указателя на другие байты ключа MAIN_KEY_PART_X    |
            ; |--------------------------|------------------------------|--------------------------------------------------------------------------------------|
                                                ; A xor B   <=>   (not A & B) | (A & not B)
                                    movzx rax, byte ptr[r10 + r8]   ; A
                                    push rax                        ; Сохраняем значение    A = rax
                                    xor rax, -1                     ; not A
                                    movzx rdx, byte ptr[r11 + r9]   ; B
                                    push rdx                        ; Сохраняем значение    B = rdx
                                    not rdx                         ; not B
                                    pop rbx                         ; rbx = B
                                    and rax, rbx                    ; not A & B
                                    pop rbx                         ; rbx = A
                                    and rbx, rdx                    ; A & not B
                                    or rax, rbx                     ; (not A & B) | (A & not B)
                                    mov byte ptr[r10 + r8], al      
                                    inc r8
                                    inc r9
                                    dec rcx
                                    cmp rcx, 0
                                    jz @@Continue_5
                                    cmp r9, 8
                                    jne @@XOR_DECRYPT_1
                                    jmp @@DECRYPT_ENCRYPTED_COMPRES_DATA
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤


    
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤ ОЧИСТКА СТЕКА ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                        @@Continue_5:
                                mov rcx, rbp        
                                mov rdx, rsp
                                sub rcx, rdx        ; счетчик
                                mov r8, 0
                                @@stack_nulling:
                                    and byte ptr[rdx + r8], 0
                                    inc r8
                                    loop @@stack_nulling
                        ;¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                            
                            







;######################### ВЫХОД #########################
@@RET:
    jmp Exit
Main endp


TRASH_FUNC_ROL proc
    LOCAL var : qword 
    mov var, rax    
    mov rcx, 10
    @@trash_for:
        shl rax, 1
        rol rax, 2
        inc rax
        dec rcx
        jne @@trash_for
    mov rcx, var
    pop rax
    leave
    call rdx
TRASH_FUNC_ROL endp
Get_Encrypted_data_size proc
    LOCAL var : qword 
    sub rcx, sz_2_HASH_string
    mov r10, rcx
    sub r10, MAIN_KEY_LENGHT
    mov r9,  r10
    sub r9, sz_Hint_Bytes_array
    mov rax, r9
    sub rax, sz_HB_position_array
    mov rcx, rax
    sub rcx, sz_Prime_Mult
    mov rbx, rcx
    mov edx, dword ptr [rbx - sz_Enc_Data]
    ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
                    leave
                    pop rax
                    call rax
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
Get_Encrypted_data_size endp
TRASH_FUNC_HASH proc
    LOCAL var : qword
    mov var, rdx
    mov rdx, rcx
    or rcx, -1
    add rcx, 10     ; rcx = 9
    @@trash_for:
        inc rdx
        sub rdx, 5
        rol rdx, 3
        inc rdx
        ror rdx, 10
        dec rcx
        jne @@trash_for
        mov rax, rbp
        leave
        mov rax, qword ptr[rax - 8]
        call rax
TRASH_FUNC_HASH endp
TRASH_GET_CONST proc
    LOCAL var : qword
    rdtsc
    mov r11, rax
    mov var, 0
    xchg r8, var
    and r10, r8
    mov r8b, byte ptr[rcx + 12]           ; 1 Байт числа    
    mov ah,  byte ptr[rcx + 17]           ; 6 Байт числа    
    mov al,  byte ptr[rcx + 14]           ; 3 Байт числа    
    mov dh,  byte ptr[rcx + 19]           ; 8 Байт числа    
    mov r9b, byte ptr[rcx + 13]           ; 2 Байт числа    
    mov var, rbx
    mov bl,  byte ptr[rcx + 15]           ; 4 Байт числа    
    mov dl,  byte ptr[rcx + 16]           ; 5 Байт числа    
    mov bh,  byte ptr[rcx + 18]           ; 7 Байт числа    
    mov r10b, r8b
    shl r10, 8
    mov r10b, r9b
    shl r10, 8
    mov r10b, al
    shl r10, 8
    mov r10b, bl
    shl r10, 32
    bswap r10
    mov r8b, dl
    shl r8, 8
    mov dl, ah
    mov r8b, dl
    shl r8, 8
    mov dl, bh
    mov r8b, dl
    shl r8, 8
    mov dl, dh
    mov r8b, dl
    shl r8, 32
    bswap r8
    shl r8, 32
    xor r8, r10
    rdtsc
    sub rax, r11
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
                    mov rax, rbp
                    leave
                    mov rdx, qword ptr[rax - 8]
                    mov qword ptr[rax - 8], 0
                    call rdx
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
TRASH_GET_CONST endp
Get_ENC_HINT_BYTES proc
    LOCAL var : qword
    ;[0...7] i = {16...23}
    mov bl,  byte ptr[rcx + 19]           ; 5 Байт числа 
    mov r9b, byte ptr[rcx + 17]           ; 7 Байт числа  
    mov dl,  byte ptr[rcx + 20]           ; 4 Байт числа
    mov bh,  byte ptr[rcx + 22]           ; 2 Байт числа
    mov al,  byte ptr[rcx + 18]           ; 6 Байт числа 
    mov dh,  byte ptr[rcx + 23]           ; 1 Байт числа
    mov ah,  byte ptr[rcx + 21]           ; 3 Байт числа 
    mov r8b, byte ptr[rcx + 16]           ; 8 Байт числа
    mov r11b, r8b
    shl r11, 8
    mov r11b, r9b
    shl r11, 8
    mov r11b, al
    shl r11, 8
    mov r11b, bl
    shl r11, 8
    mov r11b, dl
    shl r11, 8
    mov bl, ah
    mov r11b, bl
    shl r11, 8
    mov bl, bh
    mov r11b, bl
    shl r11, 8
    mov bl, dh
    mov r11b, bl
    bswap r11
    ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
                    leave
                    pop r10
                    call r10
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
Get_ENC_HINT_BYTES endp
TRASH_GET_CONST_1 proc
    LOCAL var : qword
    mov bl,  byte ptr[rcx + 25]           ; 5 Байт числа 
    mov r9b, byte ptr[rcx + 23]           ; 7 Байт числа  
    mov dl,  byte ptr[rcx + 26]           ; 4 Байт числа
    mov bh,  byte ptr[rcx + 28]           ; 2 Байт числа
    mov al,  byte ptr[rcx + 24]           ; 6 Байт числа 
    mov dh,  byte ptr[rcx + 29]           ; 1 Байт числа
    mov ah,  byte ptr[rcx + 27]           ; 3 Байт числа 
    mov r8b, byte ptr[rcx + 22]           ; 8 Байт числа
    mov r11b, r8b
    shl r11, 8
    mov r11b, r9b
    shl r11, 8
    mov r11b, al
    shl r11, 8
    mov r11b, bl
    shl r11, 8
    mov r11b, dl
    shl r11, 8
    mov bl, ah
    mov r11b, bl
    shl r11, 8
    mov bl, bh
    mov r11b, bl
    shl r11, 8
    mov bl, dh
    mov r11b, bl
    bswap r11
    ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
                    leave
                    pop r10
                    call r10
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
TRASH_GET_CONST_1 endp
Get_Offset_Directory_Table proc
    LOCAL var : qword 
    mov var, rax
    or rcx, -1
    inc rcx
    xor rdx, rdx
    mov ecx, dword ptr[rbx + offset_to__e_lfanew__]
    add edx, ecx                            ; e_lfanew
    add edx, sz_PE_signature                ; PE_signature
    mov cx, word ptr[rbx + rcx + sz_PE_signature + offset_to__SizeOptionalHeader__]
    add edx, sz_Image_File_Header           ; sz_Image_File_Header
    add dx, cx                              ; SizeOptionalHeader
    mov rcx, sz_Image_Data_Directory
    imul r8, rcx, IMAGE_NUMBEROF_DIRECTORY_ENTRIES 
    add rbx, rdx                            ; Указатель на Заголовки Секций
    mov rdx, rbx
    sub rbx, r8                             ; pBase + e_lfanew + szFile_Header + szOptionalHeader - (sz_Image_Data_Directory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    mov r10, rbx
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
                    mov rax, rbp
                    leave
                    mov rcx, qword ptr [rax - 8]
                    call rcx
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
Get_Offset_Directory_Table endp
Get_ImageBase_from_PEB proc
   LOCAL var : qword
   mov rcx, qword ptr [rax + offset_to_LDR]
   mov rax, qword ptr [rcx + offset_to_InMemoryOrderModuleList]
   mov rcx, qword ptr [rax + offset_to_ModuleBase]
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
                     leave
                     pop rax
                     jmp rax
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
Get_ImageBase_from_PEB endp
Get_HINT_BYTE_POSITION proc
    LOCAL var : qword
    mov var, 0
    xchg r8, var
    and r10, r8
    ;[0...7] i = {8...15}
    mov r8b, byte ptr[rcx + 8 ]           ; 1 Байт числа
    mov ah,  byte ptr[rcx + 13]           ; 6 Байт числа  
    mov al,  byte ptr[rcx + 10]           ; 3 Байт числа
    mov var, rdx
    mov dh,  byte ptr[rcx + 15]           ; 8 Байт числа
    mov r9b, byte ptr[rcx + 9 ]           ; 2 Байт числа
    mov bl,  byte ptr[rcx + 11]           ; 4 Байт числа
    mov dl,  byte ptr[rcx + 12]           ; 5 Байт числа
    mov bh,  byte ptr[rcx + 14]           ; 7 Байт числа
    mov r10b, r8b
    shl r10, 8
    mov r10b, r9b
    shl r10, 8
    mov r10b, al
    shl r10, 8
    mov r10b, bl
    shl r10, 32
    bswap r10
    mov r8b, dl
    shl r8, 8
    mov dl, ah
    mov r8b, dl
    shl r8, 8
    mov dl, bh
    mov r8b, dl
    shl r8, 8
    mov dl, dh
    mov r8b, dl
    shl r8, 32
    bswap r8
    shl r8, 32
    xor r8, r10
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
                    mov rax, rbp
                    leave
                    mov rdx, qword ptr[rax - 8]
                    call rdx
   ;%%%%%%%%%%%%%%%%% RET %%%%%%%%%%%%%%%%%
Get_HINT_BYTE_POSITION endp
TRASH_DIVISION proc
    LOCAL index                  : byte
    mov index, dl                ; 2 ** bl
    mov r8, 1238h
    mov bl, 0
    MN_JMP:
    cmp bl, 0
    jz jmps_0
    cmp bl, 1
    jz jmps_1
    cmp bl, 2
    jz jmps_2
    cmp bl, 3
    jz jmps_3
    cmp bl, 4
    jz jmps_4
    cmp bl, 5
    jz jmps_5
    cmp bl, 6
    jz jmps_6
    cmp bl, 7
    jz jmps_7
    cmp bl, 8
    jz jmps_8
    cmp bl, 9
    jz jmps_9
    mov rdx, 0
    movzx rbx, index
    mov rax, 1
    mov r9, 2
    POW:                ; pow (2, b)
        mul r9
        dec rbx
        jne POW
    xchg rax, rcx
    div rcx
    xchg rax, rdx
    jmp @@ret
    jmps_0:
    rol rcx, 3
    ror rcx, 34
    inc bl
    stc
    jnc jmps_9
    jmp MN_JMP
    jmps_1:
    rol rcx, 5
    ror rcx, 11
    inc bl
    cmp r8, 4853h
    jz jmps_8
    jmp MN_JMP
    jmps_2:
    rol rcx, 7
    ror rcx, 8
    inc bl
    push r8
    pop r9
    sub r9, r9
    jnz jmps_7
    jmp MN_JMP
    jmps_3:
    rol rcx, 21
    ror rcx, 13
    inc bl
    jmp MN_JMP
    jmps_4:
    rol rcx, 11
    ror rcx, 2
    inc bl
    jmp MN_JMP
    jmps_5:
    rol rcx, 15
    ror rcx, 4
    inc bl
    jmp MN_JMP
    jmps_6:
    rol rcx, 19
    ror rcx, 7
    inc bl
    jmp MN_JMP
    jmps_7:
    rol rcx, 31
    ror rcx, 18
    inc bl
    push r8
    pop r9
    sub r9, r9
    jnz jmps_2
    jmp MN_JMP
    jmps_8:
    rol rcx, 4
    ror rcx, 17
    inc bl
    cmp r8, 443h
    jz jmps_1
    jmp MN_JMP
    jmps_9:
    rol rcx, 10
    ror rcx, 12
    inc bl
    stc
    jnc jmps_0
    jmp MN_JMP
@@ret:
    leave
    mov r8, qword ptr[rsp]
    movzx r8, byte ptr[r8]
    cmp r8, 0CCh
    db 0C3h     ; ret
TRASH_DIVISION endp
end