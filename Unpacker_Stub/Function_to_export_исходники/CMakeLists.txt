cmake_minimum_required(VERSION 3.12)
project(Function_on_export)


# Linker - Advanced (Entry Point - func()), Изменение точки входа, дабы CRT не добавлялась
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE /ENTRY:GetProcAddress_HASH_VERSION") 
add_executable(Function_on_export ./Function_to_export.cpp)
# C/C++ - Optimization оптимизация по размеру (Optimization - Minimize size (/O1))
target_compile_options(Function_on_export PRIVATE "/O1")
# C/C++ Favor Size Or Speed - Favor Small code (/Os)  
target_compile_options(Function_on_export PRIVATE "/Os")
# Удаление имени библиотеки по умолчанию из .obj файла.
target_compile_options(Function_on_export PRIVATE "/Zl")  
# Linker - Manifest File отключим генерацию манифеста (Generate Manifest - No (/MANIFEST:NO)).
set_target_properties(Function_on_export PROPERTIES LINK_FLAGS "/MANIFEST:NO")
# C/C++ - Optimization - Whole Program Optimization - Yes
target_compile_options(Function_on_export PRIVATE "/GL-")
# C/C++ - Code Generation - Security Check - No (отключение проверки буферов)
target_compile_options(Function_on_export PRIVATE "/GS-")
