cmake_minimum_required(VERSION 3.12)
project(Function_on_export)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE /ENTRY:Factorize") # Linker - Advanced ставим точку входа (Entry Point - func())

add_executable(Function_on_export ./Function_on_export.cpp)
target_compile_options(Function_on_export PRIVATE "/O1")  # C/C++ - Optimization выбираем оптимизацию по размеру (Optimization - Minimize size (/O1))
target_compile_options(Function_on_export PRIVATE "/Os")  # Favor Size Or Speed - Favor Small code (/Os)
target_compile_options(Function_on_export PRIVATE "/Zl")  
set_target_properties(Function_on_export PROPERTIES LINK_FLAGS "/MANIFEST:NO") # Linker - Manifest File отключим генерацию манифеста (Generate Manifest - No (/MANIFEST:NO)).
target_compile_options(Function_on_export PRIVATE "/Oi-") # C/C++ - Optimization - Enable Intrinsic Functions - No)
target_compile_options(Function_on_export PRIVATE "/GL-") # (C/C++ - Optimization - Whole Program Optimization - No)
target_compile_options(Function_on_export PRIVATE "/GS-")       # отключение проверки буферов


