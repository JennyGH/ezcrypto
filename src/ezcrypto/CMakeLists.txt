project(ezcrypto)

# 递归地查找头文件，并存放到 INCLUDE_FILES 变量中
file(GLOB_RECURSE INCLUDE_FILES
    ${PROJECT_SOURCE_DIR}/*.h
    ${PROJECT_SOURCE_DIR}/*.hpp
)

# 递归地查找 .c/.cpp 文件，并存放到 SOURCE_FILES 变量中
file(GLOB_RECURSE SOURCE_FILES 
    ${PROJECT_SOURCE_DIR}/*.c
    ${PROJECT_SOURCE_DIR}/*.cpp
)
    
# 将文件分组
source_group("Header Files" FILES "${INCLUDE_FILES}")
source_group("Source Files" FILES "${SOURCE_FILES}")

# 指定当前子工程是编译为静态库文件
add_library(
    ${PROJECT_NAME}
    STATIC
    ${INCLUDE_FILES}
    ${SOURCE_FILES}
)

# 如果有找到 cppcheck 可执行程序，则在编译前先进行静态代码检查
if(CMAKE_CXX_CPPCHECK)
    add_custom_command(
        TARGET ${PROJECT_NAME}
        PRE_BUILD
        command ${CPPCHECK_COMMAND} ${PROJECT_SOURCE_DIR}
    )
endif() # endif `cppcheck` was found.

# 配置预编译头:
target_precompile_headers(
  ${PROJECT_NAME}
  PRIVATE
  "$<$<COMPILE_LANGUAGE:CXX>:${PROJECT_SOURCE_DIR}/pch.h>"
)

# 设置在 Linux 中编译时的版本信息
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})