CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}/sysrepo/plugins/" CACHE PATH "Sysrepo plugins directory.")

PROJECT(sysrepo-plugin-module-versions)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
#set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
#set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG")

# Determine DEIP version to simulate
if (NOT YANG_SET)
    set(YANG_SET "ipsolutionref_1_6_0")
endif()
string(TOLOWER "${YANG_SET}" YANG_SET_LOWER)

#set(VALID_YANG_SET_LIST ipsolutionref_1_6_0 ipsolutionref_2_1_0)
#
#if (NOT YANG_SET_LOWER IN_LIST VALID_YANG_SET_LIST)
#    message(FATAL_ERROR "Illegal value of YANG_SET.")
#endif()

if (NOT ((YANG_SET_LOWER STREQUAL "ipsolutionref_1_6_0") OR
         (YANG_SET_LOWER STREQUAL "ipsolutionref_2_1_0")))
    message(FATAL_ERROR "Illegal value of YANG_SET.")
endif()


if (YANG_SET_LOWER STREQUAL ipsolutionref_1_6_0)
    set(SOURCES
	src/module-versions-plugin_1-6-0.c)
else()
    set(SOURCES
	src/module-versions-plugin_2-1-0.c)
endif()

if(CMAKE_BUILD_TYPE MATCHES "debug")
  add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
  target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE DEBUG=1)
  install(TARGETS ${CMAKE_PROJECT_NAME}
	  DESTINATION lib/sysrepo/plugins)
else()
  add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
  install(TARGETS ${CMAKE_PROJECT_NAME} LIBRARY
	  DESTINATION lib/sysrepo/plugins)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME} PREFIX "")

find_package(PkgConfig REQUIRED)

include_directories(${SYSREPO_INCLUDE_DIRS})

find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

# find programs
if (NOT SYSREPOCTL_EXECUTABLE)
    find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
endif()
if (NOT SYSREPOCTL_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
endif()

if (NOT SYSREPOCFG_EXECUTABLE)
    find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
endif()
if (NOT SYSREPOCFG_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
endif()

# Command line options to be passed to `sysrepoctl` when working with modules
# which should only be accessible by an administrator
if (NOT SYSREPOCTL_ROOT_PERMS)
    set(SYSREPOCTL_ROOT_PERMS "-p 600")
endif()

## get sysrepo plugins directory
if (NOT SRPD_PLUGINS_PATH)
    if (PKG_CONFIG_FOUND)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=SRPD_PLUGINS_PATH" "sysrepo" OUTPUT_VARIABLE SRPD_PLUGINS_PATH)
        string(STRIP ${SRPD_PLUGINS_PATH} SRPD_PLUGINS_PATH)
    endif()
endif()
if (NOT SRPD_PLUGINS_PATH)
    message(FATAL_ERROR "Cannot get sysrepo plugins directory due to missing pkg-config, set SRPD_PLUGINS_PATH manually.")
endif()

option(MODEL_INSTALL "Enable yang model installation" ON)
if (MODEL_INSTALL)
    install(CODE "
        message(STATUS \"Installing sysrepo modules...\")
        execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/model-install.sh ${SYSREPOCTL_EXECUTABLE} \"${SYSREPOCTL_ROOT_PERMS}\" ${YANG_SET_LOWER} RESULT_VARIABLE RET ERROR_VARIABLE ERR)
        if(\${RET})
             message(FATAL_ERROR \"sysrepoctl failed: \${ERR}\")
        endif()
    ")
endif()
