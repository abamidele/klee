# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

#cmake_minimum_required(VERSION 3.14.5)

# remill
function(getTargetTree output_variable)
  if(${ARGC} LESS 1)
    message(FATAL_ERROR "Usage: getTargetTree output_var target1 target2 ...")
  endif()
  
  foreach(target ${ARGN})
    list(APPEND queue "${target}")
  endforeach()

  while(true)
    # Update the queue
    unset(new_queue)
    
    foreach(target ${queue})
      list(APPEND visited_dependencies "${target}")
      
      if (NOT TARGET "${target}")
        continue()
      endif()
      
      # Always reset to empty value
      set(target_link_libs "target_link_libs-NOTFOUND")
      set(target_interface_link_libs "target_interface_link_libs-NOTFOUND")

      # Skip utility targets
      get_target_property(target_type "${target}" TYPE)
      if("${target_type}" STREQUAL "UTILITY")
        continue()
      endif()

      # We can only get LINK_LIBRARIES from normal targets
      if(NOT "${target_type}" STREQUAL "INTERFACE_LIBRARY")
        get_target_property(target_link_libs "${target}" LINK_LIBRARIES)
      else()
        set(target_link_libs "target_link_libs-NOTFOUND")
      endif()

      # INTERFACE_LINK_LIBRARIES are potentially always present
      get_target_property(target_interface_link_libs "${target}" INTERFACE_LINK_LIBRARIES)

      # Collect the results
      unset(new_queue_candidates)

      if(NOT "${target_link_libs}" STREQUAL "target_link_libs-NOTFOUND")
        list(APPEND new_queue_candidates ${target_link_libs})
      endif()

      if(NOT "${target_interface_link_libs}" STREQUAL "target_interface_link_libs-NOTFOUND")
        list(APPEND new_queue_candidates ${target_interface_link_libs})
      endif()

      foreach(queue_candidate ${new_queue_candidates})
        list(FIND visited_dependencies "${queue_candidate}" visited)
        if(visited EQUAL -1)
          list(APPEND new_queue "${queue_candidate}")
        endif()
      endforeach()
    endforeach()

    list(LENGTH new_queue new_queue_size)
    if(${new_queue_size} EQUAL 0)
      break()
    endif()

    set(queue ${new_queue})
  endwhile()

  set("${output_variable}" ${visited_dependencies} PARENT_SCOPE)
endfunction()

function(getPublicIncludeFolders output_variable)
  if(${ARGC} LESS 1)
    message(FATAL_ERROR "Usage: getPublicIncludeFolders output_var target1 target2 ...")
  endif()
  
  foreach(target ${ARGN})
    if (NOT TARGET "${target}")
      continue()
    endif()
    
    get_target_property(include_dir_list "${target}" INTERFACE_INCLUDE_DIRECTORIES)
    if(NOT "${include_dir_list}" STREQUAL "include_dir_list-NOTFOUND")
      list(APPEND collected_include_dirs "${include_dir_list}")
    endif()
  endforeach()

  set("${output_variable}" ${collected_include_dirs} PARENT_SCOPE)
endfunction()

function(klee_native_PythonMain)
  find_package(PythonInterp 3.7 REQUIRED)
  find_package(PythonLibs 3.7 REQUIRED)
  
  add_library(python_settings INTERFACE)
  target_include_directories(python_settings INTERFACE ${PYTHON_INCLUDE_DIRS} )
  
  set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in")
  set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
  
  set(INIT_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/klee_native/__init__.py.in")
  set(INIT_PY    "${CMAKE_CURRENT_BINARY_DIR}/klee_native/__init__.py")
  
  set(OUTPUT     "${CMAKE_CURRENT_BINARY_DIR}/timestamp")

  if (NOT TARGET remill)
      if("${PLATFORM_NAME}" STREQUAL "windows")
          set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
      endif()
      find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})
  endif()
  
  add_library(klee_native_api STATIC
    cxx_python/CxxPython.cpp
    cxx_python/Process.cpp
    cxx_python/Module.cpp
    )
    
  #SET(CMAKE_C_COMPILER /usr/bin/clang )
  #SET(CMAKE_CXX_COMPILER /usr/bin/clang++ )
  

  set_target_properties(klee_native_api PROPERTIES
    CXX_STANDARD 17
    CXX_EXTENSIONS ON
    )

  list(APPEND PROJECT_INCLUDEDIRECTORIES "${CMAKE_SOURCE_DIR}")
  target_include_directories(klee_native_api SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
  
  target_link_libraries(klee_native_api PUBLIC
    python_settings
    remill
    ${PROJECT_NAME}
  )
  
  getTargetTree(DEPENDENT_LIBRARIES klee_native_api)
  getPublicIncludeFolders(INCLUDE_DIRS ${DEPENDENT_LIBRARIES})
  
  # Create a list of generator expressions that will find us the absolute paths
  # of all dependent libraries for setup.py to link against.
  
  foreach(lib_target ${DEPENDENT_LIBRARIES})
    if (NOT TARGET ${lib_target})
      continue()
    endif()
    get_target_property(target_type "${lib_target}" TYPE)
    if("${target_type}" STREQUAL "STATIC_LIBRARY")
      list(APPEND LIBRARY_PATHS "\$<TARGET_FILE:${lib_target}>")
    endif()
  endforeach() 
  
  configure_file("${SETUP_PY_IN}" "${SETUP_PY}.gen" @ONLY)
  file(GENERATE OUTPUT "${SETUP_PY}" INPUT "${SETUP_PY}.gen")
  configure_file("${INIT_PY_IN}" "${INIT_PY}" @ONLY)
  
  
  add_custom_command(
    OUTPUT "${OUTPUT}"
    COMMAND "${PYTHON_EXECUTABLE}" "${SETUP_PY}" build --force
    COMMAND "${CMAKE_COMMAND}" -E touch "${OUTPUT}"
    COMMENT "Building KLEE-NATIVE Python API"
    DEPENDS klee_native_api
     WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    
  add_custom_target(build_python_ext ALL DEPENDS "${OUTPUT}")
  
  install(CODE "execute_process(COMMAND \"${PYTHON_EXECUTABLE}\" \"${SETUP_PY}\" install WORKING_DIRECTORY \"${CMAKE_CURRENT_BINARY_DIR}\")")
  
endfunction()
klee_native_PythonMain()
