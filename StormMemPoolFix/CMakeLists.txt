cmake_minimum_required(VERSION 3.20)
project(StormBreaker LANGUAGES C CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "StormBreaker supports only Win32/x86 Warcraft III")
endif()

set(STORMBREAKER_LIBRARY_SOURCES
  Base/LeakProfiler.cpp
  Base/Logger.cpp
  Base/MemroySafety.cpp
  Base/Telemetry.cpp
  Game/PathCapUnlock.cpp
  Storm/MemoryPool.cpp
  Storm/MimallocBackend.cpp
  Storm/StormHook.cpp
  Storm/StormOffsets.cpp
  Storm/StormVersionProfile.cpp
  Storm/TlsfBackend.cpp
  Storm/tlsf.c
  Dependencies/mimalloc-dev/src/static.c
  dllmain.cpp
)

function(add_stormbreaker_library target_name output_name default_backend lock_backend)
  add_library(${target_name} SHARED ${STORMBREAKER_LIBRARY_SOURCES})
  target_compile_features(${target_name} PRIVATE cxx_std_20)
  set_property(TARGET ${target_name} PROPERTY C_STANDARD 17)
  set_property(TARGET ${target_name} PROPERTY C_STANDARD_REQUIRED ON)
  target_compile_definitions(${target_name} PRIVATE
    WIN32
    _WINDOWS
    _USRDLL
    NDEBUG
    STORMMEMPOOLFIX_EXPORTS
    _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR
    MI_STATIC_LIB
    STORMBREAKER_PINNED_RUNTIME=1
    STORMBREAKER_LARGE_ONLY=1
    STORMBREAKER_DEFAULT_BACKEND=${default_backend}
    STORMBREAKER_LOCK_MEMORY_BACKEND=${lock_backend}
  )
  target_include_directories(${target_name} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Detours/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/mimalloc-dev/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/spdlog/include
  )
  target_link_libraries(${target_name} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Detours/lib.X86/detours.lib
    advapi32
    bcrypt
    psapi
    shell32
    user32
  )
  if(MSVC)
    target_compile_options(${target_name} PRIVATE /utf-8 /W3)
    target_link_options(${target_name} PRIVATE /LARGEADDRESSAWARE)
  endif()
  set_target_properties(${target_name} PROPERTIES
    OUTPUT_NAME ${output_name}
    PREFIX ""
    SUFFIX ".asi"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Build
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Build
  )
  foreach(configuration Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER ${configuration} configuration_upper)
    set_target_properties(${target_name} PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY_${configuration_upper} ${CMAKE_CURRENT_SOURCE_DIR}/Build
      LIBRARY_OUTPUT_DIRECTORY_${configuration_upper} ${CMAKE_CURRENT_SOURCE_DIR}/Build
    )
  endforeach()
endfunction()

# Production build on this branch is deliberately locked to large-block TLSF.
add_stormbreaker_library(StormBreaker StormBreaker 0 1)

option(STORMBREAKER_BUILD_VARIANTS
  "Build backend-locked TLSF and mimalloc ASIs for manual comparison" OFF)
if(STORMBREAKER_BUILD_VARIANTS)
  add_stormbreaker_library(StormBreakerTLSF StormBreaker-TLSF 0 1)
  add_stormbreaker_library(StormBreakerMimalloc StormBreaker-mimalloc 1 1)
  add_stormbreaker_library(StormBreakerHybrid StormBreaker-hybrid 2 1)
endif()

option(STORMBREAKER_BUILD_TESTS "Build the Win32 allocator/profiler tests" OFF)
if(STORMBREAKER_BUILD_TESTS)
  enable_testing()
  add_executable(StormBreakerTests
    tests/StormBreakerTests.cpp
    Base/LeakProfiler.cpp
    Base/Logger.cpp
    Base/MemroySafety.cpp
    Storm/MemoryPool.cpp
    Storm/MimallocBackend.cpp
    Storm/StormHeapRegistry.cpp
    Storm/StormHook.cpp
    Storm/StormOffsets.cpp
    Storm/StormTakeover.cpp
    Storm/StormVersionProfile.cpp
    Storm/TlsfBackend.cpp
    Storm/tlsf.c
    Dependencies/mimalloc-dev/src/static.c
  )
  add_executable(StormBreakerAllocatorBenchmark
    tests/StormBreakerAllocatorBenchmark.cpp
    tests/SegregatedArenaBenchmarkAllocator.cpp
    Base/LeakProfiler.cpp
    Base/Logger.cpp
    Base/MemroySafety.cpp
    Storm/MemoryPool.cpp
    Storm/MimallocBackend.cpp
    Storm/StormHeapRegistry.cpp
    Storm/StormHook.cpp
    Storm/StormOffsets.cpp
    Storm/StormTakeover.cpp
    Storm/StormVersionProfile.cpp
    Storm/TlsfBackend.cpp
    Storm/tlsf.c
    Dependencies/mimalloc-dev/src/static.c
    Dependencies/rpmalloc-1.4.5/rpmalloc/rpmalloc.c
  )
  add_executable(SegregatedArenaBenchmarkAllocatorTests
    tests/SegregatedArenaBenchmarkAllocatorTests.cpp
    tests/SegregatedArenaBenchmarkAllocator.cpp
  )
  target_compile_features(StormBreakerTests PRIVATE cxx_std_20)
  target_compile_features(StormBreakerAllocatorBenchmark PRIVATE cxx_std_20)
  target_compile_features(
    SegregatedArenaBenchmarkAllocatorTests PRIVATE cxx_std_20)
  set_property(TARGET StormBreakerTests PROPERTY C_STANDARD 17)
  set_property(TARGET StormBreakerTests PROPERTY C_STANDARD_REQUIRED ON)
  set_property(TARGET StormBreakerAllocatorBenchmark PROPERTY C_STANDARD 17)
  set_property(TARGET StormBreakerAllocatorBenchmark PROPERTY C_STANDARD_REQUIRED ON)
  set(STORMBREAKER_TEST_DEFINITIONS
    WIN32
    _WINDOWS
    NDEBUG
    _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR
    MI_STATIC_LIB
    STORMBREAKER_TESTING
    STORMBREAKER_PINNED_RUNTIME=0
    STORMBREAKER_LARGE_ONLY=0
    STORMBREAKER_DEFAULT_BACKEND=0
    STORMBREAKER_LOCK_MEMORY_BACKEND=0
  )
  target_compile_definitions(StormBreakerTests PRIVATE
    ${STORMBREAKER_TEST_DEFINITIONS})
  target_compile_definitions(StormBreakerAllocatorBenchmark PRIVATE
    ${STORMBREAKER_TEST_DEFINITIONS}
    STORMBREAKER_BENCHMARK_PINNED_HOTPATH=1
    RPMALLOC_CONFIGURABLE=1
    RPMALLOC_FIRST_CLASS_HEAPS=1
    ENABLE_VALIDATE_ARGS=1
    ENABLE_OVERRIDE=0
    ENABLE_PRELOAD=0)
  target_compile_definitions(SegregatedArenaBenchmarkAllocatorTests PRIVATE
    ${STORMBREAKER_TEST_DEFINITIONS})
  set(STORMBREAKER_TEST_INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Detours/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/mimalloc-dev/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/rpmalloc-1.4.5/rpmalloc
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/spdlog/include
  )
  target_include_directories(StormBreakerTests PRIVATE
    ${STORMBREAKER_TEST_INCLUDE_DIRECTORIES})
  target_include_directories(StormBreakerAllocatorBenchmark PRIVATE
    ${STORMBREAKER_TEST_INCLUDE_DIRECTORIES})
  target_include_directories(SegregatedArenaBenchmarkAllocatorTests PRIVATE
    ${STORMBREAKER_TEST_INCLUDE_DIRECTORIES})
  set(STORMBREAKER_TEST_LIBRARIES
    ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Detours/lib.X86/detours.lib
    advapi32
    bcrypt
    psapi
    shell32
    user32
  )
  target_link_libraries(StormBreakerTests PRIVATE
    ${STORMBREAKER_TEST_LIBRARIES})
  target_link_libraries(StormBreakerAllocatorBenchmark PRIVATE
    ${STORMBREAKER_TEST_LIBRARIES})
  if(MSVC)
    target_compile_options(StormBreakerTests PRIVATE /utf-8 /W4)
    target_compile_options(StormBreakerAllocatorBenchmark PRIVATE /utf-8 /W4)
    target_compile_options(
      SegregatedArenaBenchmarkAllocatorTests PRIVATE /utf-8 /W4)
  endif()
  add_test(NAME StormBreakerTests COMMAND StormBreakerTests)
  add_test(NAME SegregatedArenaBenchmarkAllocatorTests
    COMMAND SegregatedArenaBenchmarkAllocatorTests)
endif()
