cmake_minimum_required(VERSION 3.24)

project(MAAUnitTests LANGUAGES CXX)

include(CTest)
include(FetchContent)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CATCH_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
set(CATCH_INSTALL_EXTRAS ON CACHE BOOL "" FORCE)
set(CATCH_DEVELOPMENT_BUILD OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.8.1
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(Catch2)

if(MSVC)
    # Catch2 enables multi-process compilation; serialize access to its shared PDB.
    target_compile_options(Catch2 PRIVATE /FS)
    target_compile_options(Catch2WithMain PRIVATE /FS)
endif()

include(Catch)

add_executable(maa-algorithm-test
    MaaCore/AlgorithmTest.cpp
)

target_compile_features(maa-algorithm-test PRIVATE cxx_std_20)
target_link_libraries(maa-algorithm-test PRIVATE Catch2::Catch2WithMain)
target_include_directories(maa-algorithm-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/MaaCore)

catch_discover_tests(maa-algorithm-test TEST_PREFIX "algorithm::")

set(BLACKFLOW_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src/MaaCore/Task/Roguelike/BlackFlow)

add_executable(maa-blackflow-planner-test
    MaaCore/BlackFlowPlannerTest.cpp
    ${BLACKFLOW_SOURCE_DIR}/BlackFlowCompactStateSpace.cpp
    ${BLACKFLOW_SOURCE_DIR}/BlackFlowModel.cpp
    ${BLACKFLOW_SOURCE_DIR}/BlackFlowPolicy.cpp
    ${BLACKFLOW_SOURCE_DIR}/BlackFlowSafetyGoal.cpp
    ${BLACKFLOW_SOURCE_DIR}/BlackFlowSafetyPlanner.cpp
    ${BLACKFLOW_SOURCE_DIR}/BlackFlowSafetyValue.cpp
    ${BLACKFLOW_SOURCE_DIR}/BlackFlowStateSpace.cpp
)

target_compile_features(maa-blackflow-planner-test PRIVATE cxx_std_20)
target_link_libraries(maa-blackflow-planner-test PRIVATE Catch2::Catch2WithMain)
target_include_directories(maa-blackflow-planner-test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/MaaCore
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/MaaUtils/include
)
if(MSVC)
    target_compile_options(maa-blackflow-planner-test PRIVATE /utf-8)
endif()

catch_discover_tests(maa-blackflow-planner-test TEST_PREFIX "blackflow::")
