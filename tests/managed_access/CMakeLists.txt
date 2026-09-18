cmake_minimum_required(VERSION 3.20)

project(apollo_managed_access_tests LANGUAGES CXX)

enable_testing()

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.11 REQUIRED)
find_package(Threads REQUIRED)

set(APOLLO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(managed_access_tests
  managed_access_tests.cpp
  "${APOLLO_ROOT}/src/managed_access.cpp"
)

target_compile_features(managed_access_tests PRIVATE cxx_std_23)
target_compile_options(managed_access_tests PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall>
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wextra>
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wpedantic>
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Werror>
)
target_include_directories(managed_access_tests PRIVATE "${APOLLO_ROOT}/src")
target_link_libraries(managed_access_tests PRIVATE
  OpenSSL::Crypto
  Threads::Threads
  nlohmann_json::nlohmann_json
)

add_test(NAME managed_access_policy COMMAND managed_access_tests)
