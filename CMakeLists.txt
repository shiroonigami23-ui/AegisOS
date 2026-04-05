cmake_minimum_required(VERSION 3.20)
project(AegisOS C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(kernel_sim STATIC
  kernel/src/kernel_main.c
)
target_include_directories(kernel_sim PUBLIC kernel/include)
target_compile_options(kernel_sim PRIVATE -Wall -Wextra -Wpedantic)

add_library(aegis_capability STATIC
  userland/security/capability.c
)
target_include_directories(aegis_capability PUBLIC userland/include)
target_compile_options(aegis_capability PRIVATE -Wall -Wextra -Wpedantic)

add_executable(kernel_sim_test tests/kernel_sim_test.c)
target_link_libraries(kernel_sim_test PRIVATE kernel_sim)

add_executable(capability_test tests/capability_test.c)
target_link_libraries(capability_test PRIVATE aegis_capability)

enable_testing()
add_test(NAME kernel-sim-test COMMAND kernel_sim_test)
add_test(NAME capability-test COMMAND capability_test)
