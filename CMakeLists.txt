cmake_minimum_required(VERSION 3.20)
project(AegisOS C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(kernel_sim STATIC
  kernel/src/kernel_main.c
  kernel/src/process_checkpoint.c
)
target_include_directories(kernel_sim PUBLIC kernel/include)
target_compile_options(kernel_sim PRIVATE -Wall -Wextra -Wpedantic)

add_library(aegis_capability STATIC
  userland/security/capability.c
)
target_include_directories(aegis_capability PUBLIC userland/include)
target_compile_options(aegis_capability PRIVATE -Wall -Wextra -Wpedantic)

add_library(aegis_sandbox STATIC
  userland/security/sandbox_policy.c
)
target_include_directories(aegis_sandbox PUBLIC userland/include)
target_compile_options(aegis_sandbox PRIVATE -Wall -Wextra -Wpedantic)

add_library(aegis_sandbox_engine STATIC
  userland/security/sandbox_engine.c
)
target_include_directories(aegis_sandbox_engine PUBLIC userland/include)
target_compile_options(aegis_sandbox_engine PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(aegis_sandbox_engine PUBLIC aegis_capability aegis_sandbox)

add_executable(kernel_sim_test tests/kernel_sim_test.c)
target_link_libraries(kernel_sim_test PRIVATE kernel_sim)

add_executable(capability_test tests/capability_test.c)
target_link_libraries(capability_test PRIVATE aegis_capability)

add_executable(sandbox_policy_test tests/sandbox_policy_test.c)
target_link_libraries(sandbox_policy_test PRIVATE aegis_sandbox)

add_executable(sandbox_engine_test tests/sandbox_engine_test.c)
target_link_libraries(sandbox_engine_test PRIVATE aegis_sandbox_engine)

add_executable(sandbox_escape_regression_test tests/sandbox_escape_regression_test.c)
target_link_libraries(sandbox_escape_regression_test PRIVATE aegis_sandbox_engine)

enable_testing()
add_test(NAME kernel-sim-test COMMAND kernel_sim_test)
add_test(NAME capability-test COMMAND capability_test)
add_test(NAME sandbox-policy-test COMMAND sandbox_policy_test)
add_test(NAME sandbox-engine-test COMMAND sandbox_engine_test)
add_test(NAME sandbox-escape-regression-test COMMAND sandbox_escape_regression_test)
