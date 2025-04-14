cmake_minimum_required(VERSION 3.22)
project(challenge)

add_executable(challenge challenge.cpp)

target_compile_options(challenge PUBLIC
    "-O0"
    "-g"
    "-fno-stack-protector"
    "-Wall"
)
