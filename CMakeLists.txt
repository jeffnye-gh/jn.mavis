cmake_minimum_required(VERSION 3.15)
project(Mavis)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optionally disable Boost JSON if using nlohmann
option(USE_NLOHMANN_JSON "Use nlohmann::json instead of boost::json" ON)

find_package(Boost 1.74.0 REQUIRED COMPONENTS program_options)

if(USE_NLOHMANN_JSON)
  add_compile_definitions(USE_NLOHMANN_JSON)
endif()

if(NOT USE_NLOHMANN_JSON)
    message(STATUS "Using BOOST ${Boost_VERSION_STRING}")
    set(USE_BOOST_JSON TRUE)
else()
# 1.74 does not supply json, 1st is 1.75
# original cmake file didnt use find_package for boost::json, all
# sub-cmakelists add the bare boost_json lib target.
#    find_package(Boost 1.75.0 REQUIRED COMPONENTS json)
    set(USE_BOOST_JSON FALSE)
endif()

include_directories(.)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/elfio ${Boost_INCLUDE_DIRS})

add_library(mavis
  impl/ExtractorRegistry.cpp
  impl/FormRegistry.cpp
  impl/forms/CommonForms.cpp
  impl/forms/CompressedForms.cpp
  impl/forms/VectorForms.cpp
)

if(USE_NLOHMANN_JSON)
    message(STATUS "Using nlohmann::json")
    target_compile_definitions(mavis PRIVATE USE_NLOHMANN_JSON)
else()
    message(STATUS "Using Boost::json")
# see above, 1.74 vs 1.75, so using bare boost_json
#    find_package(Boost 1.74.0 REQUIRED COMPONENTS json)
#    target_link_libraries(mavis PRIVATE Boost::json)
    target_link_libraries(mavis PRIVATE boost_json)
endif()

# These may still use Boost program_options (leave as is)
add_subdirectory(example EXCLUDE_FROM_ALL)
add_subdirectory(test EXCLUDE_FROM_ALL)

