project(SIMPLE_EXAMPLE)

add_executable(SimpleExample
    main.cpp
    )

if(USE_NLOHMANN_JSON)
  target_link_libraries(SimpleExample mavis)
else()
  target_link_libraries(SimpleExample mavis boost_json)
endif()

