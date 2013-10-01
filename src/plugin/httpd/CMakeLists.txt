set(lua_sources)
lua_source(lua_sources lua/box_httpd.lua)
lua_source(lua_sources lua/box_http.lua)

add_library(httpd SHARED httpd.cc httpfast/httpfast.c ${lua_sources})
install(TARGETS httpd LIBRARY DESTINATION ${PLUGIN_DIR})

message(STATUS "box.httpd: Plugin was configured")

