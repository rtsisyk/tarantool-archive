find_program(PATCH patch)
if (NOT PATCH)
    message(FATAL_ERROR "Could not find 'patch' command")
endif()

set(LUAROCKS_ROCKS_SERVER https://raw.github.com/tarantool/rocks/master/)

set(src_dir ${PROJECT_SOURCE_DIR}/third_party/taranrocks)
set(bin_dir ${PROJECT_BINARY_DIR}/third_party/taranrocks)
set(upstream_dir ${src_dir}/luarocks)
set(patched_dir ${src_dir}/luarocks.patched)

add_custom_command(OUTPUT ${patched_dir}/src/luarocks/cfg.lua
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${upstream_dir} ${patched_dir}
    COMMAND ${PATCH} -d ${patched_dir} -f -p1 -i ${src_dir}/00-tarantool.patch)
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${patched_dir})

add_custom_target(luarocks ALL DEPENDS ${patched_dir}/src/luarocks/cfg.lua)

configure_file(
    "${src_dir}/site_config.lua.in"
    "${patched_dir}/src/luarocks/site_config.lua"
)

install(DIRECTORY ${patched_dir}/src/luarocks DESTINATION ${LUA_SRC_SUBDIR})
install(PROGRAMS ${patched_dir}/src/bin/luarocks DESTINATION bin RENAME taranrocks)
configure_file(${src_dir}/config.lua.in ${bin_dir}/config.lua)
install(FILES ${src_dir}/config.lua
    DESTINATION ${CMAKE_SYSCONF_DIR}/tarantool/rocks)
install(FILES ${src_dir}/taranrocks.1 DESTINATION ${CMAKE_MAN_DIR}/man1)
