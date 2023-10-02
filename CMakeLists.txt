cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(fcgi_auth
	VERSION 0.1
    DESCRIPTION "Fast CGI Session Authentication"
)

find_library( LIB_FCGI fcgi REQUIRED )

add_executable( ${PROJECT_NAME}
	src/fcgi_auth.c
)

target_include_directories( ${PROJECT_NAME}
	PRIVATE inc
)

#target_compile_options( ${PROJECT_NAME}
#	PRIVATE
#	-Wall
#	-Wextra
#	-Wpedantic
#	-Werror
#)

target_link_libraries( ${PROJECT_NAME}
	sessionmgr
    ${LIB_FCGI}
)

install(TARGETS ${PROJECT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID
)