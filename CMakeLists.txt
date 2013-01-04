cmake_minimum_required(VERSION 2.6)

PROJECT(uhttpd C)
SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
ADD_DEFINITIONS(-Os -Wall -Werror -Wmissing-declarations --std=gnu99 -g3)

OPTION(TLS_SUPPORT "TLS support" ON)

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

FIND_LIBRARY(LIBS crypt)
IF(LIBS STREQUAL "LIBS-NOTFOUND")
	SET(LIBS "")
ENDIF()

SET(SOURCES main.c listen.c client.c utils.c file.c auth.c cgi.c relay.c proc.c)
IF(TLS_SUPPORT)
	SET(SOURCES ${SOURCES} tls.c)
	ADD_DEFINITIONS(-DHAVE_TLS)
ENDIF()

ADD_EXECUTABLE(uhttpd ${SOURCES})
TARGET_LINK_LIBRARIES(uhttpd ubox dl ${LIBS})
