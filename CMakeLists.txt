cmake_minimum_required(VERSION 2.6)

PROJECT(uhttpd C)
ADD_DEFINITIONS(-Os -Wall -Werror -Wmissing-declarations --std=gnu99 -g3)

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

FIND_LIBRARY(LIBS crypt)
IF(LIBS STREQUAL "LIBS-NOTFOUND")
	SET(LIBS "")
ENDIF()

ADD_EXECUTABLE(uhttpd main.c listen.c client.c utils.c file.c auth.c cgi.c relay.c proc.c)
TARGET_LINK_LIBRARIES(uhttpd ubox ${LIBS})
