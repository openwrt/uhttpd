cmake_minimum_required(VERSION 2.6)

PROJECT(uhttpd C)
ADD_DEFINITIONS(-O2 -Wall -Werror -Wmissing-declarations --std=gnu99 -g3)

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

ADD_EXECUTABLE(uhttpd main.c listen.c client.c utils.c file.c auth.c cgi.c relay.c proc.c)
TARGET_LINK_LIBRARIES(uhttpd ubox ubus)
