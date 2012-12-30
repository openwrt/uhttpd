cmake_minimum_required(VERSION 2.6)

PROJECT(uhttpd C)
ADD_DEFINITIONS(-O1 -Wall -Werror --std=gnu99 -g3)

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

ADD_EXECUTABLE(uhttpd main.c listen.c client.c utils.c file.c)
TARGET_LINK_LIBRARIES(uhttpd ubox ubus)
