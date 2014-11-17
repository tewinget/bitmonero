set (CMAKE_SYSTEM_NAME Windows)

set (GCC_PREFIX x86_64-w64-mingw32)
set (CMAKE_C_COMPILER ${GCC_PREFIX}-gcc)
set (CMAKE_CXX_COMPILER ${GCC_PREFIX}-g++)
#set (CMAKE_AR ar CACHE FILEPATH "" FORCE)
#set (CMAKE_NM nm CACHE FILEPATH "" FORCE)
#set (CMAKE_RANLIB ${GCC_PREFIX}-gcc-ranlib CACHE FILEPATH "" FORCE)
set (CMAKE_RC_COMPILER ${GCC_PREFIX}-windres)

#set (CMAKE_FIND_ROOT_PATH /usr/${GCC_PREFIX})
set (BOOST_INCLUDEDIR /usr/${GCC_PREFIX}/include/boost;/usr/${GCC_PREFIX}/sys-root/mingw/include/boost)
set (BOOST_LIBRARYDIR /usr/${GCC_PREFIX}/lib;/usr/${GCC_PREFIX}/sys-root/mingw/lib)
set (BOOST_ROOT /usr/${GCC_PREFIX}/sys-root/mingw)

set (OPENSSL_ROOT_DIR /usr/${GCC_PREFIX};/usr/${GCC_PREFIX}/sys-root/mingw)

set (Boost_USE_STATIC_LIBS ON)

# Ensure cmake doesn't find things in the wrong places
set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER) # Find programs on host
set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY) # Find libs in target
set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY) # Find includes in target

set (MINGW_FLAG "-m64")
set (USE_LTO_DEFAULT false)
