cmake_platform = 

ifeq ($(strip $(platform)),mingw32)
       cmake_platform = -D CMAKE_TOOLCHAIN_FILE=./cmake/32-bit-toolchain.cmake
endif
ifeq ($(strip $(platform)),mingw64)
       cmake_platform = -D CMAKE_TOOLCHAIN_FILE=./cmake/64-bit-toolchain.cmake
endif


all: all-release

cmake-debug:
	mkdir -p build/debug
	cd build/debug && cmake $(cmake_platform) -D CMAKE_BUILD_TYPE=Debug ../..

build-debug: cmake-debug
	cd build/debug && $(MAKE)

test-debug: build-debug
	cd build/debug && $(MAKE) test

all-debug: build-debug

cmake-release:
	mkdir -p build/release
	cd build/release && cmake $(cmake_platform) -D CMAKE_BUILD_TYPE=Release ../..

build-release: cmake-release
	cd build/release && $(MAKE)

test-release: build-release
	cd build/release && $(MAKE) test

all-release: build-release

release-static:
	mkdir -p build/release
	cd build/release && cmake -D STATIC=ON -D ARCH="x86-64" -D CMAKE_BUILD_TYPE=Release ../.. && $(MAKE)

clean:
	@echo "WARNING: Back-up your wallet if it exists within ./build!" ; \
        read -r -p "This will destroy the build directory, continue (y/N)?: " CONTINUE; \
	[ $$CONTINUE = "y" ] || [ $$CONTINUE = "Y" ] || (echo "Exiting."; exit 1;)
	rm -rf build

tags:
	ctags -R --sort=1 --c++-kinds=+p --fields=+iaS --extra=+q --language-force=C++ src contrib tests/gtest

.PHONY: all cmake-debug build-debug test-debug all-debug cmake-release build-release test-release all-release clean tags
