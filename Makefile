CC		=	gcc
RM		=	rm -f
STRIP		=	strip
CFLAGS		=	-O3 -W -Wall

# 平台检测信息在 all 规则中通过 shell 动态判断

# 颜色定义
COLOR_RESET   = \033[0m
COLOR_BOLD    = \033[1m
COLOR_GREEN   = \033[32m
COLOR_YELLOW  = \033[33m
COLOR_BLUE    = \033[34m
COLOR_CYAN    = \033[36m

# 静默模式
MAKEFLAGS+= --no-print-directory
.SILENT:

# 修正后的目录结构路径
CRYPTO_SRC = src/crypto/protocol/pel.c src/crypto/aes/aes.c src/crypto/sha1/sha1.c
CLIENT_SRC = src/client/client.c
SERVER_SRC = src/server/server.c \
	     src/server/core/daemon.c \
	     src/server/managers/client/client_manager.c \
	     src/server/managers/plugin/plugin_manager.c \
	     src/server/session/session_manager.c \
	     src/server/session/shell_session.c \
	     src/server/commands/management/management_commands.c \
	     src/server/commands/client/client_commands.c \
	     src/server/network/tcp_listener.c \
	     src/server/network/unix_socket.c \
	     src/server/ui/interactive_terminal.c \
	     src/server/utils/output_writer.c

# 插件相关
PLUGIN_SRC_DIR = plugins/src
PLUGIN_LIB_DIR = plugins/lib
PLUGIN_SOURCES = ${PLUGIN_SRC_DIR}/*.c
PLUGIN_EXT ?=

CLIENT_TARGET = build/client
SERVER_TARGET = build/server

# 目标文件
CRYPTO_OBJ = ${CRYPTO_SRC:.c=.o}
CLIENT_OBJ = ${CLIENT_SRC:.c=.o} ${CRYPTO_OBJ}
SERVER_OBJ = ${SERVER_SRC:.c=.o} ${CRYPTO_OBJ}

# 链接模式 (dynamic 或 static)
LINK_MODE ?= dynamic

# 通用链接库
CLIENT_LDFLAGS_dynamic = -lutil
CLIENT_LDFLAGS_static  = -static -lutil
SERVER_LDFLAGS_dynamic = -pthread
SERVER_LDFLAGS_static  = -static -pthread
PLUGIN_LDFLAGS_dynamic = -pthread
PLUGIN_LDFLAGS_static  = -static -pthread

CLIENT_LDFLAGS = ${CLIENT_LDFLAGS_${LINK_MODE}}
SERVER_LDFLAGS = ${SERVER_LDFLAGS_${LINK_MODE}}
PLUGIN_LDFLAGS = ${PLUGIN_LDFLAGS_${LINK_MODE}}

# 包含路径
INC_PATHS = -Isrc/server \
	    -Isrc/server/core \
	    -Isrc/server/managers/client \
	    -Isrc/server/managers/plugin \
	    -Isrc/server/session \
	    -Isrc/server/commands/management \
	    -Isrc/server/commands/client \
	    -Isrc/server/network \
	    -Isrc/server/ui \
	    -Isrc/server/utils \
	    -Isrc/client \
	    -Isrc/crypto/protocol \
	    -Isrc/crypto/aes \
	    -Isrc/crypto/sha1 \
	    -Isrc/crypto/obfuscation

# Client 混淆编译标志
CLIENT_OBFUSCATE_FLAGS = -ffunction-sections -fdata-sections \
			 -fno-asynchronous-unwind-tables \
			 -fno-ident \
			 -Wl,--gc-sections

DISTFILES= \
	src/crypto/sha1/sha1.h \
	src/crypto/aes/aes.h \
	src/crypto/protocol/pel.h \
	src/client/client.h \
	src/server/core/daemon.h \
	src/server/managers/client/client_manager.h \
	src/server/managers/plugin/plugin_manager.h \
	src/server/session/session_manager.h \
	src/server/session/shell_session.h \
	src/server/commands/management/management_commands.h \
	src/server/commands/client/client_commands.h \
	src/server/network/tcp_listener.h \
	src/server/network/unix_socket.h \
	src/server/ui/interactive_terminal.h \
	src/server/utils/output_writer.h \
	README \
	ChangeLog \
	Makefile \
	${CRYPTO_SRC} ${CLIENT_SRC} ${SERVER_SRC}

all:
	echo ""
	printf '%b\n' "${COLOR_BOLD}KSH Build System${COLOR_RESET}"
	echo ""
	echo "Available targets:"
	printf '%b\n' "  ${COLOR_CYAN}make linux${COLOR_RESET}          - Build Linux (dynamic)"
	printf '%b\n' "  ${COLOR_CYAN}make linux-static${COLOR_RESET}  - Build Linux (static)"
	printf '%b\n' "  ${COLOR_CYAN}make freebsd${COLOR_RESET}        - Build FreeBSD (dynamic)"
	printf '%b\n' "  ${COLOR_CYAN}make freebsd-static${COLOR_RESET}  - Build FreeBSD (static)"
	printf '%b\n' "  ${COLOR_CYAN}make cygwin${COLOR_RESET}         - Build Cygwin (dynamic alias)"
	echo ""
	@host=`uname -s`; \
	case "$$host" in \
		Linux) target=linux; desc="Linux (dynamic)";; \
		FreeBSD) target=freebsd; desc="FreeBSD (dynamic)";; \
		CYGWIN*|Cygwin*) target=cygwin; desc="Cygwin (dynamic)";; \
		*) target=""; desc="Unsupported";; \
	esac; \
	if [ -z "$$target" ]; then \
		printf '%b\n' "${COLOR_YELLOW}Unsupported host platform: $$host. Please choose a target manually.${COLOR_RESET}"; \
		exit 1; \
	else \
		printf '%b\n' "${COLOR_BLUE}Detected $$desc; running 'make $$target'...${COLOR_RESET}"; \
		${MAKE} $$target; \
	fi

linux:
	@set -e; \
	echo ""; \
	if [ "${CYGWIN_BUILD}" = "1" ]; then \
		client_out="${CLIENT_TARGET}.exe"; \
		server_out="${SERVER_TARGET}.exe"; \
		plugin_ext=".exe"; \
		printf '%b\n' "${COLOR_BOLD}Building for Cygwin (POSIX layer)...${COLOR_RESET}"; \
	else \
		client_out="${CLIENT_TARGET}"; \
		server_out="${SERVER_TARGET}"; \
		plugin_ext=""; \
		printf '%b\n' "${COLOR_BOLD}Building for Linux...${COLOR_RESET}"; \
	fi; \
	mkdir -p build; \
	mkdir -p ${PLUGIN_LIB_DIR}; \
	rm -f ${CLIENT_TARGET} ${CLIENT_TARGET}.exe ${SERVER_TARGET} ${SERVER_TARGET}.exe; \
	printf '%b\n' "${COLOR_CYAN}[1/4]${COLOR_RESET} Compiling client (with obfuscation)..."; \
	${CC} ${CFLAGS} ${INC_PATHS} ${CLIENT_OBFUSCATE_FLAGS} -o "$$client_out" ${CRYPTO_SRC} ${CLIENT_SRC} -DLINUX ${CLIENT_LDFLAGS}; \
	printf '%b\n' "${COLOR_CYAN}[2/4]${COLOR_RESET} Compiling server..."; \
	${CC} ${CFLAGS} ${INC_PATHS} -o "$$server_out" ${CRYPTO_SRC} ${SERVER_SRC} -DLINUX ${SERVER_LDFLAGS}; \
	printf '%b\n' "${COLOR_CYAN}[3/4]${COLOR_RESET} Building plugins..."; \
	${MAKE} clean-plugins >/dev/null; \
	PLUGIN_EXT="$$plugin_ext" ${MAKE} plugins PLATFORM_DEF=-DLINUX; \
	printf '%b\n' "${COLOR_CYAN}[4/4]${COLOR_RESET} Stripping binaries..."; \
	${STRIP} --strip-all --remove-section=.comment --remove-section=.note "$$client_out"; \
	${STRIP} "$$server_out"; \
	echo ""; \
	client_size=$$(ls -lh "$$client_out" | awk '{print $$5}'); \
	server_size=$$(ls -lh "$$server_out" | awk '{print $$5}'); \
	printf '%b\n' "${COLOR_GREEN}Build completed successfully!${COLOR_RESET}"; \
	echo "  Client: $$client_out ($$client_size) [OBFUSCATED]"; \
	echo "  Server: $$server_out ($$server_size)"; \
	echo ""

linux-static:
	@${MAKE} LINK_MODE=static linux

freebsd:
	echo ""
	printf '%b\n' "${COLOR_BOLD}Building for FreeBSD...${COLOR_RESET}"
	mkdir -p build
	mkdir -p ${PLUGIN_LIB_DIR}
	printf '%b\n' "${COLOR_CYAN}[1/4]${COLOR_RESET} Compiling client (with obfuscation)..."
	${CC} ${CFLAGS} ${INC_PATHS} ${CLIENT_OBFUSCATE_FLAGS} -DFREEBSD -o ${CLIENT_TARGET} ${CRYPTO_SRC} ${CLIENT_SRC} ${CLIENT_LDFLAGS}
	printf '%b\n' "${COLOR_CYAN}[2/4]${COLOR_RESET} Compiling server..."
	${CC} ${CFLAGS} ${INC_PATHS} -DFREEBSD -o ${SERVER_TARGET} ${CRYPTO_SRC} ${SERVER_SRC} ${SERVER_LDFLAGS}
	printf '%b\n' "${COLOR_CYAN}[3/4]${COLOR_RESET} Building plugins..."
	@${MAKE} clean-plugins >/dev/null
	@${MAKE} plugins PLATFORM_DEF=-DFREEBSD
	printf '%b\n' "${COLOR_CYAN}[4/4]${COLOR_RESET} Stripping binaries..."
	${STRIP} -s ${CLIENT_TARGET}
	${STRIP} ${SERVER_TARGET}
	echo ""
	printf '%b\n' "${COLOR_GREEN}Build completed successfully!${COLOR_RESET}"
	echo "  Client: build/client ($$(ls -lh build/client | awk '{print $$5}')) [OBFUSCATED]"
	echo "  Server: build/server ($$(ls -lh build/server | awk '{print $$5}'))"
	echo ""

freebsd-static:
	@${MAKE} LINK_MODE=static freebsd

.PHONY: linux linux-static freebsd freebsd-static cygwin plugins clean-plugins

cygwin:
	@CYGWIN_BUILD=1 ${MAKE} linux

plugins:
	@set -e; \
	mkdir -p ${PLUGIN_LIB_DIR}; \
	set -- ${PLUGIN_SRC_DIR}/*.c; \
	plugin_ext="${PLUGIN_EXT}"; \
	if [ "$$1" = "${PLUGIN_SRC_DIR}/*.c" ]; then \
		printf '%b\n' "       ${COLOR_BLUE}-> No plugins to build${COLOR_RESET}"; \
	else \
		count=0; \
		for src in "$$@"; do \
			name=$$(basename "$$src" .c); \
			out="${PLUGIN_LIB_DIR}/$$name$${plugin_ext}"; \
			printf '%b\n' "       ${COLOR_CYAN}-> Building $$name$${plugin_ext}...${COLOR_RESET}"; \
			${CC} ${CFLAGS} ${INC_PATHS} -o "$$out" "$$src" ${PLATFORM_DEF} ${PLUGIN_LDFLAGS}; \
			count=$$((count + 1)); \
		done; \
		printf '%b\n' "       ${COLOR_GREEN}-> Compiled $$count plugin(s) successfully${COLOR_RESET}"; \
	fi

# 清理插件
clean-plugins:
	${RM} ${PLUGIN_LIB_DIR}/*

# 编译规则
.SUFFIXES: .c .o

.c.o:
	${CC} ${CFLAGS} ${INC_PATHS} -c $< -o $@

# clean
clean:
	${RM} ${CLIENT_TARGET} ${CLIENT_TARGET}.exe ${SERVER_TARGET} ${SERVER_TARGET}.exe
	${RM} src/*/*.o src/*/*/*.o src/*/*/*/*.o
	${RM} -rf build/*.o
	${RM} core core.*
	${MAKE} clean-plugins

distclean: clean
	${RM} -rf build ${PLUGIN_LIB_DIR}
