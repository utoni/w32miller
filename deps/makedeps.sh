#!/bin/bash
#
# Module:  makedeps.sh
# Author:  Toni <matzeton@googlemail.com>
# Purpose: Build full host- and mingw64 C toolchain without multilib support ..
#          (Using built-in specs.)
# Changed: 04.01.2018
#
# Automated Build Steps:
#   1. build host binutils
#   2. build host gcc
#   3. build host python
#   4. build host tor (try)
#   5. build mingw64 binutils
#   6. build mingw64 gcc core (with mingw64 headers)
#   7. build mingw64 winpthreads
#   8. build mingw64 gcc
#   9. build mingw tor/libtor and dependencies (try)
#
# mingw64 target      : i686-w64-mingw32
# mingw64 Thread model: WINPTHREAD
#

# basic commands
command -v "echo" >/dev/null 2>&1 || exit 1
command -v "printf" >/dev/null 2>&1 || exit 1
command -v "for" >/dev/null 2>&1 || exit 1
command -v "do" >/dev/null 2>&1 || exit 1
command -v "in" >/dev/null 2>&1 || exit 1
command -v "done" >/dev/null 2>&1 || exit 1
# required commands
REQ_CMDS=( "set" "unset" "exec" "export" "test" "if" "else" "fi" "tput" "pwd" "dirname" "touch" "date" "wget" "tar" "mkdir" "patch" "mv" "cd" "make" "cp" "ln" "install" "realpath" "tail" \
    "gcc" "g++" "cpp" "ar" "as" "ld" "ranlib" "strip" )
for cmd in "${REQ_CMDS[@]}"
do
    command -v "${cmd}" >/dev/null 2>&1 || { echo >&2 "$0: I need command \"${cmd}\" but it's not installed. Aborting."; exit 1; }
done
# bash version check
if [ -z "${BASH_VERSINFO}" ]; then
    echo >&2 "$0: Bash version variable \${BASH_VERSINFO}"
    exit 1
fi
if [ ${BASH_VERSINFO[0]} -lt 4 -a ${BASH_VERSINFO[1]} -lt 3 ]; then
    echo >&2 "$0: Bash version 4.3.* required!"
    exit 1
fi
# sha512 available?
SHA512_BIN=$(command -v "sha512sum" 2>/dev/null)


set -e
set -u

DBG_ERRLINES=${DBG_ERRLINES:-10}
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
CYAN=$(tput setaf 6)
BOLD=$(tput bold)
NC=$(tput sgr0)
cd "$(dirname $0)"

export MILLER_PYTHON=Python-2.7.18
export MINGW=mingw-w64-v6.0.0
export ISL=isl-0.20
export BIN=binutils-2.33.1
export GCC=gcc-8.4.0
export GMP=gmp-6.1.2
export MPF=mpfr-4.0.1
export MPC=mpc-1.1.0
export MUSL=musl-1.1.20
export NASM=nasm-2.12.02
#export TOR=tor-0.3.0.9
export PKGCONFIG=pkg-config-0.29.2
export OPENSSL=openssl-1.1.1f
export ZLIB=zlib-1.2.11
export LIBEVENT=libevent-2.1.8-stable

export BUILDDIRS="build_python build_binutils build_gcc build_musl build_tor build_mingw_binutils build_mingw_hdr build_mingw_crt build_mingw_gcc build_nasm build_mingw_winpthread build_pkgconfig build_mingw_openssl build_mingw_zlib build_mingw_libevent build_mingw_tor"

DBG_LOGFILE=${DBG_LOGFILE:-$(realpath "./build.log")}
touch "${DBG_LOGFILE}"
exec 3> ${DBG_LOGFILE}

function dbg {
	timestamp=$(date '+%d-%m-%Y_%H-%M-%S')
	echo -e "[${timestamp}] $*" >&3
	printf "%s\n" "[${timestamp}]${BOLD}${GREEN}[*] $*${NC}"
}

function dbg_run {
    set +e
    timestamp=$(date '+%d-%m-%Y_%H-%M-%S')
    echo -e "[${timestamp}] COMMAND: $*" >&3
    printf "%s\n" "[${timestamp}]${BOLD}${CYAN}[*] COMMAND: $*${NC}"

    if [ -z "${DBG_NOLOG:-}" ]; then
        $* 2>&3 1>&3
        ret=$?
    else
        $* >/dev/null 2>/dev/null
        ret=$?
    fi

    if [ -z "${DBG_NOERR:-}" -a $ret -ne 0 ]; then
        timestamp=$(date '+%d-%m-%Y_%H-%M-%S')
        printf "%s\n" "[${timestamp}]${BOLD}${RED}ERROR: Last command returned ${ret}${NC}"
        printf "%s\n" "[${timestamp}]${BOLD}${RED}ERROR: Printing the last ${DBG_ERRLINES} lines ..${NC}"
        tail -n ${DBG_ERRLINES} ${DBG_LOGFILE}
        printf "%s\n" "[${timestamp}]${BOLD}${RED}EOF ERROR${NC}"
	echo -e "[${timestamp}] COMMAND $* failed with ${ret}" >&3
    fi

    set -e
    return $ret
}

# args: basename, url
function dl_and_extract {
    if [ ! -f "${1}${3}" ]; then
        dbg "download ${1}"
        wget "${2}" -O".tmp.${1}${3}"
        mv ".tmp.${1}${3}" "${1}${3}"
    fi
    if [ "x${3}" != x ]; then
        if [ ! -d "${1}" ]; then
            dbg "extract ${1}"
            if [ "${3}" = '.tar.gz' ]; then
                tar -xzf "${1}${3}"
            elif [ "${3}" = '.tar.bz2' ]; then
                tar -xjf "${1}${3}"
            fi
        fi
        if [ ! -d "${1}" ]; then
            dbg "directory ${1} missing, extraction failed?"
            return 1
        fi
    fi
    return 0
}

function dl_and_extract_gz {
    dl_and_extract "${1}" "${2}" '.tar.gz'
}

function dl_and_extract_bz {
    dl_and_extract "${1}" "${2}" '.tar.bz2'
}


# entry
dbg "DEPS_ROOT     = $(realpath .)"
dbg "DBG_LOGFILE   = ${DBG_LOGFILE}"
dbg "DBG_NOLOG     = ${DBG_NOLOG:-0}"
dbg "DBG_ERRLINES  = ${DBG_ERRLINES}"
if [ $# -gt 0 ]; then
	NMB_BUILDJOBS=$1
else
	NMB_BUILDJOBS=4
fi
dbg "NMB_BUILDJOBS = ${NMB_BUILDJOBS}"
dbg "======="

dbg "exec $(pwd)/config.sh"
. config.sh >/dev/null
dbg "Host...: $(gcc -dumpmachine)"
dbg "Target.: ${targ}"
dbg "Sysroot: ${MY_SYS_ROOT}"
dbg "======="

export PY_BUILD_STAMP=".stamp-python"
if [ ! -d "${MY_SYS_ROOT}" ]; then
	mkdir -p "${MY_SYS_ROOT}"
	dbg "remove ${BUILDDIRS}"
	rm -rf ${BUILDDIRS} ${PY_BUILD_STAMP}
fi

dl_and_extract_gz "${MILLER_PYTHON}" "https://www.python.org/ftp/python/2.7.18/${MILLER_PYTHON}.tgz"

#libtor is disabled until patch the was ported
#dl_and_extract "${TOR}" "https://www.torproject.org/dist/${TOR}.tar.gz"
#if [ ! -d "${TOR}-libtor" ]; then
#	dbg_run cp -rf "${TOR}" "${TOR}-libtor"
#	dbg "patching ${TOR}-libtor"
#	dbg_run patch -d "${TOR}-libtor" -p1 < "${TOR}-libtor.patch"
#fi

dl_and_extract_bz "${MINGW}" "https://downloads.sourceforge.net/project/mingw-w64/mingw-w64/mingw-w64-release/${MINGW}.tar.bz2"
dl_and_extract_gz "${ISL}" "https://libisl.sourceforge.io/${ISL}.tar.gz"
dl_and_extract_gz "${BIN}" "https://ftp.gnu.org/gnu/binutils/${BIN}.tar.gz"
dl_and_extract_gz "${GCC}" "https://ftp.gnu.org/gnu/gcc/${GCC}/${GCC}.tar.gz"
dl_and_extract_gz "${MUSL}" "https://www.musl-libc.org/releases/${MUSL}.tar.gz"
dl_and_extract_gz "${NASM}" "http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/${NASM}.tar.gz"
dl_and_extract_gz "${PKGCONFIG}" "https://pkgconfig.freedesktop.org/releases/${PKGCONFIG}.tar.gz"
dl_and_extract_gz "${OPENSSL}" "https://www.openssl.org/source/${OPENSSL}.tar.gz"
dl_and_extract_gz "${ZLIB}" "https://zlib.net/${ZLIB}.tar.gz"
dl_and_extract_gz "${LIBEVENT}" "https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/${LIBEVENT}.tar.gz"

if [ ! -d "${GCC}/isl" ]; then
    dbg_run mv -fv "${ISL}" "${GCC}/isl"
fi

test -f "${GMP}.tar.bz2" || { dbg_run wget "https://gmplib.org/download/gmp/${GMP}.tar.bz2" -O".tmp.${GMP}.tar.bz2" && dbg_run mv ".tmp.${GMP}.tar.bz2" "${GMP}.tar.bz2" || false; }
test -f "${MPF}.tar.bz2" || { dbg_run wget "http://www.mpfr.org/mpfr-4.0.1/${MPF}.tar.bz2" -O".tmp.${MPF}.tar.bz2" && dbg_run mv ".tmp.${MPF}.tar.bz2" "${MPF}.tar.bz2" || false; }
test -f "${MPC}.tar.gz" || { dbg_run wget "ftp://ftp.gnu.org/gnu/mpc/${MPC}.tar.gz" -O".tmp.${MPC}.tar.gz" && dbg_run mv ".tmp.${MPC}.tar.gz" "${MPC}.tar.gz" || false; }

if [ ! -d "${GCC}/gmp" ]; then
    dbg "extract gmp"
    dbg_run tar -xjf "${GMP}.tar.bz2"
    dbg_run mv -fv "${GMP}" "${GCC}/gmp"
fi
if [ ! -d "${GCC}/mpfr" ]; then
    dbg "extract mpfr"
    dbg_run tar -xjf "${MPF}.tar.bz2"
    dbg_run mv -fv "${MPF}" "${GCC}/mpfr"
fi
if [ ! -d "${GCC}/mpc" ]; then
    dbg "extract mpc"
    dbg_run tar -xzf "${MPC}.tar.gz"
    dbg_run mv -fv "${MPC}" "${GCC}/mpc"
fi

if [ x"${SHA512_BIN}" != x ]; then
    dbg_run ${SHA512_BIN} -c ./sha512.chksms
fi

mkdir -p ${BUILDDIRS}
export CFLAGS="-g0 -O2 -pipe -fPIC -fomit-frame-pointer -Wl,-S -Wno-unused-but-set-parameter -Wno-unused -Wno-unused-result -Wno-attributes -Wno-switch -Wno-shift-negative-value"
export CXXFLAGS="-g0 -O2 -fPIC -fomit-frame-pointer -Wl,-S -Wno-literal-suffix -Wno-switch"

# 0: Make host binutils
dbg "MAKE HOST BINUTILS"
cd build_binutils
test -f Makefile || dbg_run ../${BIN}/configure --disable-multilib --prefix="${MY_SYS_ROOT}" \
  --enable-lto --enable-ld=yes --enable-gold --enable-plugins --enable-64-bit-bfd \
  --with-sysroot="${MY_SYS_ROOT}" \
  --disable-libstdcxx --disable-nls --disable-libquadmath --disable-libquadmath-support
dbg_run make configure-host
dbg_run make -j${NMB_BUILDJOBS}
dbg_run make install-strip
dbg_run cp "../${BIN}/include/libiberty.h" "${MY_SYS_ROOT}/include/libiberty.h"
cd ..

# 0: Make host gcc
dbg "MAKE HOST GCC"
cd build_gcc
test -f Makefile || dbg_run ../${GCC}/configure --disable-multilib --prefix="${MY_SYS_ROOT}" \
  --enable-static --disable-shared --with-system-zlib \
  --enable-languages=c,c++,go --enable-libstdcxx --enable-fully-dynamic-string \
  --disable-libmpx --disable-nls --disable-threads --enable-lto --enable-ld=yes
dbg_run make all-gcc -j${NMB_BUILDJOBS}
dbg_run make all-target-libgcc -j${NMB_BUILDJOBS}
dbg_run make all-target-libstdc++-v3 -j${NMB_BUILDJOBS}
dbg_run make install-strip-gcc
dbg_run make install-strip-target-libgcc
dbg_run make install-strip-target-libstdc++-v3
dbg_run make all-gotools -j${NMB_BUILDJOBS} LDFLAGS=-pthread
dbg_run make install-strip-gotools
dbg_run make all-target-libgo -j${NMB_BUILDJOBS} LDFLAGS=-pthread
dbg_run make install-strip-target-libgo
cd ..

# force use of recent host gcc build
export CC="${MY_SYS_ROOT}/bin/gcc"
export CXX="${MY_SYS_ROOT}/bin/g++"
export CPP="${MY_SYS_ROOT}/bin/cpp"
export AR="${MY_SYS_ROOT}/bin/ar"
export AS="${MY_SYS_ROOT}/bin/as"
export LD="${MY_SYS_ROOT}/bin/ld"
export RANLIB="${MY_SYS_ROOT}/bin/ranlib"
export STRIP="${MY_SYS_ROOT}/bin/strip"

DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/bin/ld" "${MY_SYS_ROOT}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/real-ld" || true
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/bin/nm" "${MY_SYS_ROOT}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/nm" || true
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/bin/strip" "${MY_SYS_ROOT}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/strip" || true
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/bin/strip" "${MY_SYS_ROOT}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/gstrip" || true

# 0.1: Make Python
if [ ! -r ${PY_BUILD_STAMP} ]; then
    dbg "MAKE PYTHON"
    cd build_python
    test -f Makefile || dbg_run ../${MILLER_PYTHON}/configure --prefix=${MY_SYS_ROOT} --enable-optimizations --disable-shared
    dbg_run make -j${NMB_BUILDJOBS}
    dbg_run make install
    dbg_run ln -sr ${MY_SYS_ROOT}/bin/python2.7 ${MY_SYS_ROOT}/bin/${MILLER_PYTHON} || true
    dbg_run ${STRIP} -s "${MY_SYS_ROOT}/bin/python2.7"
    cd ..
    dbg_run touch ${PY_BUILD_STAMP} # build python only once (takes lots of time with --enable-optimizations + tests)
else
    dbg "Skipping Python build (already done)"
fi

#libtor is disabled until patch the was ported
# 0.5: Make host TOR (required for CNC server)
#dbg "MAKE HOST TOR (try)"
#cd build_tor
#unset ret
#test -f Makefile || dbg_run ../${TOR}/configure --prefix=${MY_SYS_ROOT} --disable-silent-rules --enable-gcc-warnings-advisory --disable-systemd --disable-libfuzzer --disable-oss-fuzz --disable-system-torrc && ret=0 || ret=$?
#if [ $ret -eq 0 ]; then
#	dbg_run make -j${NMB_BUILDJOBS} || dbg "HOST TOR build failed, ignore"
#	dbg_run make install
#else
#	dbg "HOST TOR configure failed, ignore"
#fi
#cd ..
# generate torrc
#if [ -r "${MY_SYS_ROOT}/etc/tor/torrc.sample" ]; then
#    dbg_run ./torconf.sh
#fi

# 1: Make binutils
dbg "MAKE BINUTILS for ${targ}"
cd build_mingw_binutils
test -f Makefile || dbg_run ../${BIN}/configure --target=${targ} --disable-multilib --prefix="${MY_SYS_ROOT}/${targ}" \
  --enable-lto --enable-ld=yes --with-sysroot="${MY_SYS_ROOT}/${targ}" \
  --disable-libstdcxx --disable-nls --disable-libquadmath --disable-libquadmath-support
dbg_run make -j${NMB_BUILDJOBS}
dbg_run make install-strip
cd ..

# 2: Make nasm
dbg "MAKE NASM for ${targ}"
cd build_nasm
dbg_run mkdir -p common macros # nasm build fix
test -f Makefile || dbg_run ../${NASM}/configure --target=${targ} --prefix=${MY_SYS_ROOT}/${targ}
dbg_run make -j${NMB_BUILDJOBS}
dbg_run make install
cd ..

# 3: Make symlinks / directories required for Mingw64 builds
dbg "MAKE SYMLINKS/DIRS"
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/${targ}" "${MY_SYS_ROOT}/mingw" || true
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/${targ}" "${MY_SYS_ROOT}/${targ}/mingw" || true
mkdir -p ${MY_SYS_ROOT}/${targ}/lib

# 4: Make mingw headers
dbg "MAKE MINGW HEADERS"
cd build_mingw_hdr
test -f Makefile || dbg_run ../${MINGW}/mingw-w64-headers/configure --host=${targ} --prefix="${MY_SYS_ROOT}/${targ}"
dbg_run make -j${NMB_BUILDJOBS}
dbg_run make install
cd ..

# 5: Make gcc core
dbg "MAKE GCC CORE"
cd build_mingw_gcc
test -f Makefile || dbg_run ../${GCC}/configure --target=${targ} --disable-multilib --with-sysroot="${MY_SYS_ROOT}/${targ}" --prefix="${MY_SYS_ROOT}/${targ}" \
  --enable-static --disable-shared --with-system-zlib --without-included-gettext \
  --enable-sjlj-exceptions --enable-threads=posix --disable-libstdcxx --enable-fully-dynamic-string \
  --disable-libmpx --enable-languages=c --enable-lto
dbg_run make all-gcc -j${NMB_BUILDJOBS}
dbg_run make install-strip-gcc
cd ..

# 6: Make pkg-config (required for libtor)
dbg "MAKE PKG-CONFIG"
cd build_pkgconfig
test -f Makefile || dbg_run ../${PKGCONFIG}/configure --prefix="${MY_SYS_ROOT}/${targ}" --with-internal-glib --with-pc-path="${MY_SYS_ROOT}/${targ}/lib/pkgconfig/"
dbg_run make -j${NMB_BUILDJOBS}
dbg_run make install
cd ..
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/${targ}/bin/pkg-config" "${MY_SYS_ROOT}/${targ}/bin/${targ}-pkg-config" || true

# force use of recent host gcc build
export CC="${MY_SYS_ROOT}/${targ}/bin/${targ}-gcc"
export CXX=false
export CPP="${MY_SYS_ROOT}/${targ}/bin/${targ}-cpp"
export AR="${MY_SYS_ROOT}/${targ}/bin/${targ}-ar"
export AS="${MY_SYS_ROOT}/${targ}/bin/${targ}-as"
export LD="${MY_SYS_ROOT}/${targ}/bin/${targ}-ld"
export RANLIB="${MY_SYS_ROOT}/${targ}/bin/${targ}-ranlib"
export STRIP="${MY_SYS_ROOT}/${targ}/bin/${targ}-strip"
export DLLTOOL="${MY_SYS_ROOT}/${targ}/bin/${targ}-dlltool"
export WINDRES="${MY_SYS_ROOT}/${targ}/bin/${targ}-windres"

# 7: Make mingw crt
dbg "MAKE MINGW CRT"
cd build_mingw_crt
test -f Makefile || dbg_run ../${MINGW}/mingw-w64-crt/configure --host=${targ} \
  --with-sysroot="${MY_SYS_ROOT}/${targ}" --prefix="${MY_SYS_ROOT}/${targ}"
dbg_run make -j${NMB_BUILDJOBS}
dbg_run make install-strip
cd ..

# 8: Make win pthreads
dbg "MAKE WINPTHREADS"
cd build_mingw_winpthread
test -f Makefile || dbg_run ../${MINGW}/mingw-w64-libraries/winpthreads/configure --host=${targ} \
  --with-sysroot="${MY_SYS_ROOT}/${targ}" --prefix="${MY_SYS_ROOT}/${targ}"
dbg_run make -j${NMB_BUILDJOBS} || dbg "expected failure"
dbg_run cp fakelib/libgcc.a fakelib/libpthread.a
dbg_run make -j${NMB_BUILDJOBS} && dbg_run make install-strip

dbg_run cp ${MY_SYS_ROOT}/${targ}/bin/libwinpthread-1.dll \
   ${MY_SYS_ROOT}/${targ}/lib/

cd ..

# 9: Make gcc second pass
dbg "MAKE GCC PASS #2"
cd build_mingw_gcc
dbg_run make -j${NMB_BUILDJOBS}
dbg_run make install-strip-gcc
dbg_run make all-target-libgcc -j${NMB_BUILDJOBS}
dbg_run make install-target-libgcc
cd ..

export CFLAGS="-g0 -Os -s -pipe -flto -fuse-linker-plugin -ffat-lto-objects -fomit-frame-pointer -fdata-sections -ffunction-sections -Wno-unused-but-set-parameter -Wno-unused-variable -Wno-unused-result -Wno-attributes -Wno-switch -Wno-float-conversion -Wno-maybe-uninitialized -Wl,-gc-sections"
export LDFLAGS="-flto -Os -Wno-maybe-uninitialized -Wl,-gc-sections"

DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/${targ}/bin/${targ}-ld" "${MY_SYS_ROOT}/${targ}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/real-ld" || true
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/${targ}/bin/${targ}-nm" "${MY_SYS_ROOT}/${targ}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/nm" || true
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/${targ}/bin/${targ}-strip" "${MY_SYS_ROOT}/${targ}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/strip" || true
DBG_NOERR=1 dbg_run ln -sr "${MY_SYS_ROOT}/${targ}/bin/${targ}-strip" "${MY_SYS_ROOT}/${targ}/lib/gcc/$(${CC} -dumpmachine)/$(${CC} -dumpversion)/gstrip" || true

# 10: Make mingw openssl
dbg "MAKE MINGW OPENSSL (try, required for libtor)"
cd build_mingw_openssl
DISBALED_CIPHERS="no-idea no-mdc2 no-camellia no-bf no-cast no-des no-rc2 no-rc4 no-rc5 no-mdc2 no-afalgeng no-asan no-blake2 no-chacha no-cmac no-seed no-md2 no-md4 no-cms no-capieng no-comp no-ct no-dgram no-ec_nistp_64_gcc_128 no-err no-async no-dynamic-engine no-dso no-dtls no-filenames no-zlib-dynamic no-whirlpool no-ui no-ubsan no-srp no-srtp no-ts no-asm no-autoalginit no-ssl3-method no-weak-ssl-ciphers no-dsa no-async"
unset ret
test -f Makefile || dbg_run ../${OPENSSL}/Configure mingw no-egd no-zlib no-hw ${DISBALED_CIPHERS} --prefix="${MY_SYS_ROOT}/${targ}" ${CFLAGS} && ret=0 || ret=$?
if [ $ret -eq 0 ]; then
	dbg_run make -j${NMB_BUILDJOBS} || dbg "MINGW OPENSSL build failed, ignore"
	dbg_run make install_dev || dbg "MINGW OPENSSL install failed, ignore"
else
	dbg "mingw openssl configure failed, ignore"
fi
cd ..

# 11: Make mingw zlib
dbg "MAKE MINGW ZLIB (try, required for libtor)"
cd build_mingw_zlib
unset ret
test -f Makefile || dbg_run ../${ZLIB}/configure --static --const --prefix="${MY_SYS_ROOT}/${targ}" && ret=0 || ret=$?
if [ $ret  -eq 0 ]; then
	dbg_run make -j${NMB_BUILDJOBS} libz.a || dbg "MINGW ZLIB build failed, ignore"
	dbg_run make install || dbg "MINGW ZLIB install failed, ignore"
else
	 dbg "MINGW ZLIB configure failed, ignore"
fi
cd ..

# 12: Make mingw libevent
dbg "MAKE MINGW LIBEVENT (try, required for libtor)"
cd build_mingw_libevent
unset ret
test -f Makefile || dbg_run ../${LIBEVENT}/configure \
  --disable-libevent-regress --disable-samples --disable-openssl \
  --enable-function-sections --prefix="${MY_SYS_ROOT}/${targ}" \
  --host=${targ} --enable-static --disable-shared && ret=0 || ret=$?
if [ $ret -eq 0 ]; then
	dbg_run make -j${NMB_BUILDJOBS} || dbg "MINGW LIBEVENT build failed, ignore"
	dbg_run make install || dbg "MINGW LIBEVENT install failed, ignore"
	DBG_NOERR=1 dbg_run ln -sr ./.libs/libevent* ./ || true # required for mingw tor builds (using static libevent)
else
	dbg "MINGW LIBEVENT configure failed, ignore"
fi
cd ..

#libtor is disabled until patch the was ported
# 13: Make patch'd mingw tor (libtor)
#dbg "MAKE MINGW TOR (libtor patch)"
#cd build_mingw_tor
#TOR_CFLAGS="-DHAVE_SSL_GET_SERVER_RANDOM=1 -DHAVE_SSL_GET_CLIENT_CIPHERS=1 -DHAVE_SSL_GET_CLIENT_RANDOM=1 -DHAVE_SSL_SESSION_GET_MASTER_KEY=1"
#TOR_CFLAGS_EXTRA="-fasynchronous-unwind-tables -fno-strict-aliasing -Wall -Wextra -W"
#TOR_ARCHIVES="src/or/libtor.a src/common/libor.a src/common/libor-ctime.a src/common/libor-crypto.a src/ext/keccak-tiny/libkeccak-tiny.a src/common/libcurve25519_donna.a src/ext/ed25519/ref10/libed25519_ref10.a src/ext/ed25519/donna/libed25519_donna.a src/common/libor-event.a src/trunnel/libor-trunnel.a"
#TOR_STATIC_LIBS="$(realpath ../build_mingw_libevent)/libevent.a $(realpath ../build_mingw_openssl)/libssl.a $(realpath ../build_mingw_openssl)/libcrypto.a $(realpath ../build_mingw_zlib)/libz.a"
#unset ret
#test -f Makefile || CFLAGS="${CFLAGS} ${TOR_CFLAGS}" dbg_run ../${TOR}-libtor/configure --host=${targ} --disable-gcc-hardening --enable-static-tor --prefix="${MY_SYS_ROOT}/${targ}" --disable-tool-name-check --with-libevent-dir="$(realpath ../build_mingw_libevent)" --with-openssl-dir="$(realpath ../build_mingw_openssl)" --with-zlib-dir="$(realpath ../build_mingw_zlib)" --disable-systemd --disable-libfuzzer --disable-oss-fuzz --disable-system-torrc --disable-local-appdata --enable-tor2web-mode && ret=0 || ret=$?
#if [ $ret -eq 0 ]; then
#	# build only required targets
#	CFLAGS="${CFLAGS} ${TOR_CFLAGS}" dbg_run make src/or/tor.exe src/tools/tor-resolve.exe src/tools/tor-gencert.exe src/test/test.exe -j${NMB_BUILDJOBS} V=1 || dbg "MINGW TOR build failed, ignore"
#	dbg_run ${STRIP} -s src/or/tor.exe || true
#	dbg_run make install-exec || dbg "MINGW TOR install failed, ignore"
#	# install tests
#	dbg_run install -c src/test/test.exe "${MY_SYS_ROOT}/${targ}/bin/tor-tests.exe" || dbg "tor-tests.exe install failed, ignore"
#else
#	dbg "MINGW TOR configure failed, ignore"
#fi
# compile/link libtor
#dbg "MAKE MINGW LIBTOR"
#dbg_run ${CC} -std=gnu99 ${CFLAGS} ${TOR_CFLAGS} ${TOR_CFLAGS_EXTRA} ../${TOR}-libtor/src/or/tor_main.c ${TOR_ARCHIVES} -shared -o src/or/libtor.dll -lgdi32 -lcrypt32 ${TOR_STATIC_LIBS} -lws2_32 "${MY_SYS_ROOT}/${targ}/lib/libwinpthread.a" -static-libgcc -Wl,-require-defined=_tor_main@8 -Wl,-require-defined=_tor_init -Wl,-Map=src/or/libtor.map || dbg "LIBTOR build failed, ignore"
#dbg_run ${STRIP} -s src/or/libtor.dll
## install libtor
#dbg_run install -c src/or/libtor.dll "${MY_SYS_ROOT}/${targ}/lib/libtor.dll" || dbg "libtor.dll install failed, ignore"
#dbg_run install -c ../${TOR}-libtor/src/or/libtor.h "${MY_SYS_ROOT}/${targ}/include/libtor.h" || dbg "libtor.h install failed, ignore"
#cd ..

dbg "Creating ${MY_SYS_ROOT}/activate.sh"
cat <<EOF >${MY_SYS_ROOT}/activate.sh
#!/bin/bash
export PATH="${MY_SYS_ROOT}/bin:${MY_SYS_ROOT}/i686-w64-mingw32/bin:${MY_SYS_ROOT}/x86_64-pc-linux-gnu/bin:${PATH}"
EOF
chmod +x ${MY_SYS_ROOT}/activate.sh

dbg "DONE"

if [ ! -z "${SECONDS:-}" ]; then
	T_DELTA_H=$(( ${SECONDS} / 3600 ))
	T_DELTA_M=$(( ${SECONDS} / 60 % 60 ))
	dbg "TOTAL TIME: ${T_DELTA_H}hrs ${T_DELTA_M}min"
fi
