#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THIRD_PARTY_DIR="${THIRD_PARTY_DIR:-$(cd "$ROOT_DIR/.." && pwd)}"

OPENHITLS_DIR="${OPENHITLS_DIR:-$THIRD_PARTY_DIR/openhitls}"
SECUREC_LINK_DIR="${SECUREC_LINK_DIR:-$OPENHITLS_DIR/platform/Secure_C}"
BOUNDSCHECK_SRC_DIR="${BOUNDSCHECK_SRC_DIR:-$SECUREC_LINK_DIR}"

G_VERSION="${G_VERSION:-208.11.0}"
G_CPU="${G_CPU:-arm64le}"
G_KERNEL="${G_KERNEL:-5.10_ek_preempt_pro}"
SDK_ENV_SCRIPT="${SDK_ENV_SCRIPT:-/opt/RTOS/${G_VERSION}/dlsetenv.sh}"
CROSS_COMPILE_INSTALL_PATH="${CROSS_COMPILE_INSTALL_PATH:-/opt/hcc_arm64le}"

CROSS_COMPILE="${CROSS_COMPILE:-aarch64-target-linux-gnu-}"
CC="${CC:-${CROSS_COMPILE}gcc}"
CXX="${CXX:-${CROSS_COMPILE}g++}"
AR="${AR:-${CROSS_COMPILE}ar}"
RANLIB="${RANLIB:-${CROSS_COMPILE}ranlib}"
STRIP="${STRIP:-${CROSS_COMPILE}strip}"

BITS="${BITS:-64}"
SYSTEM="${SYSTEM:-linux}"
NPROC="${NPROC:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build-a55}"
OPENHITLS_BUILD="${OPENHITLS_BUILD:-$OPENHITLS_DIR/build-a55}"
SKIP_SDK_SETUP="${SKIP_SDK_SETUP:-0}"

usage() {
	cat <<EOF
用法: $(basename "$0") [target] [额外 make 参数]

默认 target: all

常用 target:
  all          构建 openhitls、pqmagic、pqcp 以及三个本地工具
  third_party  只构建 openhitls、pqmagic、pqcp
  tools        只构建本地三个工具
  clean        清理 pqc_soft_demo 构建输出
  help         打印本帮助
  print-config 打印当前脚本会使用的关键环境变量

常用覆盖变量:
  G_VERSION, G_CPU, G_KERNEL, SDK_ENV_SCRIPT, CROSS_COMPILE_INSTALL_PATH
  CROSS_COMPILE, CC, CXX, AR, RANLIB, STRIP
  BUILD_DIR, OPENHITLS_BUILD, BITS, SYSTEM, NPROC, CMAKE_ARGS
  BOUNDSCHECK_SRC_DIR
  SKIP_SDK_SETUP=1   已经在华为环境里手工 source 过工具链时可设置
EOF
}

die() {
	echo "error: $*" >&2
	exit 1
}

print_config() {
	cat <<EOF
ROOT_DIR=$ROOT_DIR
THIRD_PARTY_DIR=$THIRD_PARTY_DIR
OPENHITLS_DIR=$OPENHITLS_DIR
SECUREC_LINK_DIR=$SECUREC_LINK_DIR
BOUNDSCHECK_SRC_DIR=$BOUNDSCHECK_SRC_DIR
SDK_ENV_SCRIPT=$SDK_ENV_SCRIPT
CROSS_COMPILE_INSTALL_PATH=$CROSS_COMPILE_INSTALL_PATH
CROSS_COMPILE=$CROSS_COMPILE
CC=$CC
CXX=$CXX
AR=$AR
RANLIB=$RANLIB
STRIP=$STRIP
BITS=$BITS
SYSTEM=$SYSTEM
NPROC=$NPROC
BUILD_DIR=$BUILD_DIR
OPENHITLS_BUILD=$OPENHITLS_BUILD
CMAKE_ARGS=${CMAKE_ARGS:-}
SKIP_SDK_SETUP=$SKIP_SDK_SETUP
EOF
}

ensure_secure_c_tree() {
	if [[ -d "$SECUREC_LINK_DIR" ]]; then
		return
	fi

	[[ -d "$BOUNDSCHECK_SRC_DIR" ]] || die "未找到 bounds_checking_function/Secure_C 源码目录: $BOUNDSCHECK_SRC_DIR"

	mkdir -p "$(dirname "$SECUREC_LINK_DIR")"
	ln -sfn "$BOUNDSCHECK_SRC_DIR" "$SECUREC_LINK_DIR"
}

setup_sdk() {
	if [[ "$SKIP_SDK_SETUP" == "1" ]]; then
		echo "=== [1] 跳过 SDK 初始化，直接使用当前 shell 环境 ==="
	else
		[[ -f "$SDK_ENV_SCRIPT" ]] || die "未找到 SDK 环境脚本: $SDK_ENV_SCRIPT"
		echo "=== [1] 激活华为 ARM 交叉编译工具链 ==="
		# shellcheck disable=SC1090
		source "$SDK_ENV_SCRIPT" -p "${G_CPU}_${G_KERNEL}" --sdk-path="$CROSS_COMPILE_INSTALL_PATH"
	fi

	export CROSS_COMPILE CC CXX AR RANLIB STRIP
	export BITS SYSTEM NPROC

	command -v "$CC" >/dev/null 2>&1 || die "未找到编译器: $CC"
	command -v "$AR" >/dev/null 2>&1 || die "未找到归档器: $AR"
	command -v "$RANLIB" >/dev/null 2>&1 || die "未找到 ranlib: $RANLIB"
}

run_make() {
	local target="$1"
	shift || true
	local -a args=(
		-C "$ROOT_DIR"
		"$target"
		"CROSS_COMPILE=$CROSS_COMPILE"
		"CC=$CC"
		"AR=$AR"
		"RANLIB=$RANLIB"
		"BUILD_DIR=$BUILD_DIR"
		"OPENHITLS_BUILD=$OPENHITLS_BUILD"
		"BITS=$BITS"
		"SYSTEM=$SYSTEM"
		"NPROC=$NPROC"
	)

	if [[ -n "${CMAKE_ARGS:-}" ]]; then
		args+=("CMAKE_ARGS=$CMAKE_ARGS")
	fi
	if (($# > 0)); then
		args+=("$@")
	fi

	echo "=== [2] 开始构建: $target ==="
	make "${args[@]}"
	echo "=== [3] 构建完成，输出目录: $BUILD_DIR/bin ==="
}

target="${1:-all}"
if (($# > 0)); then
	shift
fi

case "$target" in
	-h|--help|help)
		usage
		exit 0
		;;
	print-config)
		print_config
		exit 0
		;;
esac

ensure_secure_c_tree
setup_sdk
run_make "$target" "$@"