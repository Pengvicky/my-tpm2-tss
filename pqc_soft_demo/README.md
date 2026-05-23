PQC 软算法桥接工具说明

这个目录是一个独立的小型外部工程，目标是把 TPM/TCM 侧的公钥 blob、签名、KEM 数据和主机侧的 pqmagic、pqcp 软件算法库接起来。

当前包含三个命令行工具：

- `tpm_pq_pubtool`：TPM2B_PUBLIC 和原始公钥之间互转。
- `pqmagic_aigis_tool`：AIGIS-SIG 软件侧 keygen、sign、verify。
- `pqcp_scloud_tool`：SCLOUD 软件侧 keygen、encap、decap。

为什么这里仍然保留 Makefile

这里没有改成新的 CMakeLists。原因很直接：

1. 这套工具本身很薄，核心难点在第三方库的构建顺序和链接方式，不在本地源文件组织。
2. 华为侧实际使用方式是直接执行 `build.sh`，那最稳的方案就是让 `build.sh` 负责初始化环境，再调用一个可读、可改、可单步执行的 GNU Makefile。
3. openhitls、pqmagic、pqcp 本身已经各自有自己的构建逻辑，强行再包一层新的顶层 CMakeLists，收益不大，排障反而更绕。

目录假设

默认假设目录结构如下：

```text
third_party/
	openhitls/
	pqcp/
	pqmagic/
	pqc_soft_demo/
```

其中：

- `openhitls/platform/Secure_C` 是本机这边的 Secure_C 源码位置。
- 华为环境里如果目录名字是 `bounds_checking_function`，但源码版本和本地 Secure_C 相同，也没有本质问题，见下文说明。

关于 Secure_C 和 bounds_checking_function 是否有影响

结论先说：如果版本一致、头文件接口一致、最终导出的仍然是 `libboundscheck.so` 或 `-lboundscheck`，那对这套工具源码本身没有影响，差别主要在“集成方式”和“目录命名”。

这里要区分三层：

1. 源码实现层：openHiTLS 依赖的是 Secure_C/libboundscheck 这一套安全字符串与内存函数实现。
2. 构建集成层：华为侧经常把它作为 `bounds_checking_function` 组件挂进 LiteOS 构建系统。
3. 链接层：真正参与链接时，通常仍然是 `boundscheck` / `libboundscheck.so` 这个名字。

所以：

- 如果华为那边只是组件目录名不同，但内容与本地 `openhitls/platform/Secure_C` 相同，那么不影响。
- 如果华为那边只有 LiteOS 组件路径，没有 `openhitls/platform/Secure_C` 这个目录，可以在执行 `build.sh` 前设置 `BOUNDSCHECK_SRC_DIR`，脚本会把它软链接到 openhitls 期望的位置。
- 如果华为那边导出的库名不是 `boundscheck`，那才需要额外改 Makefile 的 `BOUNDSCHECK_LIB_NAME`。

本工程推荐的构建方式

在华为环境中，优先直接执行：

```bash
cd pqc_soft_demo
./build.sh all
```

如果你只是想看脚本会用哪些路径和变量：

```bash
./build.sh print-config
```

如果你已经在当前 shell 里手工 source 过 SDK 环境，可以跳过脚本内部那一步：

```bash
SKIP_SDK_SETUP=1 ./build.sh all
```

如果华为那边的 bounds_checking_function 源码不在 `openhitls/platform/Secure_C`，可以这样执行：

```bash
BOUNDSCHECK_SRC_DIR=/your/path/bounds_checking_function ./build.sh all
```

build.sh 默认行为

`build.sh` 会做这几件事：

1. 按你给的 RTOS 脚本格式初始化华为 A55 交叉编译环境。
2. 检查 `openhitls/platform/Secure_C` 是否存在；如果不存在且设置了 `BOUNDSCHECK_SRC_DIR`，则自动建立软链接。
3. 调用本目录的 `Makefile`，按顺序构建 Secure_C、openhitls、pqmagic、pqcp，再编译三个工具。
4. 将交叉编译产物输出到独立目录，默认是 `build-a55/`，避免和本机 x86 构建缓存混用。

build.sh 支持的常用 target

- `all`：构建全部内容。
- `third_party`：只构建 openhitls、pqmagic、pqcp。
- `tools`：只构建本地三个工具。
- `clean`：清理本工程输出。
- `help`：打印帮助。
- `print-config`：打印当前脚本解析出的关键环境变量。

常用可覆盖变量

- `G_VERSION`
- `G_CPU`
- `G_KERNEL`
- `SDK_ENV_SCRIPT`
- `CROSS_COMPILE_INSTALL_PATH`
- `CROSS_COMPILE`
- `CC`
- `CXX`
- `AR`
- `RANLIB`
- `BUILD_DIR`
- `OPENHITLS_BUILD`
- `BITS`
- `SYSTEM`
- `NPROC`
- `CMAKE_ARGS`
- `BOUNDSCHECK_SRC_DIR`
- `SKIP_SDK_SETUP`

输出目录

默认输出位于：

- `build-a55/bin/`：三个工具可执行文件。
- `build-a55/lib/`：为了运行 `pqcp_scloud_tool` 方便，会额外带上 `libboundscheck.so`。
- `build-a55/third_party/`：pqmagic、pqcp 的外部 build 目录。

三个工具的使用方法

`tpm_pq_pubtool`

```text
extract --in <tpm2b_public> [--raw-out <file>]
wrap [--alg <aigis1|aigis2|aigis3|scloud128|scloud192|scloud256>] --raw-in <file> --out <tpm2b_public>
```

`pqmagic_aigis_tool`

```text
keygen --mode <1|2|3> --pub-out <file> --sk-out <file> [--tpm-pub-out <file>]
sign --mode <1|2|3> --sk-in <file> (--message <text> | --message-file <file>) [--sig-out <file>]
verify [--mode <1|2|3>] (--pub-in <raw> | --tpm-pub-in <tpm2b_public>) --sig-in <file> (--message <text> | --message-file <file>)
```

`pqcp_scloud_tool`

```text
keygen --level <128|192|256> --pub-out <file> --sk-out <file> [--tpm-pub-out <file>]
encap [--level <128|192|256>] --pub-in <raw> --cipher-out <file> [--secret-out <file>]
decap [--level <128|192|256>] --sk-in <raw> --cipher-in <file> [--secret-out <file>]
```

互操作说明

- `pqmagic_aigis_tool verify` 可以直接吃 `TPM2B_PUBLIC` 格式公钥，不需要你先手工抽 raw public key。
- `pqcp_scloud_tool keygen --tpm-pub-out` 可以直接导出一个 SCLOUD `TPM2B_PUBLIC` blob，后续可接 `TPM2_LoadExternal` 或 TCM 侧等价路径。
- TPM/TCM demo 里的 `state/scloud.priv` 是 TPM 私有 blob，不是原始 SCLOUD 私钥，不能直接拿给 `pqcp_scloud_tool decap`。

建议的上手顺序

1. 在华为环境先执行 `./build.sh print-config`，确认 SDK 路径、编译器前缀、输出目录都对。
2. 执行 `./build.sh all`，先把三方库和本地工具一起编出来。
3. 用 `pqmagic_aigis_tool` 先走通软件 keygen/sign/verify。
4. 再用 `pqcp_scloud_tool` 走通软件 keygen/encap/decap。
5. 最后把 TCM 侧真实签名、公钥 blob、密文接进来做真互操作。