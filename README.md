# MK300 固件逆向

研究 M-VAVE MK300 综合效果器的升级包、控制协议和屏幕交互，为自定义 GUI 和第三方固件开发提供参考。

仓库包含固件解包工具、离线协议工具，以及带地址和反汇编片段的研究记录。可以用它提取应用程序、校验 CRC、查看 GUI 页面描述和 MIDI CC 指南表，也可以生成 SysEx 报文来研究设备控制方式。

目前主要完成了静态分析，还没有可刷入的第三方固件。协议工具只生成或解析字节，不连接设备；文档中的操作也尚未经过本项目的实机收发验证。

## 先试一下协议工具

需要 Python 3，工具只使用标准库。在项目根目录执行：

```sh
python3 tools/mk300_protocol.py version-query
```

输出固件版本查询报文：

```text
F0 00 59 01 09 01 00 50 F7
```

这条命令不需要固件文件，也不会把报文发送给 MK300。查看其他命令：

```sh
python3 tools/mk300_protocol.py --help
```

## 解包并生成报告

自行准备 `MK300.fwsc`，放到项目根目录。现有分析和固定地址以 **MK300_073** 为基准，文件大小和 SHA256 见 [分析入口](analysis/START_HERE.txt)。

```sh
python3 tools/inspect_fwsc.py MK300.fwsc --out analysis/extracted
python3 tools/build_report.py
```

然后用浏览器打开 `analysis/REPORT.html`。报告包含封装与分区布局、两套 SysEx 协议、42 项 CC 指南记录、GUI 页面关系和证据地址。

解包器会拒绝覆盖已有目录。如果 `analysis/extracted` 已有这份固件的解包结果，只需运行第二条命令。另行解包时可用 `--out` 指定新目录，但报告生成脚本固定读取 `analysis/extracted`。

报告中的厂商文档和第三方协议资料需按 [来源清单](analysis/sources/SOURCES.json) 另行下载，放到清单指定的本地位置。解包不需要杰理工具链；生成完整反汇编时才需要，具体命令见分析入口。

## 继续阅读

- [硬件配置与第三方固件可行性](analysis/HARDWARE_FEASIBILITY.txt)：区分固件配置、说明书规格和尚未确认的板级信息。
- [游戏导入的 25 KB 限制](analysis/NES_LIMITS.txt)：记录 NES 加载器、GAME 分区边界和 Mapper 分发的分析。
- [拆解资料](analysis/TEARDOWN_SOURCES.txt)：拆机视频、论坛照片、FCC 档案，以及实际取得了哪些资料。
- [文件索引与复现命令](analysis/START_HERE.txt)：查找反汇编片段、组件入口、跳转表和硬件数据。

Git 保留工具、自写说明、精选反汇编片段、整理后的数据表和来源清单。原厂固件、解包结果、完整反汇编、生成的报告、下载资料和缓存只保存在本地，具体规则见 [.gitignore](.gitignore)。
