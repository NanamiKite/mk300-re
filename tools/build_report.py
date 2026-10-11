#!/usr/bin/env python3
"""Render the local firmware analysis as a standalone HTML report."""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'analysis'
EX = OUT / 'extracted'
manifest = json.loads((EX/'manifest.json').read_text())
ccs = json.loads((EX/'midi_cc.json').read_text())
pages = json.loads((EX/'gui_pages.json').read_text())
handlers = json.loads((OUT/'component_handlers.json').read_text())


def esc(value):
    return html.escape(str(value))


def table(headers, rows):
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>'+esc(x)+'</th>' for x in headers) + '</tr></thead><tbody>' + ''.join('<tr>'+''.join('<td>'+esc(x).replace('\n','<br>')+'</td>' for x in row)+'</tr>' for row in rows) + '</tbody></table></div>'


def section(title, content):
    return '<section><h2>'+title+'</h2>'+content+'</section>'


body = '''<h1>MK300 固件操作协议与 GUI 逆向分析</h1>
<p class="lead">本地 <code>MK300.fwsc</code> 是杰理 AC792N 平台的 <strong>MK300_073</strong> 综合效果器固件。
已解开 FWSC 和应用区的混淆，提取主程序，并定位了 42 项 CC 指南记录、12 个组件式 SysEx 处理入口和 12 个具名 GUI 页面描述项。
本地反汇编还确认了 <code>F0 00 59 … F7</code> 组件协议的结构、XOR 校验和主要命令。</p>
<p>分析日期：2026-10-11。原始固件未修改。报告区分三类证据：<b>本地确认</b>（CRC、数据表、反汇编）、<b>外部实测记录</b>（他人的 M-EFCS 抓包）和<b>待实机验证</b>（传输、时序、实际界面响应）。静态解析结果尚未通过设备验证。</p>
<nav><a href="#package">封装</a><a href="#protocol59">组件协议</a><a href="#protocol32">编辑器协议</a><a href="#cc">MIDI CC</a><a href="#gui">GUI</a><a href="#verify">复现与边界</a></nav>'''

body += section('<span id="package">固件封装与存储布局</span>',
    table(['项目','本地结果'], [
        ['原文件',f"{manifest['size']:,} 字节"],['SHA256',manifest['sha256']],
        ['目标芯片 / 架构','AC792N / pi32v2，使用杰理官方 objdump 成功解码'],
        ['版本','MK300_073：app.bin 偏移 0xF8041、0xF9744；系统版本查询引用后者'],
        ['app.bin','1,306,576 字节，CRC16 0xF051；线性代码入口 0x18000120'],
        ['解混淆参数','ENC 多项式 0x1021；头部初值 0xFFFF；应用区 chipkey 0x980F'],
        ['编译配置','Flash 8 MiB，SDRAM/DDR 8 MiB，SYS_CLK=360 MHz，SDRAM_CLK=250 MHz；这些是配置值'],
    ])+'''<p>将文件前 960 字节按 48 字节分组，移除每组末尾 1 字节后，可恢复 UFW 头和目录。
解码头部和各目录条目时，分别重置 ENC 状态。64 字节头和 80 字节目录条目均通过 CRC 校验。
后续文件在 FWSC 中的偏移为 <code>UFW offset + 20</code>。其中 flash.bin 位于 <code>0x414</code>，长度为 <code>0x145000</code>。
应用区位于 flash.bin 的 <code>0x5000</code>，每 32 字节使用密钥 <code>chipkey XOR (区内偏移 &gt;&gt; 2)</code>。
部分升级元数据也按 32 字节分块混淆，但偏移以 UFW 文件为基准，不以应用区为基准。10 个封装条目均通过 CRC 校验。</p>
<p>格式参考 <a href="https://github.com/kagaimiq/jl-misctools/blob/main/firmware/fwunpack_newfw.py">jl-misctools 的作者实现</a>。本目录的独立 Python 脚本还校验了各层 CRC，并导出分析证据。
完整偏移、长度、SHA256 与校验结果见 <a href="extracted/manifest.json">manifest.json</a>。</p>'''+
    table(['封装条目','FWSC 偏移','长度','CRC'], [[e['name'],hex(e['fwsc_offset']),e['size'],'通过'] for e in manifest['container_entries']])+
    '''<p>主程序在应用目录中的偏移为 <code>0x120</code>，换算为 flash.bin 偏移是 <code>0x5120</code>。
本报告按以下公式换算代码地址：<code>运行地址 = app.bin 偏移 + 0x18000120</code>。
合成 ELF 只补入架构、地址和段信息，不含原始符号。</p>
<p>VM、BTIF、SNAPSHOT、GAME、USR 和扩展区 STYLEUSER、DRUMUSER、DRUMNOTE 均有分区条目，但多数分区位于本次升级镜像末端以外。
因此，这份 FWSC 不能用于恢复用户当前预设、完整用户 IR/模型、录音或游戏内容。
<code>DOWNLOAD_MODEL=usb</code> 和 <code>usb_hid_ota.bin</code> 属于升级链。配置中的串口波特率不能直接作为运行时控制协议的依据。</p>''')

operations = [
    ['09','01','00','无','查询版本；回复 payload 为 MK300_073（9 字节）','0x18059268 / 0x18059288'],
    ['09','01','01','无','查询数值版本；本地回复常量 00 07 03','0x1805939E'],
    ['09','01','7F','无','查询系统摘要，8 字节','0x18059358'],
    ['00','01','00','无','读取当前预设位置等 4 字节状态','0x18058FCE / 0x18058FE2'],
    ['00','01','01','无','读取当前预设名称（该分支最多复制前 16 字节）','0x1805919C'],
    ['00','01','7F','无','读取 10 字节预设摘要','0x1805913E'],
    ['01','01','7F','无','读取 11 组模块状态，每组 2 字节，共 22 字节','0x18058526'],
    ['01','00','01','module, model','设置模块模型，先进行合法性检查','0x180584C8'],
    ['01','02','00','module','切换模块开关；ctrl2 在此分支未使用','0x18058560'],
    ['01','03','00','module','显式开启模块；module 0..10','0x18058582'],
    ['01','04','00','module','显式关闭模块；module 0..10','0x18058598'],
    ['02','01','00','module, model, param','读取单个参数，回复带标识和 14 位值','0x18058742'],
    ['02','01','7F','module, model','读取该模块 12 个参数，回复 26 字节；model 必须与当前选择匹配','0x18058796'],
    ['02','00','00','module, model, param, lo7, hi7','写绝对参数；后两字节为有符号 14 位补码','0x18058806'],
    ['02','05 / 06','00','module, model, param','参数加 1 / 减 1，按参数规则钳制','0x18058860 / 0x1805888C'],
    ['03','01','7F','无','读取鼓机状态，6 字节','0x18057C64'],
    ['03','00','01','volume','鼓机音量，钳制至 0..100','0x18057C4E'],
    ['03','00','02','bpm_lo7, bpm_hi7','鼓机 BPM，钳制至 40..240','0x18057D30'],
    ['03','00','04','0 / 非零','鼓机 BPM 跟随开关','0x18057D86'],
    ['04','01','7F','无','读取 Looper 状态，6 字节','0x18057E14'],
    ['04','00','01 / 02','volume','两个 Looper 音量字段，均钳制至 0..100；字段顺序待实机对应 REC/PLAY','0x18057DFE / 0x18057EEC'],
    ['05','01','7F','无','读取调音器状态，6 字节','0x18057FBA'],
    ['06','01','7F','无','读取全局摘要，13 字节；不等同于 M-EFCS 86 字节块','0x180580C0'],
    ['06','00','03','bpm_lo7, bpm_hi7','全局 BPM，40..240','0x180581CA'],
    ['06','00','05','mode 0..2','右声道模式候选；值域与 GUI 一致，具体枚举待收发核对','0x180581E4'],
    ['06','00','06','mode 0..3','USB Audio 模式候选；具体枚举待收发核对','0x180581F2'],
    ['0A','01','7F','snapshot_id','快照查询，ID 0..7，回复 6 字节','0x18058E76'],
]
body += section('<span id="protocol59">本地恢复的组件式 SysEx 协议</span>', '''
<p><b>本地确认。</b>接收解析器位于 <code>0x180521E4</code>，校验函数位于 <code>0x1804168A</code>，发送组帧函数位于 <code>0x1804176E</code>。
代码检查的协议前缀是 <code>00 59</code>，尚不能据此将它认定为标准注册厂商 ID。</p>
<pre>F0 00 59 DEV COMPONENT CTRL1 CTRL2 DATA... XOR F7
XOR = 00 ^ 59 ^ DEV ^ COMPONENT ^ CTRL1 ^ CTRL2 ^ DATA[0] ^ ...</pre>
<p>帧长最少为 9 字节。发送缓存上限为 256 字节，因此 payload 最多为 247 字节。DEV 接受 0 或 1；此解析器不接受 0x7F 作为设备广播号。
COMPONENT 的范围为 0..15，已初始化的组件为 0..11。多字节参数使用两个 7-bit 字节。绝对参数采用有符号 14-bit 编码，与某些相对增量的偏置编码不同，两者不能混用。
CTRL1、CTRL2 的含义取决于组件。通常 CTRL1=1 表示查询，CTRL2=0x7F 表示聚合查询/响应，但不能将它们视为所有组件通用的读写位。</p>
<p>接收器先检查 F0/F7、前缀、XOR、设备号和组件号，再调用处理函数。大多数动作返回内部错误码或更新 GUI 标志。现有证据不足以确认每次写入都会返回统一 ACK。</p>'''+
    table(['组件号','用途','处理函数'], [[f"0x{e['component']:02X}",e['name'],e['address']] for e in handlers])+
    '''<p>0x0B RESOURCE 分支按名称访问有限的资源分区，包含列举、读取、写入和擦除路径。
命令 0x09 的部分分支涉及重启和批量持久化。本分析只生成离线报文，未调用这些动作。
反汇编证据见 <a href="protocol_handlers.asm">protocol_handlers.asm</a>，跳转表见 <a href="jump_tables.json">jump_tables.json</a>。</p>'''+
    table(['组件','CTRL1','CTRL2','DATA','操作与限制','代码证据'], operations)+
    '''<p><b>以下查询样例由静态分析推导，尚未实机验证：</b></p>
<pre>查询固件版本：F0 00 59 01 09 01 00 50 F7
查询所有模块：F0 00 59 01 01 01 7F 27 F7
查询预设摘要：F0 00 59 01 00 01 7F 26 F7
读取鼓机状态：F0 00 59 01 03 01 7F 25 F7
读取 Looper ：F0 00 59 01 04 01 7F 22 F7</pre>
<p>例如，AMP 的模块号为 4，读取参数时还需提供它当前的 model 编号。模块号、模型号和参数序号是三种不同索引，GUI 中的效果链位置也不能作为模块号。</p>''')

body += section('<span id="protocol32">M-EFCS 编辑器的内存块 SysEx 协议</span>', '''
<p><b>外部实测记录。</b>以下字节格式来自 <a href="https://github.com/jpfaria/mvave/blob/main/docs/protocol.md">jpfaria/mvave 的 V73 抓包研究</a>，本地副本为 <a href="sources/community_protocol.md">community_protocol.md</a>。
本次在本地固件中独立核实了预设结构的 448 字节步长、160 个普通预设和 11×12 个参数布局，但尚未独立追踪完整的 <code>00 32</code> 接收路径。</p>
<pre>F0 00 32 CLS CMD[4] 02 FIELD[4] SUB[4] PACK7(payload + ck8) F7
CMD、FIELD、SUB：每字节 7 位、低位先行；SUB = (length &lt;&lt; 4) | space
CLS：09 写，0D 读/数据回复，01 ACK
CMD：41 读；49 写 1 字节；51 写 2 字节
PACK7：连续位流，LSB first（不是每七字节增加一个 MSB 掩码）
ck8 = (0xFB - sum(payload) - sum(FIELD 的四个线缆字节)
       - sum(LE32((length &lt;&lt; 8) | (space &lt;&lt; 4)))) &amp; 0xFF</pre>
<p>空间 0 是预设银行，1 是编辑缓冲，2 是全局/状态，E 是预设加载命令，F 是提交。
参数偏移计算为 <code>0x42 + 24×module + 2×parameter</code>；开关在 <code>0x2B+module</code>，模型在 <code>0x36+module</code>。
修改空间 1 不表示已经保存至预设银行。保存需要写入银行、提交，再回读确认。具体上传流程、时序和 ACK 见原始研究记录。离线工具只处理普通读写编码，未处理模型上传扩展标志。</p>'''+
    table(['预设内偏移','内容','证据'], [
        ['0x00 / 20 字节','名称区域','外部抓包；本地组件名称查询只复制前 16 字节'],
        ['0x18 / u16','预设音量','本地 0x18059076 及外部抓包'],
        ['0x1A / u16','BPM','本地 BPM 钳制 40..240；外部偏移'],
        ['0x1C / i16','Pan','外部抓包'],
        ['0x20 / 11 字节','效果链排序','外部抓包'],
        ['0x2B / 11 字节','模块开关','本地 0x18058494，运行时 +0x258B'],
        ['0x36 / 11 字节','模块模型编号','本地 0x180584E6，运行时 +0x2596'],
        ['0x42 / 264 字节','11 模块 × 12 参数 × i16','本地 0x1805875C / 0x180587D8，运行时 +0x25A2'],
        ['0x14A 起','控制分配等尾部数据','未完整解码'],
    ])+'''<p>本地代码 <code>0x18058F16</code> 对索引 0..159 使用 <code>index×0x1C0</code> 访问普通预设，对 160..167 则转入特殊路径。固件另有 8 个快照槽。
因此，普通预设在界面上应标为 1..160，线缆值为 0..159。此处不采用营销网页中的“200 预设”说法。</p>''')

body += section('<span id="cc">MIDI CC 操作表与文档差异</span>', '''
<p><b>本地确认的是 GUI 指南表。</b>以下 42 项来自固件内的 16 字节记录，每条记录包含 CC 号、标签指针、模式枚举和提示指针。
这些结构化记录比单独的字符串更能支持映射关系，但表中文字仍可能与执行分支不一致。模式名称同样取自固件：Toggle / Momentary / Continuous / Mapped。
完整数据见 <a href="extracted/midi_cc.json">midi_cc.json</a>。</p>
<p>模块 ID 顺序：<code>0 WAH · 1 FX · 2 GATE · 3 DS · 4 AMP · 5 CAB · 6 EQ · 7 MOD · 8 DLY · 9 REV · 10 VOL</code>。
常用 CC 可表达为 <code>B0 CC VALUE</code>，其中 CC 数字为十进制；例如鼓机开始 <code>B0 16 7F</code>，鼓机停止 <code>B0 16 00</code>。</p>'''+
    table(['CC 十进制','标签','模式','固件内提示','app.bin 表偏移'], [[c['cc'],c['label'],c['ui_mode'],c['hint'] or '—',c['offset']] for c in ccs])+
    '''<p><b>需要实机解决的差异：</b>厂商 <a href="https://yms-file-store.oss-cn-hongkong.aliyuncs.com/software/releaseNote/firmware/MK300%20MIDI%E6%96%B0%E5%A2%9E%E6%8E%A7%E5%88%B6%E8%A1%A8.docx">新增 MIDI 控制表</a>
将 CC58/59 的目标模式写为 0..2 / 0..3。本地 GUI 表则将 CC59 输入分为 0–31、32–63、64–95、96–127 四段，将 CC60/61 的 0..127 映射到 0..100%。
CC58 的三段标签为 Disable / Enable / Dry，与本地全局菜单的 Nor / Dry / NoCAB 不一致。这可能是界面文案错误，实际执行映射仍待确认。</p>
<p>官方表使用 B0 作为示例，本地 GUI 中有 <code>Channel: OMNI</code>（app.bin 0xF85FB）。固件是否接受所有输入通道、是否区分 USB 和 DIN，仍需抓包确认。
CC0 表示 Bank Select，不能直接替代 Program Change。超过第 128 个预设时使用的银行/PC 组合也需实测。</p>''')

page_names = {'cc_midi':'MIDI CC 指南','chain':'STOMP / 效果链','change':'预设选择 / 切换相关',
    'ctrl_display':'控制映射概览','ctrl':'控制分配编辑','drum':'鼓机','game':'游戏页面',
    'glob':'全局设置','looper':'循环器','pc_midi':'MIDI PC 映射','save':'保存 / 交换','tuner':'调音器'}
body += section('<span id="gui">设备 GUI 页面与交互模型</span>', '''
<p>GUI 的基本模型是“页面 + 当前预设 + 独立全局状态 + 硬件事件”。本地固件中有 12 个具名页面描述项及函数指针，效果模块另有独立的参数处理代码。
下图根据交互关系重建，不是固件直接渲染的截图。按键入口与面板的关系参照 <a href="sources/MK-300-manual.pdf#page=26">厂商说明书第 26–28 页</a>，主界面示意见 <a href="sources/MK-300-manual.pdf#page=32">第 32 页</a>。</p>
<svg viewBox="0 0 960 330" role="img" aria-label="MK300 页面与状态关系图">
<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0L8 4L0 8" fill="#64748b"/></marker></defs>
<g fill="#eff6ff" stroke="#93c5fd"><rect x="355" y="15" width="250" height="70" rx="12"/>
<rect x="20" y="150" width="170" height="65" rx="10"/><rect x="210" y="150" width="170" height="65" rx="10"/>
<rect x="400" y="150" width="170" height="65" rx="10"/><rect x="590" y="150" width="170" height="65" rx="10"/>
<rect x="780" y="150" width="160" height="65" rx="10"/><rect x="215" y="260" width="530" height="55" rx="10"/></g>
<g fill="none" stroke="#64748b" marker-end="url(#arr)">
<path d="M480 85V115H105V150"/><path d="M480 85V115H295V150"/><path d="M480 85V150"/>
<path d="M480 85V115H675V150"/><path d="M480 85V115H860V150"/><path d="M105 215V287H215"/><path d="M295 215V260"/></g>
<g fill="#0f172a" font-size="17" text-anchor="middle">
<text x="480" y="43">HOME 主界面 / 当前预设</text><text x="480" y="68" font-size="14">预设音量 · BPM · Pan · 控制状态</text>
<text x="105" y="176">STOMP / MODULE</text><text x="105" y="198" font-size="14">顺序 · 开关 · 模型 · 参数</text>
<text x="295" y="176">CTRL</text><text x="295" y="198" font-size="14">踏板 / 旋钮 / 脚钉分配</text>
<text x="485" y="176">DRUM / LOOPER</text><text x="485" y="198" font-size="14">播放 · 录制 · 同步</text>
<text x="675" y="176">TUNER</text><text x="675" y="198" font-size="14">音高 · 校准基准 · 旁路</text>
<text x="860" y="176">GLOBAL</text><text x="860" y="198" font-size="14">I/O · EQ · MIDI · 校准</text>
<text x="480" y="294">编辑缓冲 → SAVE / SWAP → 普通预设 1–160</text></g></svg>
<p>短按 HOME 在主页面与 STOMP 间切换。效果键打开该 MODULE 的参数页，PARA 和三个快调旋钮用于编辑或翻页，CTRL 打开控制映射概览或编辑页。
SAVE 管理预设，GLOB 管理独立的全局设置。这一操作模型与本地分别存在的 MODULE、PARAM、GLOBAL、HW、PRESET 处理入口一致。</p>'''+
    table(['固件页面名','对应功能','名称指针所在偏移','首个候选页面回调'], [[p['name'],page_names.get(p['name'],'待定'),p['name_pointer_offset'],p['callbacks_after_fields'][0]] for p in pages])+
    '''<p>页面名称和地址可直接从固件读取。“首个候选回调”在页面生命周期中的作用尚未完全恢复，不能将它认定为构造函数或完整事件处理函数。
<a href="extracted/gui_pages.json">gui_pages.json</a> 保留了名称前后的全部函数指针和未知结构字段，未给未知字段命名。</p>
<p>本地文案还包含以下操作细节：</p>
<ul><li>CTRL 可分配两个踏板、三个旋钮与四个脚钉；菜单有 Module Ctrl、PreSet±1/±4、Preset Vol±5、Drum Preset±、Pedal A/B、Looper Scr、Drum Scr 等动作。</li>
<li>GLOBAL 内有 Pedal 1/2、Global BPM、Other、BT、EQ、About、MIDI、Diff、Comb Key；本地新增组合键设置不应被旧手册“组合键固定”的描述覆盖。</li>
<li>三步踏板校准依次提示抬起、正常踩下、再用力保持；成功/失败文案和 Knob/Pedal Threshold 均存在。</li>
<li>Other 包含 RCH、USB Audio、BT&amp;USB 音量、USB Rec Vol、输入增益、动画级别等。输入增益文案为 −15..+15 dB；动画有 All / NoSlide / None。</li>
<li>Looper 有 REC、PLAY、DUB、UNDO、REDO、AUTO REC、POS、DRUM SYNC；单次/保持自动录音与同步 1/2 在 CC 表和组件处理函数中都有对应线索。</li>
<li>存在 SnapShot、GAME 分区和 game 页面。NES / nes_player 字符串提供了实现线索，但不能证明所有入口默认可见，也不能证明升级包包含这些资源。</li></ul>
<p>证据主要位于 <a href="extracted/strings.tsv">strings.tsv</a> 的 app.bin 0x107D68–0x1092F0 和 GUI 描述区域 0xE7EC4–0xE8524。
尚未发现可直接作为整屏图使用的 PNG/JPEG 资源，也未确认 GUI 是否使用 LVGL/Qt 等框架。由于未模拟显示驱动，本报告未按像素复原 GUI。</p>''')

body += section('<span id="verify">复现、已做验证与剩余边界</span>', '''
<pre>python3 tools/inspect_fwsc.py MK300.fwsc --out /tmp/mk300-recheck
python3 tools/mk300_protocol.py self-check
python3 tools/mk300_protocol.py version-query
python3 tools/mk300_protocol.py component 1 1 0x7f
python3 tools/mk300_protocol.py efcs-read 1 0 448
python3 tools/mk300_protocol.py cc 22 127</pre>
<p>这些命令只读取文件或打印报文，不向设备发送数据。解包器会拒绝覆盖已有输出目录。
离线自检匹配了 5 条独立公开的 M-EFCS 抓包向量，并检查了组件式版本查询、校验错误拒绝和有符号参数编码。
CRC 检查用于确认解包字节一致性，不能替代硬件行为验证。</p>
<p>完整反汇编见 <a href="app.disassembly.asm.gz">app.disassembly.asm.gz</a>，关键段见 <a href="protocol_handlers.asm">protocol_handlers.asm</a>。
使用 <a href="https://pkgman.jieliapp.com/s/linux-toolchain">杰理官方 Linux 工具链</a>（本次版本 20260730.1）可重建：</p>
<pre>objdump -d -print-imm-hex -no-show-raw-insn analysis/extracted/app.elf</pre>
<p>此处使用厂商工具链中的 objdump。线性反汇编范围包含跳转表、常量和资源区，因此 unknown instruction 不一定表示固件损坏。已解析的关键跳转表另存于 JSON。</p>
<p>仍需实机验证的内容包括：USB/DIN/蓝牙各自使用的协议入口、回复启用条件、实际选用的端点和设备描述符、CC58/59 分段映射、保存时序、模型上传，以及页面能否实际进入。
本地还找到一组 USB 描述符候选值：VID=0x3654、PID=0x7756（app.bin 0xF8C17）。需通过实机枚举确认后，才能用它们过滤设备。</p>
<p>若继续做设备验证，应优先发送组件式版本查询，抓取回复并检查是否为 MK300_073，再读取模块、预设和全局状态。
开发独立控制 GUI 时，应区分当前编辑缓冲、已保存预设、全局设置和异步设备状态，并在切换模型后主动回读参数。</p>''')

page = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MK300 固件操作协议与 GUI 逆向分析</title><style>
*{box-sizing:border-box}body{font:16px/1.7 system-ui,"Noto Sans CJK SC",sans-serif;color:#243247;background:#f4f7fb;margin:0}
main{max-width:1200px;margin:32px auto;padding:36px;background:white;border-radius:12px}h1{font-size:30px;line-height:1.4;color:#102d4e}h2{font-size:23px;color:#173d65;margin:0 0 18px}
section{margin-top:42px;padding-top:28px;border-top:1px solid #dbe4ee}p{margin:14px 0}.lead{font-size:18px}nav{display:flex;flex-wrap:wrap;gap:20px;padding:14px 0}
a{color:#155ca5}code,pre{font-family:ui-monospace,monospace;font-size:14px}code{background:#eef3f9;padding:2px 4px;border-radius:4px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf3fa;padding:18px;border-radius:8px}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;vertical-align:top;border:1px solid #d8e3ef;padding:9px 12px;overflow-wrap:anywhere}th{background:#eaf1f9;color:#173d65}tr:nth-child(even){background:#f8fafc}svg{display:block;width:100%;height:auto;margin:24px 0}li{margin:9px 0}
@media(max-width:700px){main{padding:18px;margin:0}h1{font-size:25px}table{min-width:680px}}@media print{body{background:white}main{margin:0;padding:0;max-width:none}nav{display:none}section{break-before:auto}tr{break-inside:avoid}}
</style><main>'''+body+'</main></html>'
(OUT/'REPORT.html').write_text(page)
print('Written analysis/REPORT.html')
