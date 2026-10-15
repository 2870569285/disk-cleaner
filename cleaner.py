# -*- coding: utf-8 -*-
"""
C盘清理助手 - 本地可视化清理工具
安全机制：删除目标仅限下方 WHITELIST 白名单中的路径，接口不接受任意路径。
用法：python cleaner.py  （自动打开浏览器）
"""
import os, sys, json, shutil, socket, threading, traceback, webbrowser, ctypes, datetime
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ============ 配置 ============
PORT = 8795
USER = os.path.expanduser("~")
LOCAL = os.path.join(USER, "AppData", "Local")

def P(*parts):
    return os.path.join(*parts)

# 白名单：id -> {label, desc, level, paths}
# level: safe=安全 | warn=注意（建议先关闭相关程序） | care=谨慎
WHITELIST = {
    "user_temp": {"label": "用户临时文件", "level": "safe",
        "desc": "程序运行产生的临时文件，正在使用的文件会自动跳过",
        "paths": [P(LOCAL, "Temp")]},
    "sys_temp": {"label": "系统临时文件", "level": "safe",
        "desc": "Windows 系统临时目录，正在使用的文件会自动跳过",
        "paths": [r"C:\Windows\Temp"]},
    "wu_cache": {"label": "Windows 更新下载缓存", "level": "safe",
        "desc": "已安装更新的安装包残留，更新已装到系统里，删后不影响使用",
        "paths": [r"C:\Windows\SoftwareDistribution\Download"]},
    "do_cache": {"label": "传递优化缓存", "level": "safe",
        "desc": "Windows 更新分发的 P2P 缓存，删除后不影响系统更新",
        "paths": [r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"]},
    "dumps": {"label": "崩溃转储 / 内存转储", "level": "safe",
        "desc": "程序或蓝屏崩溃时的诊断转储文件，仅用于排查问题，日常无用",
        "paths": [r"C:\Windows\Minidump", r"C:\Windows\MEMORY.DMP", P(LOCAL, "CrashDumps")]},
    "wer": {"label": "Windows 错误报告", "level": "safe",
        "desc": "程序出错时上报的诊断记录，无日常用途",
        "paths": [r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
                  r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
                  P(LOCAL, "Microsoft", "Windows", "WER")]},
    "cbs_logs": {"label": "系统更新日志 (CBS)", "level": "safe",
        "desc": "Windows 更新过程日志，删除后系统按需重建",
        "paths": [r"C:\Windows\Logs\CBS"]},
    "d3dscache": {"label": "DirectX 着色器缓存", "level": "safe",
        "desc": "显卡着色器缓存，删除后首次打开游戏/应用会自动重建",
        "paths": [P(LOCAL, "D3DSCache")]},
    "thumbnails": {"label": "缩略图 / 图标缓存", "level": "safe",
        "desc": "文件缩略图缓存，删除后系统自动重建，正在被占用的会跳过",
        "paths": [P(LOCAL, "Microsoft", "Windows", "Explorer")]},
    "pip_cache": {"label": "pip 下载缓存", "level": "safe",
        "desc": "Python 包管理器缓存，删除后安装包需重新联网下载",
        "paths": [P(LOCAL, "pip", "cache")]},
    "npm_cache": {"label": "npm 缓存", "level": "safe",
        "desc": "Node.js 包管理器缓存，删除后安装包需重新联网下载",
        "paths": [P(LOCAL, "npm-cache"), P(USER, ".npm")]},
    "inetcache": {"label": "系统网络缓存 (INetCache)", "level": "safe",
        "desc": "Windows 系统组件的联网缓存，无保留价值",
        "paths": [P(LOCAL, "Microsoft", "Windows", "INetCache")]},
    "chrome_cache": {"label": "Chrome 浏览器缓存", "level": "warn",
        "desc": "网页缓存文件，建议先关闭 Chrome 再清理（不影响密码/历史/书签）",
        "paths": [P(LOCAL, "Google", "Chrome", "User Data", "Default", "Cache"),
                  P(LOCAL, "Google", "Chrome", "User Data", "Default", "Code Cache")]},
    "edge_cache": {"label": "Edge 浏览器缓存", "level": "warn",
        "desc": "网页缓存文件，建议先关闭 Edge 再清理（不影响密码/历史/书签）",
        "paths": [P(LOCAL, "Microsoft", "Edge", "User Data", "Default", "Cache"),
                  P(LOCAL, "Microsoft", "Edge", "User Data", "Default", "Code Cache")]},
    "recyclebin": {"label": "回收站", "level": "care",
        "desc": "清空前请确认没有需要恢复的文件，清空后无法找回",
        "paths": [r"C:\$Recycle.Bin"]},
}

# Windows.old 存在时才出现（回退旧系统的备份，谨慎）
OLD = r"C:\Windows.old"
if os.path.exists(OLD):
    WHITELIST["windows_old"] = {"label": "Windows.old 旧系统备份", "level": "care",
        "desc": "重装/升级系统后的备份。删除后将无法回退到旧系统，请确认不需要后再清理",
        "paths": [OLD]}

# 不允许清理整个目录本身的类别（只清内容，保留目录结构）
KEEP_DIR_ONLY = {"user_temp", "sys_temp", "wu_cache", "do_cache", "wer", "cbs_logs",
                 "thumbnails", "recyclebin", "d3dscache", "inetcache", "drive_temp"}

SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:").rstrip(":\\").upper()

def fixed_drives():
    """枚举本地固定磁盘盘符（大写字母列表）"""
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    out = []
    for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        if bitmask & (1 << i):
            try:
                if ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:\\") == 3:  # DRIVE_FIXED
                    out.append(letter)
            except OSError:
                pass
    return out

def build_targets(drive=None):
    """按盘符生成该盘可清理目标（白名单的一部分，接口只接受这里定义的ID）"""
    drive = (drive or SYSTEM_DRIVE).upper()
    if drive == SYSTEM_DRIVE:
        return dict(WHITELIST)  # 系统盘使用完整白名单
    root = f"{drive}:\\"
    t = {}
    rb = os.path.join(root, "$Recycle.Bin")
    if os.path.exists(rb):
        t["recyclebin"] = {"label": f"{drive}盘回收站", "level": "care",
            "desc": "该盘回收站中的已删除文件，清空前请确认没有需要恢复的文件，清空后无法找回",
            "paths": [rb]}
    wo = os.path.join(root, "Windows.old")
    if os.path.exists(wo):
        t["windows_old"] = {"label": f"{drive}盘 Windows.old 旧系统备份", "level": "care",
            "desc": "旧系统备份，删除后无法回退，请确认不需要后再清理",
            "paths": [wo]}
    temps, seen = [], set()
    for n in ("Temp", "tmp", "temp"):
        p = os.path.join(root, n)
        if os.path.isdir(p) and p.lower() not in seen:
            seen.add(p.lower()); temps.append(p)
    if temps:
        t["drive_temp"] = {"label": f"{drive}盘根目录临时文件夹", "level": "care",
            "desc": "该盘根目录下的 Temp/tmp 文件夹。若你自行在其中存放过重要文件，请勿清理",
            "paths": temps}
    return t

# ============ 工具函数 ============
def dir_stats(path):
    total, count = 0, 0
    if os.path.isfile(path):
        try: return os.path.getsize(path), 1
        except OSError: return 0, 0
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f)); count += 1
            except OSError:
                pass
    return total, count

def _uniq_dest(bdir, name):
    """备份目标重名时追加序号，避免覆盖"""
    dest = os.path.join(bdir, name)
    if not os.path.exists(dest):
        return dest
    base, ext = os.path.splitext(name)
    i = 1
    while True:
        dest = os.path.join(bdir, f"{base}({i}){ext}")
        if not os.path.exists(dest):
            return dest
        i += 1

def delete_path(p, keep_dir, backup_dir=None):
    """删除文件或目录（backup_dir 提供时先移动备份再删除），返回 (释放字节, 失败数, 失败样本列表)"""
    freed, failed, samples = 0, 0, []
    if os.path.isfile(p):
        try:
            sz = os.path.getsize(p)
            if backup_dir:
                shutil.move(p, _uniq_dest(backup_dir, os.path.basename(p)))
            else:
                os.remove(p)
            return sz, 0, []
        except OSError as e:
            return 0, 1, [str(e)]
    try:
        names = os.listdir(p)
    except OSError:
        return 0, 0, []
    for n in names:
        child = os.path.join(p, n)
        try:
            if backup_dir:
                sz, _ = dir_stats(child)
                shutil.move(child, _uniq_dest(backup_dir, n))
                freed += sz
                continue
            if os.path.isdir(child) and not os.path.islink(child):
                sz, _ = dir_stats(child)
                if keep_dir:
                    # 递归删除子项内容
                    f2, d2, s2 = delete_path(child, keep_dir)
                    freed += f2; failed += d2; samples += s2
                    if d2 == 0:
                        try: os.rmdir(child)
                        except OSError: pass
                else:
                    shutil.rmtree(child, ignore_errors=False)
                    freed += sz
            else:
                sz = os.path.getsize(child)
                os.remove(child)
                freed += sz
        except OSError as e:
            failed += 1
            if len(samples) < 5: samples.append(f"{n}: {e.strerror or e}")
    return freed, failed, samples

def do_scan(drive=None):
    targets = build_targets(drive)
    items = []
    for tid, meta in targets.items():
        size, files = 0, 0
        paths_present = []
        for p in meta["paths"]:
            if os.path.exists(p):
                paths_present.append(p)
                s, c = dir_stats(p)
                size += s; files += c
        items.append({"id": tid, "label": meta["label"], "desc": meta["desc"],
                      "level": meta["level"], "size": size, "files": files,
                      "paths": paths_present})
    items.sort(key=lambda x: -x["size"])
    return items

# ============ HTTP 服务 ============
HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>磁盘清理助手</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--line:#e4e8ef;--txt:#24292f;--sub:#6a737d;
--blue:#2563eb;--green:#16a34a;--orange:#d97706;--red:#dc2626;--hover:#f0f4fa}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Microsoft YaHei",system-ui,sans-serif;background:var(--bg);color:var(--txt);font-size:14px}
.wrap{max-width:1080px;margin:0 auto;padding:16px 20px 40px}
h1{font-size:20px;font-weight:700}
.bar{display:flex;align-items:center;gap:14px;margin-bottom:12px}
.bar h1{margin-right:auto}
button{font-family:inherit;cursor:pointer;border:1px solid var(--line);background:#fff;border-radius:6px;padding:6px 14px;font-size:13px}
button:hover{background:var(--hover)}
button:disabled{opacity:.5;cursor:not-allowed}
.btn-primary{background:var(--blue);border-color:var(--blue);color:#fff;font-weight:600}
.btn-primary:hover{background:#1d4fd8}
.btn-danger{background:var(--red);border-color:var(--red);color:#fff;font-weight:600}
.btn-danger:hover{background:#b91c1c}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}
.diskrow{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.diskbar{flex:1;min-width:220px;height:10px;background:#e8ecf2;border-radius:5px;overflow:hidden}
.diskbar i{display:block;height:100%;background:linear-gradient(90deg,#60a5fa,#2563eb);border-radius:5px}
.muted{color:var(--sub);font-size:12px}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.stat{flex:1;min-width:150px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.stat b{font-size:20px;display:block}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}
th{font-size:12px;color:var(--sub);font-weight:600;background:#fafbfc;white-space:nowrap}
th.c,td.c{text-align:center}
th.r,td.r{text-align:right;white-space:nowrap}
tbody tr:hover{background:var(--hover)}
tbody tr.disabled{color:#b6bcc6}
.name{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.name span{font-weight:400;color:var(--sub);font-size:12px}
.tip{position:relative}
.tip:hover::after{content:attr(data-tip);position:absolute;left:0;top:100%;z-index:30;background:#1f2937;color:#fff;
padding:8px 10px;border-radius:6px;font-size:12px;font-weight:400;white-space:normal;width:420px;box-shadow:0 4px 14px rgba(0,0,0,.25)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;white-space:nowrap}
.lv-safe{background:#dcfce7;color:#15803d}
.lv-warn{background:#fef3c7;color:#b45309}
.lv-care{background:#fee2e2;color:#b91c1c}
input[type=checkbox]{width:16px;height:16px;cursor:pointer;vertical-align:middle}
.accent{color:var(--blue);font-weight:600}
.warnbox{background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:10px 14px;margin-bottom:12px;font-size:13px;line-height:1.6}
.modal-mask{display:none;position:fixed;inset:0;background:rgba(15,23,42,.45);z-index:50;align-items:center;justify-content:center}
.modal{background:#fff;border-radius:12px;max-width:520px;width:92%;max-height:80vh;overflow:auto;padding:20px 22px}
.modal h3{margin-bottom:10px}
.modal li{margin:4px 0 4px 20px;line-height:1.5}
.modal .acts{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
#result{display:none}
#result.ok{display:block}
.flash{animation:fl .8s}
@keyframes fl{0%{background:#dcfce7}100%{background:transparent}}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #cbd5e1;border-top-color:var(--blue);border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px;margin-right:6px}
@keyframes sp{to{transform:rotate(360deg)}}
.empty{color:var(--sub);text-align:center;padding:30px 0}
.errbox{background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:8px 12px;margin-top:10px;font-size:12px;color:#991b1b;display:none;white-space:pre-wrap;max-height:180px;overflow:auto}
.backuprow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.backuprow label{display:flex;align-items:center;gap:6px;cursor:pointer;white-space:nowrap;font-weight:600}
.backuprow input[type=text]{flex:1;min-width:200px;max-width:340px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;font-family:inherit;font-size:13px}
.backuprow input[type=text]:disabled{background:#f6f7f9;color:#b6bcc6}
</style>
</head>
<body>
<div class="wrap">
  <div class="bar">
    <h1>磁盘清理助手</h1>
    <select id="driveSel" style="padding:6px 10px;border:1px solid var(--line);border-radius:6px;font-family:inherit;font-size:13px"></select>
    <span class="muted" id="scanstate"></span>
    <button id="btnRescan">重新扫描</button>
    <button id="btnFull">全屏显示</button>
  </div>

  <div class="card diskrow">
    <b id="disklabel">C盘空间</b>
    <div class="diskbar"><i id="usedbar"></i></div>
    <span class="muted" id="disktext"></span>
  </div>

  <div class="warnbox">
    安全说明：本工具只能清理下方白名单内的缓存与垃圾文件，不涉及系统文件、程序和文档。
    清理缓存不会删除软件本身、账号数据或个人文件；标注「注意」的项目建议先关闭对应程序，被占用的文件会自动跳过。
    提示：部分安全软件会把删除的文件转入回收站兜底，此时需再清空回收站才真正释放空间；清空回收站前请先确认无需恢复其中的文件。
  </div>

  <div class="stats">
    <div class="stat"><span class="muted">可清理总量</span><b id="stTotal">-</b></div>
    <div class="stat"><span class="muted">已选中</span><b id="stSel" style="color:var(--blue)">0 B</b></div>
    <div class="stat" style="display:flex;align-items:center;gap:8px">
      <button id="btnSafeAll">全选安全项</button>
      <button id="btnNone">取消全选</button>
    </div>
  </div>

  <div class="card" style="padding:0">
    <table>
      <thead><tr>
        <th style="width:36px"><input type="checkbox" id="chkAll"></th>
        <th>项目</th>
        <th class="c">文件数</th>
        <th class="r">大小</th>
      </tr></thead>
      <tbody id="tbody"><tr><td colspan="4" class="empty"><span class="spin"></span>正在扫描...</td></tr></tbody>
    </table>
  </div>

  <div class="card backuprow">
    <label><input type="checkbox" id="chkBackup">删除前备份到其他盘</label>
    <input type="text" id="backupPath" placeholder="例如 D:\\清理备份" disabled>
    <span class="muted">备份所在盘不能与正在清理的盘相同；空间不足的项目会自动跳过，旧备份请自行管理删除</span>
  </div>

  <div style="display:flex;align-items:center;gap:14px;margin-top:4px">
    <button class="btn-danger" id="btnDel" disabled>删除选中项</button>
    <span class="muted" id="delhint"></span>
  </div>

  <div class="card" id="result">
    <b id="restitle"></b>
    <div class="muted" id="resdetail" style="margin-top:6px"></div>
    <div class="errbox" id="reserr"></div>
  </div>
</div>

<div class="modal-mask" id="mask">
  <div class="modal">
    <h3>确认清理</h3>
    <div id="mbody" style="line-height:1.7"></div>
    <div class="acts">
      <button id="mCancel">取消</button>
      <button class="btn-primary" id="mOk">开始清理</button>
    </div>
  </div>
</div>

<script>
const LEVEL={safe:["安全","lv-safe"],warn:["注意","lv-warn"],care:["谨慎","lv-care"]};
let DATA=[],SEL=new Set(),FREE_BEFORE=0,DRIVES=[],DRIVE="C";
const fmt=b=>{if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";
if(b<1073741824)return (b/1048576).toFixed(1)+" MB";return (b/1073741824).toFixed(2)+" GB"};
const $=id=>document.getElementById(id);

async function loadDisk(){$("disklabel").textContent=DRIVE+"盘空间";$("disktext").textContent="读取中...";
try{const r=await fetch("/api/disk?drive="+DRIVE);const d=await r.json();
$("usedbar").style.width=(d.used/d.total*100).toFixed(1)+"%";
$("disktext").textContent=`已用 ${fmt(d.used)} / 总 ${fmt(d.total)}，剩余 ${fmt(d.free)}`;
FREE_BEFORE=d.free}catch(e){$("disktext").textContent="读取失败"}}

async function loadScan(){
$("scanstate").innerHTML='<span class="spin"></span>扫描中';
$("stTotal").textContent="-";
try{const r=await fetch("/api/scan?drive="+DRIVE);DATA=await r.json();render();calcTotals()}
catch(e){$("tbody").innerHTML='<tr><td colspan="4" class="empty">扫描失败，请点击「重新扫描」</td></tr>'}
$("scanstate").textContent="扫描完成 "+new Date().toLocaleTimeString();}

async function loadDrives(){try{const r=await fetch("/api/drives");DRIVES=await r.json();
$("driveSel").innerHTML=DRIVES.map(d=>`<option value="${d.letter}"${d.letter===DRIVE?" selected":""}>${d.letter}盘（剩 ${fmt(d.free)}）</option>`).join("");
if(!DRIVES.some(d=>d.letter===DRIVE)&&DRIVES.length){DRIVE=DRIVES[0].letter;$("driveSel").value=DRIVE;loadDisk();loadScan()}}catch(e){}}

function render(){
const tb=$("tbody");
if(!DATA.length){tb.innerHTML='<tr><td colspan="4" class="empty">没有找到可清理的项目</td></tr>';return}
tb.innerHTML=DATA.map(it=>{
 const dis=it.size===0&&it.files===0;
 const paths=(it.paths||[]).join("；")||"（目录不存在）";
 const lv=LEVEL[it.level]||LEVEL.safe;
 return `<tr class="${dis?'disabled':''}" data-id="${it.id}">
  <td><input type="checkbox" class="chk" data-id="${it.id}" data-size="${it.size}" ${dis||it.size===0?'disabled':''}></td>
  <td><div class="name tip" data-tip="${it.label}：${paths.replace(/"/g,'')}">${it.label} <span class="badge ${lv[1]}">${lv[0]}</span></div>
      <div class="muted" style="max-width:420px;white-space:normal">${it.desc}</div></td>
  <td class="c">${it.files.toLocaleString()}</td>
  <td class="r"><b>${fmt(it.size)}</b></td></tr>`}).join("");
tb.querySelectorAll(".chk").forEach(c=>c.addEventListener("change",()=>{
 c.checked?SEL.add(c.dataset.id):SEL.delete(c.dataset.id);updateUI()}));
}

function calcTotals(){
const total=DATA.reduce((s,i)=>s+i.size,0);
$("stTotal").textContent=fmt(total);
const has=DATA.some(i=>i.size>0);
if(!has)$("tbody").innerHTML='<tr><td colspan="4" class="empty">没有发现可清理的垃圾数据</td></tr>';}

function selSize(){let s=0;SEL.forEach(id=>{const it=DATA.find(d=>d.id===id);if(it)s+=it.size});return s}
function updateUI(){
$("stSel").textContent=fmt(selSize());
$("btnDel").disabled=SEL.size===0;
$("chkAll").checked=DATA.length>0&&SEL.size===DATA.filter(i=>i.size>0).length;}

$("chkAll").addEventListener("change",()=>{
SEL.clear();
if($("chkAll").checked)DATA.forEach(i=>{if(i.size>0)SEL.add(i.id)});
$("tbody").querySelectorAll(".chk").forEach(c=>c.checked=SEL.has(c.dataset.id));updateUI()});
$("btnSafeAll").addEventListener("click",()=>{
SEL.clear();DATA.forEach(i=>{if(i.size>0&&i.level==="safe")SEL.add(i.id)});
$("tbody").querySelectorAll(".chk").forEach(c=>c.checked=SEL.has(c.dataset.id));updateUI()});
$("btnNone").addEventListener("click",()=>{SEL.clear();
$("tbody").querySelectorAll(".chk").forEach(c=>c.checked=false);updateUI()});
$("btnRescan").addEventListener("click",()=>{SEL.clear();loadScan();loadDisk()});
$("driveSel").addEventListener("change",()=>{DRIVE=$("driveSel").value;SEL.clear();
$("tbody").innerHTML='<tr><td colspan="4" class="empty"><span class="spin"></span>正在扫描...</td></tr>';
loadDisk();loadScan()});
$("chkBackup").addEventListener("change",()=>{
$("backupPath").disabled=!$("chkBackup").checked;
if($("chkBackup").checked&&!$("backupPath").value.trim()){
const other=DRIVES.find(d=>d.letter!==DRIVE);
if(other)$("backupPath").value=other.letter+":\\\\清理备份";}});

$("btnDel").addEventListener("click",()=>{
const items=DATA.filter(i=>SEL.has(i.id));
const care=items.filter(i=>i.level==="care"),warn=items.filter(i=>i.level==="warn");
const bk=$("chkBackup").checked;
$("mbody").innerHTML=`<p>即将清理以下 <b>${items.length}</b> 项，共 <b class="accent">${fmt(selSize())}</b>：</p>
<ul>${items.map(i=>`<li><b>${i.label}</b>（${fmt(i.size)}）</li>`).join("")}</ul>
${bk?`<p class="accent">备份已开启：删除前先移动到 <b>${$("backupPath").value.trim()||"（未填写路径）"}</b>，确认无误后可自行删除旧备份。</p>`:""}
${care.length?'<p style="color:var(--red)">警告：包含「谨慎」级项目，删除后不可恢复！</p>':""}
${warn.length?'<p style="color:var(--orange)">提醒：包含「注意」级项目，建议已关闭对应浏览器；被占用文件会自动跳过。</p>':""}
<p class="muted">清理完成后会显示实际释放的空间。</p>`;
$("mask").style.display="flex";});

$("mCancel").addEventListener("click",()=>$("mask").style.display="none");
$("mOk").addEventListener("click",doDelete);
async function doDelete(){
$("mask").style.display="none";
$("btnDel").disabled=true;$("btnDel").innerHTML='<span class="spin"></span>清理中...';
const ids=[...SEL];
const bk=$("chkBackup").checked;
$("delhint").innerHTML='<span class="spin"></span>正在清理，请稍候（文件多时需要几分钟，开启备份时更久）...';
try{const r=await fetch("/api/delete",{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({ids,drive:DRIVE,backup:{enabled:bk,path:$("backupPath").value.trim()}})});
const res=await r.json();
if(res.error)throw new Error(res.error.split("\\n")[0]);
const after=await (await fetch("/api/disk?drive="+DRIVE)).json();
const gained=after.free-FREE_BEFORE;
$("restitle").innerHTML=`清理完成，实际释放 <span class="accent">${fmt(gained>0?gained:res.freed)}</span>（统计含系统占用波动）`;
let det=`已删除 ${res.freed_fmt}，失败跳过 ${res.failed} 个文件（多为正在使用中的文件，属正常现象）`;
if(res.backup_path)det+=`；已备份到 ${res.backup_path}`;
if(res.skipped_backup&&res.skipped_backup.length)det+=`；${res.skipped_backup.length} 项因备份盘空间不足被跳过：`+res.skipped_backup.map(s=>s.label).join("、");
$("resdetail").textContent=det;
$("reserr").style.display=res.samples.length?"block":"none";
$("reserr").textContent=res.samples.length?"跳过示例：\\n"+res.samples.join("\\n"):"";
$("result").classList.add("ok");$("result").classList.add("flash");
SEL.clear();await loadScan();loadDisk();
}catch(e){$("restitle").textContent="清理请求失败："+e.message;$("result").classList.add("ok")}
$("delhint").textContent="";$("btnDel").textContent="删除选中项";updateUI();}

// 全屏（ESC 或再次点击退出）
$("btnFull").addEventListener("click",()=>{
if(document.fullscreenElement){document.exitFullscreen()}
else{document.documentElement.requestFullscreen().catch(()=>{})}});
document.addEventListener("fullscreenchange",()=>{
$("btnFull").textContent=document.fullscreenElement?"退出全屏（ESC）":"全屏显示"});

loadDrives();loadDisk();loadScan();
</script>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        drive = (q.get("drive", [SYSTEM_DRIVE])[0] or SYSTEM_DRIVE).rstrip(":\\").upper()
        if u.path == "/":
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/api/drives":
            out = []
            for L in fixed_drives():
                try:
                    du = shutil.disk_usage(f"{L}:\\")
                    out.append({"letter": L, "free": du.free, "total": du.total})
                except OSError:
                    pass
            self._json(out)
        elif u.path == "/api/disk":
            try:
                du = shutil.disk_usage(f"{drive}:\\")
                self._json({"total": du.total, "used": du.used, "free": du.free})
            except OSError:
                self._json({"error": f"无法读取 {drive} 盘"}, 400)
        elif u.path == "/api/scan":
            try:
                self._json(do_scan(drive))
            except Exception:
                self._json({"error": traceback.format_exc()}, 500)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path != "/api/delete":
            self.send_response(404); self.end_headers(); return
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n).decode("utf-8"))
            ids = req.get("ids", [])
            drive = (req.get("drive") or SYSTEM_DRIVE).rstrip(":\\").upper()
            targets = build_targets(drive)  # 只允许该盘白名单ID，不接收任意路径
            backup = req.get("backup") or {}
            backup_root, skipped_backup = None, []
            if backup.get("enabled"):
                bp = (backup.get("path") or "").strip().strip('"')
                if not os.path.isabs(bp):
                    raise ValueError("备份路径必须是绝对路径，如 D:\\清理备份")
                bdrive = os.path.splitdrive(bp)[0].rstrip(":").upper()
                if bdrive == drive:
                    raise ValueError("备份路径不能与正在清理的盘相同，请选择其他盘")
                if not os.path.splitdrive(bp)[1].strip("\\/"):
                    raise ValueError("备份路径不能是盘符根目录，请指定一个文件夹")
                try:
                    os.makedirs(bp, exist_ok=True)
                except OSError as e:
                    raise ValueError(
                        f"无法创建备份文件夹 {bp}（{e.strerror}）。"
                        "可能是安全软件拦截或权限不足：可更换备份路径重试，"
                        "或取消勾选备份直接清理（被删文件通常会被转入回收站兜底）")
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_root = os.path.join(bp, f"清理备份_{ts}")
                i = 1
                while os.path.exists(backup_root):
                    backup_root = os.path.join(bp, f"清理备份_{ts}({i})"); i += 1
                os.makedirs(backup_root)
            total_freed, total_failed, all_samples = 0, 0, []
            for tid in ids:
                meta = targets.get(tid)
                if not meta:
                    continue
                keep = tid in KEEP_DIR_ONLY
                bdir = None
                if backup_root:
                    # 备份空间预检：不足时整项跳过，避免备份到一半失败
                    tsize = sum(dir_stats(p)[0] for p in meta["paths"] if os.path.exists(p))
                    bfree = shutil.disk_usage(backup_root).free
                    if tsize > bfree - 512 * 1024 * 1024:  # 预留512MB余量
                        skipped_backup.append({"id": tid, "label": meta["label"],
                                               "need": tsize, "free": bfree})
                        continue
                    bdir = os.path.join(backup_root, tid)
                    os.makedirs(bdir, exist_ok=True)
                for p in meta["paths"]:
                    if os.path.exists(p):
                        f, d, s = delete_path(p, keep, bdir)
                        total_freed += f; total_failed += d
                        all_samples += s
            resp = {"freed": total_freed,
                    "freed_fmt": f"{total_freed/1024/1024:.1f} MB",
                    "failed": total_failed, "samples": all_samples,
                    "skipped_backup": skipped_backup}
            if backup_root:
                resp["backup_path"] = backup_root
            self._json(resp)
        except (ValueError, OSError) as e:
            self._json({"error": str(e)}, 400)
        except Exception:
            self._json({"error": traceback.format_exc()}, 500)

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"磁盘清理助手已启动: {url}  (Ctrl+C 停止)")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")

if __name__ == "__main__":
    main()
