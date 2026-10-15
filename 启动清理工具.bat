@echo off
chcp 65001 >nul
title 磁盘清理助手
cd /d "%~dp0"
python cleaner.py
pause
