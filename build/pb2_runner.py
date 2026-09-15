# -*- coding: utf-8 -*-
"""Обёртка для сборки автономного pb2.exe (ProxyBroker2) через PyInstaller."""
import sys

from proxybroker2.cli import cli

if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))