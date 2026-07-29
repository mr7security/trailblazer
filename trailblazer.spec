# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec para TrailBlazer
# Genera: dist/TrailBlazer.exe  (Windows)  o  dist/TrailBlazer  (Linux)
#
# Uso:
#   pyinstaller trailblazer.spec

from PyInstaller.building.build_main import Analysis, PYZ, EXE

block_cipher = None

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Entry point
        'trailblazer',
        # Collectors (importados dinámicamente con importlib)
        'collectors.processes',
        'collectors.network',
        'collectors.users',
        'collectors.persistence',
        'collectors.eventlogs',
        'collectors.filesystem',
        'collectors.credentials',
        'collectors.wmi',
        'collectors.antivirus',
        'collectors.enrichment',
        # Core
        'core.config',
        'core.mitre',
        'core.baseline',
        # Reporters
        'reporters.terminal_reporter',
        'reporters.html_reporter',
        # Dependencias de rich
        'rich',
        'rich.console',
        'rich.panel',
        'rich.table',
        'rich.text',
        'rich.rule',
        'rich.columns',
        'rich.prompt',
        'rich.progress',
        # psutil
        'psutil',
        'psutil._pswindows',
        'psutil._pslinux',
        # Stdlib usadas en collectors
        'winreg',
        'subprocess',
        'hashlib',
        'urllib.request',
        'urllib.error',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'PIL', 'cv2', 'scipy', 'sklearn',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='TrailBlazer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # compresión UPX si está instalado
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # ventana de consola — esencial para herramienta CLI
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,          # puedes añadir: icon='assets/trailblazer.ico'
)
