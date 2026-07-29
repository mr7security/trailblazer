<div align="center">

```
 ████████╗██████╗  █████╗ ██╗██╗     ██████╗ ██╗      █████╗ ███████╗███████╗██████╗
    ██╔══╝██╔══██╗██╔══██╗██║██║     ██╔══██╗██║     ██╔══██╗╚════██║██╔════╝██╔══██╗
    ██║   ██████╔╝███████║██║██║     ██████╔╝██║     ███████║    ██╔╝█████╗  ██████╔╝
    ██║   ██╔══██╗██╔══██║██║██║     ██╔══██╗██║     ██╔══██║   ██╔╝ ██╔══╝  ██╔══██╗
    ██║   ██║  ██║██║  ██║██║███████╗██████╔╝███████╗██║  ██║   ██║  ███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚══════╝╚═╝  ╚═╝
```

**Red Team OPSEC & Forensic Footprint Analyzer**

*¿Cuánta huella forense estás dejando durante tu engagement?*

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square&logo=windows)](https://github.com/mr7security/trailblazer)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-red?style=flat-square)](https://github.com/mr7security/trailblazer/releases)
[![Red Team](https://img.shields.io/badge/Category-Red%20Team-red?style=flat-square)](https://github.com/mr7security/trailblazer)
[![CI](https://img.shields.io/github/actions/workflow/status/mr7security/trailblazer/ci.yml?style=flat-square&label=CI)](https://github.com/mr7security/trailblazer/actions)

</div>

---

## ¿Qué es TrailBlazer?

TrailBlazer es una herramienta de **análisis forense post-explotación** orientada a Red Teams. Su propósito es responder una pregunta crítica durante cualquier engagement:

> *"¿Qué evidencia estoy dejando atrás y cómo la detectaría un Blue Team?"*

Analiza el estado del sistema en tiempo real — procesos, red, usuarios, persistencia y logs de eventos — calcula un **OPSEC Score** y genera un **informe HTML interactivo** con todos los hallazgos clasificados por severidad.

Diseñada tanto para **operadores Red Team** que quieren mejorar su OPSEC, como para **analistas de Incident Response** que necesitan una visión rápida del estado de compromiso de un sistema.

---

## Características

- **5 módulos de análisis** independientes y combinables
- **Cross-platform**: Windows (Event Logs, Registro, Schtasks) y Linux (auth.log, cron, systemd)
- **OPSEC Score 0–100** con recomendaciones por severidad
- **Informe HTML interactivo** con filtros por severidad, dark theme profesional
- **Export JSON** para integración con SIEM o pipelines de análisis
- **Output Rich** en terminal con tablas, colores y barras de progreso
- **Detección de técnicas MITRE ATT&CK**: Process Hollowing, Persistence via Registry, Log Clearing, Lateral Movement, C2 Beaconing...
- Sin dependencias externas pesadas — solo `psutil` + `rich`

---

## Arquitectura

```
trailblazer/
│
├── trailblazer.py              ← CLI principal (argparse)
│
├── core/
│   ├── config.py               ← Constantes, Event IDs, scoring weights
│   └── __init__.py
│
├── collectors/                 ← Módulos de recolección y análisis
│   ├── processes.py            ← Procesos: hollowing, shells, ofensivos
│   ├── network.py              ← Conexiones: C2, puertos sensibles
│   ├── users.py                ← Cuentas, sesiones, grupos privilegiados
│   ├── persistence.py          ← Registro, cron, systemd, ld.so.preload
│   └── eventlogs.py            ← Windows EVTX / Linux auth.log & syslog
│
└── reporters/
    ├── terminal_reporter.py    ← Output Rich (tablas, OPSEC score)
    └── html_reporter.py        ← Informe HTML con filtros interactivos
```

---

## Módulos de Análisis

### `processes` — Análisis de Procesos
Detecta procesos sospechosos comparando nombres, rutas de ejecución y comportamiento:
- Herramientas ofensivas conocidas (mimikatz, meterpreter, netcat...)
- Ejecución desde rutas sospechosas (`/tmp`, `%APPDATA%`, `C:\Temp`)
- PowerShell con flags de evasión (`-enc`, `-nop`, `-bypass`, `-windowstyle hidden`)
- Shells hijas de procesos inusuales (Office, browsers → cmd/bash)
- Process Hollowing: procesos sin ruta de ejecutable resuelta
- Conexiones de red externas desde procesos del sistema

### `network` — Análisis de Red
Mapea el footprint de red del sistema:
- Conexiones a puertos sensibles (4444, 9001, 31337, RDP, WinRM...)
- Procesos inusuales con conexiones externas (C2 / exfiltración)
- Puertos en escucha sin proceso identificado (posibles backdoors)
- Inventario completo de interfaces e IPs

### `users` — Usuarios y Sesiones
Enumera el contexto de identidad del sistema:
- Usuario actual y nivel de privilegios (admin/root)
- Sesiones activas locales y remotas
- Cuentas locales con shell interactiva (Linux)
- Grupos privilegiados y sus miembros (Administrators, sudo, docker, lxd...)

### `persistence` — Mecanismos de Persistencia
Audita todos los puntos de arranque del sistema:

| Windows | Linux |
|---------|-------|
| Registry Run Keys (HKLM/HKCU) | Cron jobs (/etc/cron.*, /var/spool/cron) |
| Scheduled Tasks (schtasks) | Systemd units (incluyendo user-level) |
| Startup Folder | Init scripts (/etc/rc.local, profile.d) |
| Services (sc query) | Shell profiles (.bashrc, .zshrc...) |
| — | /etc/ld.so.preload (rootkit indicator) |

### `eventlogs` — Análisis de Logs
Correlaciona eventos de seguridad en la ventana temporal especificada:

| Event ID | Descripción | Relevancia |
|----------|-------------|------------|
| 4625 | Logon fallido | Brute Force |
| 4688 | Proceso creado | Ejecución de código |
| 4698/4702 | Scheduled Task creada/modificada | Persistencia |
| 4720 | Usuario creado | Backdoor account |
| 4732 | Miembro añadido a Administrators | Escalada |
| 1102 | Audit log limpiado | Anti-Forense |
| 7045 | Nuevo servicio instalado | Persistencia |

---

## Instalación

### Requisitos
- Python 3.8+
- pip

### Windows (PowerShell como Administrador)
```powershell
git clone https://github.com/mr7security/trailblazer.git
cd trailblazer
.\install.bat
```

### Linux / macOS
```bash
git clone https://github.com/mr7security/trailblazer.git
cd trailblazer
chmod +x install.sh && ./install.sh
```

### Manual
```bash
pip install -r requirements.txt
```

---

## Uso

```bash
# Análisis completo del sistema
python trailblazer.py --full-scan

# Análisis completo + informe HTML + JSON
python trailblazer.py --full-scan --output informe.html --json

# Módulos específicos con verbose
python trailblazer.py --modules processes,network,users --verbose

# Análisis de logs de las últimas 48 horas
python trailblazer.py --modules eventlogs --timeframe 48h

# Sin generar informe HTML
python trailblazer.py --full-scan --no-report
```

### Opciones CLI

| Flag | Descripción | Default |
|------|-------------|---------|
| `--full-scan` | Ejecuta todos los módulos | — |
| `--modules` | Módulos separados por coma | — |
| `--output` | Ruta del informe HTML | `trailblazer_YYYYMMDD_HHMMSS.html` |
| `--timeframe` | Ventana temporal para logs | `24h` |
| `--no-report` | Omitir generación de HTML | `False` |
| `--json` | Exportar resultados en JSON | `False` |
| `--verbose` / `-v` | Salida detallada | `False` |

### Timeframes disponibles

`1h` · `6h` · `12h` · `24h` · `48h` · `7d` · `30d`

---

## Output de ejemplo

```
╭─────────────────────────────────────────────────────────────────────────────╮
│   ████████╗██████╗  █████╗ ██╗██╗...                                        │
│   v1.0.0  ·  Red Team OPSEC & Forensic Footprint Analyzer                   │
╰─────────────────────────────────────────────────────────────────────────────╯

  Sistema: Windows 10  Host: DESKTOP-XXXX  Módulos: processes, network, users

══════════════════════════ ▶  PROCESSES ═══════════════════════════════════════
  Procesos totales: 124  Sospechosos: 2

══════════════════════════ 🔎  FINDINGS ════════════════════════════════════════
┌──────────────┬────────────┬───────────────┬──────────────────────────────────┐
│ Sev          │ Módulo     │ Categoría     │ Descripción                      │
├──────────────┼────────────┼───────────────┼──────────────────────────────────┤
│ 💀 CRITICAL  │ processes  │ OPSEC         │ Proceso ofensivo detectado: nc.  │
│ 🔴 HIGH      │ network    │ C2/Exfil      │ powershell.exe → 185.220.x.x:443 │
│ 🟡 MEDIUM    │ users      │ Sessions      │ 2 sesiones activas detectadas    │
└──────────────┴────────────┴───────────────┴──────────────────────────────────┘

══════════════════════════ 🛡  OPSEC SCORE ═════════════════════════════════════
  ████████████████░░░░░░░░░░░░░░░░░░░░░░░░  42/100
  🔴 OPSEC DÉBIL  ·  Risk Score: 58
```

---

## Técnicas MITRE ATT&CK cubiertas

| ID | Técnica | Módulo |
|----|---------|--------|
| T1055 | Process Injection / Hollowing | `processes` |
| T1059 | Command and Scripting Interpreter | `processes` |
| T1053 | Scheduled Task/Job | `persistence`, `eventlogs` |
| T1547 | Boot or Logon Autostart Execution | `persistence` |
| T1071 | Application Layer Protocol (C2) | `network` |
| T1136 | Create Account | `eventlogs` |
| T1070 | Indicator Removal (Log Clearing) | `eventlogs` |
| T1078 | Valid Accounts | `users` |
| T1014 | Rootkit (ld.so.preload) | `persistence` |
| T1021 | Remote Services (RDP/WinRM/SSH) | `network` |

---

## Roadmap

- [ ] Módulo `filesystem` — prefetch, MFT, archivos recientes, temp dirs
- [ ] Módulo `memory` — análisis básico de memoria de procesos
- [ ] Integración con MITRE ATT&CK Navigator (export de capas)
- [ ] Output en formato Markdown para reportes de engagement
- [ ] Modo daemon con alertas en tiempo real
- [ ] Plugin para Sliver / Cobalt Strike (BOF)

---

## Disclaimer

> **USO EXCLUSIVO EN ENTORNOS AUTORIZADOS**
>
> TrailBlazer es una herramienta de **auditoría de seguridad** diseñada para profesionales con autorización explícita sobre los sistemas analizados. Su uso en sistemas sin autorización puede constituir un delito según la legislación vigente.
>
> El autor no se responsabiliza del uso indebido de esta herramienta. **Hackea solo lo que te pertenece o para lo que tengas permiso escrito.**

---

## Autor

**Miguel R.** — Red & Blue Team Security Researcher

[![GitHub](https://img.shields.io/badge/GitHub-mr7security-black?style=flat-square&logo=github)](https://github.com/mr7security)

---

<div align="center">
<sub>Si esta herramienta te resulta útil, dale una ⭐ — ayuda a que más gente la encuentre.</sub>
</div>
