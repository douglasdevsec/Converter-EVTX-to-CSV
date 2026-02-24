<p align="center">
  <img src="banner.svg" alt="EVTX-to-CSV" width="900"/>
</p>

<p align="center">
  <b>Convierte archivos de registro de eventos de Windows (<code>.evtx</code>) a CSV.</b><br/>
  Creado por <b>Douglas Puente</b>
</p>

---

## ¿Qué hace esta aplicación?

Los archivos `.evtx` son los registros de eventos de Windows (Event Viewer). Contienen información de seguridad, errores del sistema, inicios de sesión, actividad de red y mucho más. Esta herramienta convierte esos archivos binarios a CSV legible, para que puedas analizarlos en Excel, Python, Splunk, o cualquier herramienta de análisis de datos.

### Campos exportados por evento

| Columna                        | Descripción                                                            |
| ------------------------------ | ---------------------------------------------------------------------- |
| `EventID`                      | ID del evento                                                          |
| `TimeCreated`                  | Fecha y hora UTC del evento                                            |
| `Channel`                      | Canal (Security, System, Application…)                                 |
| `Computer`                     | Nombre del equipo                                                      |
| `Level` / `LevelText`          | Nivel numérico y texto (Critical, Error, Warning…)                     |
| `Provider` / `ProviderGUID`    | Proveedor del evento                                                   |
| `EventRecordID`                | Número de registro único                                               |
| `Task` / `Opcode` / `Keywords` | Clasificación del evento                                               |
| `Correlation_ActivityID`       | ID de actividad correlacionada                                         |
| `ProcessID` / `ThreadID`       | Proceso y hilo generador                                               |
| `UserID`                       | SID del usuario                                                        |
| `EventData`                    | Resumen de todos los datos del evento                                  |
| `Data_*`                       | **Una columna por campo nombrado** (IPs, usuarios, workstations, etc.) |
| `Data_0`, `Data_1`…            | Campos sin nombre, por índice                                          |
| `UD_*`                         | Datos UserData aplanados (eventos de firewall, WFP, etc.)              |
| `UserData_Raw`                 | XML completo de UserData                                               |
| `Binary`                       | Datos binarios en hexadecimal                                          |

> Los eventos de seguridad (canal `Security`) incluyen columnas como `Data_IpAddress`, `Data_TargetUserName`, `Data_WorkstationName`, `Data_LogonType`, etc.

---

## Requisitos

- **Python 3.9+**
- Las dependencias se instalan automáticamente al ejecutar `run.bat`

### Dependencias

```
python-evtx>=0.7.4
lxml>=4.9.0
```

---

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/dp/Converter-EVTX-to-CSV.git
cd Converter-EVTX-to-CSV

# Instalar dependencias
pip install -r requirements.txt
```

---

## Uso

### Modo GUI (recomendado)

Doble clic en `run.bat`, o:

```bash
python evtx_to_csv.py
```

La interfaz permite:

- Seleccionar uno o varios archivos `.evtx`
- O apuntar a una carpeta completa para convertir todos los `.evtx` en ella
- Elegir la carpeta de salida
- Ver el progreso y el log en tiempo real

### Modo CLI (línea de comandos)

```bash
# Convertir un archivo
python evtx_to_csv.py -i Security.evtx -o Security.csv

# Convertir todos los .evtx de una carpeta
python evtx_to_csv.py -i C:\Windows\System32\winevt\Logs -o C:\Output

# Ver ayuda
python evtx_to_csv.py --help
```

---

## Casos de uso

- 🔍 **Análisis forense** — exportar eventos de seguridad para investigar incidentes
- 🛡️ **Auditoría de seguridad** — revisar inicios de sesión, cambios de contraseña, accesos fallidos
- 📊 **SIEM / análisis de datos** — importar a Splunk, Elastic, Excel, Power BI
- 🤖 **Automatización** — usar el modo CLI en scripts de PowerShell o Python

---

## Licencia

MIT — Uso libre con atribución al autor.

---

\*Creado por **Douglas Puente\***
