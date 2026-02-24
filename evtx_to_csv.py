#!/usr/bin/env python3
"""
EVTX to CSV Converter
Convierte archivos de registro de eventos de Windows (.evtx) a CSV.
Soporta modo GUI y modo CLI.

Creado por: Douglas Puente

Uso (GUI):  python evtx_to_csv.py
Uso (CLI):  python evtx_to_csv.py -i Security.evtx -o Security.csv
            python evtx_to_csv.py -i Logs -o Output   (carpeta completa)
"""

from __future__ import annotations

import argparse
import csv
import sys
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Iterator, Callable, Optional

AUTOR   = "Douglas Puente"
VERSION = "1.0.0"

# ──────────────────────────────────────────────
# Lógica de parsing (usada por GUI y CLI)
# ──────────────────────────────────────────────
LEVEL_MAP = {
    "0": "Information",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}

BASE_FIELDS = [
    "EventID",
    "EventIDQualifiers",
    "Version",
    "TimeCreated",
    "Channel",
    "Computer",
    "Level",
    "LevelText",
    "Task",
    "Opcode",
    "Keywords",
    "Provider",
    "ProviderGUID",
    "EventRecordID",
    "Correlation_ActivityID",
    "Correlation_RelatedActivityID",
    "ProcessID",
    "ThreadID",
    "UserID",
    "EventData",
    "UserData_Raw",
    "Binary",
]


def _text(el) -> str:
    """Retorna el texto de un elemento XML o cadena vacía."""
    return (el.text or "").strip() if el is not None else ""


def _attr(el, attr: str) -> str:
    """Retorna un atributo de un elemento XML o cadena vacía."""
    if el is None:
        return ""
    return (el.get(attr) or "").strip()


def _xml_to_flat(el, prefix: str = "") -> dict:
    """
    Aplana recursivamente un elemento XML en un dict.
    Se usa para secciones <UserData> de estructura arbitraria.
    """
    result: dict[str, str] = {}
    if el is None:
        return result
    for child in el:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        key = f"{prefix}{tag}" if prefix else tag
        if list(child):
            result.update(_xml_to_flat(child, key + "_"))
        else:
            val = (child.text or "").strip()
            if key in result:
                i = 2
                while f"{key}_{i}" in result:
                    i += 1
                key = f"{key}_{i}"
            result[key] = val
        for attr_name, attr_val in child.attrib.items():
            result[f"{key}_{attr_name}"] = attr_val.strip()
    return result


def parse_evtx_file(evtx_path: str) -> Iterator[dict]:
    """
    Genera un dict por cada evento en un archivo EVTX.
    Captura TODA la metadata: campos System, EventData (nombrados y sin nombre),
    UserData (XML aplanado a columnas UD_*), datos Binary.
    Las IPs, nombres de usuario, workstations, etc. aparecen como columnas Data_*.
    """
    try:
        import Evtx.Evtx as evtx
        from lxml import etree
    except ImportError as exc:
        raise ImportError(
            f"Dependencia faltante: {exc}\nEjecuta: pip install python-evtx lxml"
        ) from exc

    NS = "http://schemas.microsoft.com/win/2004/08/events/event"

    def q(tag: str) -> str:
        return f"{{{NS}}}{tag}"

    with evtx.Evtx(evtx_path) as log_file:
        for record in log_file.records():
            try:
                root = etree.fromstring(record.xml().encode("utf-8"))

                def find(tag: str):
                    return root.find(f".//{q(tag)}")

                # ── Bloque System ──
                provider_el    = find("Provider")
                event_id_el    = find("EventID")
                time_el        = find("TimeCreated")
                correlation_el = find("Correlation")
                execution_el   = find("Execution")
                security_el    = find("Security")

                level_raw  = _text(find("Level"))
                row: dict[str, str] = {
                    "EventID":                       _text(event_id_el),
                    "EventIDQualifiers":             _attr(event_id_el, "Qualifiers"),
                    "Version":                       _text(find("Version")),
                    "TimeCreated":                   _attr(time_el, "SystemTime"),
                    "Channel":                       _text(find("Channel")),
                    "Computer":                      _text(find("Computer")),
                    "Level":                         level_raw,
                    "LevelText":                     LEVEL_MAP.get(level_raw, level_raw),
                    "Task":                          _text(find("Task")),
                    "Opcode":                        _text(find("Opcode")),
                    "Keywords":                      _text(find("Keywords")),
                    "Provider":                      _attr(provider_el, "Name"),
                    "ProviderGUID":                  _attr(provider_el, "Guid"),
                    "EventRecordID":                 _text(find("EventRecordID")),
                    "Correlation_ActivityID":        _attr(correlation_el, "ActivityID"),
                    "Correlation_RelatedActivityID": _attr(correlation_el, "RelatedActivityID"),
                    "ProcessID":                     _attr(execution_el, "ProcessID"),
                    "ThreadID":                      _attr(execution_el, "ThreadID"),
                    "UserID":                        _attr(security_el, "UserID"),
                }

                # ── Bloque EventData ──
                # <Data Name="X">valor</Data> → columnas "Data_X"  (IPs, usuarios, etc.)
                # <Data>valor</Data> sin nombre → "Data_0", "Data_1", …
                event_data_el    = root.find(q("EventData"))
                event_data_parts: list[str] = []
                event_data_dict: dict[str, str] = {}
                unnamed_idx = 0

                if event_data_el is not None:
                    for child in event_data_el:
                        name = child.get("Name", "").strip()
                        val  = (child.text or "").strip()
                        if name:
                            event_data_dict[f"Data_{name}"] = val
                            event_data_parts.append(f"{name}={val}")
                        else:
                            event_data_dict[f"Data_{unnamed_idx}"] = val
                            event_data_parts.append(val)
                            unnamed_idx += 1

                row["EventData"] = " | ".join(event_data_parts)
                row.update(event_data_dict)

                # ── Bloque UserData (XML de eventos de vendor, ej. firewall, WFP) ──
                user_data_el = root.find(q("UserData"))
                user_data_raw = ""
                if user_data_el is not None:
                    user_data_raw = etree.tostring(user_data_el, encoding="unicode")
                    for child in user_data_el:
                        row.update({f"UD_{k}": v for k, v in _xml_to_flat(child).items()})

                row["UserData_Raw"] = user_data_raw
                row["Binary"]       = _text(find("Binary"))

                yield row

            except Exception:
                continue  # Omitir registros malformados


def convert_file(
    evtx_path: str,
    csv_path: str,
    progress_cb: Optional[Callable] = None,
    log_cb: Optional[Callable] = None,
) -> int:
    """Convierte un archivo EVTX a CSV. Retorna el número de eventos escritos."""
    if log_cb:
        log_cb(f"Leyendo: {evtx_path}")

    rows: list[dict] = []
    all_keys: list[str] = list(BASE_FIELDS)

    for i, row in enumerate(parse_evtx_file(evtx_path)):
        rows.append(row)
        for k in row:
            if k not in all_keys:
                all_keys.append(k)
        if progress_cb and i % 500 == 0:
            progress_cb(i, None)

    if log_cb:
        log_cb(f"Escribiendo {len(rows):,} eventos → {csv_path}")

    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for idx, row in enumerate(rows):
            writer.writerow(row)
            if progress_cb and idx % 500 == 0:
                progress_cb(idx, len(rows))

    if progress_cb:
        progress_cb(len(rows), len(rows))
    if log_cb:
        log_cb(f"Listo: {csv_path}")

    return len(rows)


def convert_folder(
    input_folder: str,
    output_folder: str,
    progress_cb: Optional[Callable] = None,
    log_cb: Optional[Callable] = None,
) -> dict[str, int]:
    """Convierte todos los .evtx de una carpeta. Retorna {nombre: cantidad_eventos}."""
    results: dict[str, int] = {}
    input_path  = Path(input_folder)
    output_path = Path(output_folder)
    output_path.mkdir(parents=True, exist_ok=True)

    files = list(input_path.glob("*.evtx"))
    if not files:
        if log_cb:
            log_cb("No se encontraron archivos .evtx en la carpeta.")
        return results

    for evtx_file in files:
        csv_file = output_path / (evtx_file.stem + ".csv")
        try:
            count = convert_file(str(evtx_file), str(csv_file), progress_cb, log_cb)
            results[evtx_file.name] = count
        except Exception as exc:
            if log_cb:
                log_cb(f"ERROR convirtiendo {evtx_file.name}: {exc}")
            results[evtx_file.name] = -1

    return results


# ──────────────────────────────────────────────
# Interfaz Gráfica (GUI)
# ──────────────────────────────────────────────

def launch_gui() -> None:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    # ── Paleta de colores ──
    BG        = "#1a1a2e"
    SURFACE   = "#16213e"
    SURFACE2  = "#0f3460"
    ACCENT    = "#e94560"
    ACCENT2   = "#f5a623"
    FG        = "#e0e0e0"
    FG_DIM    = "#8892a4"
    SUCCESS   = "#27ae60"
    ERROR_COL = "#e74c3c"
    MONO      = ("Consolas", 9)

    root = tk.Tk()
    root.title(f"EVTX → CSV Converter  v{VERSION}")
    root.geometry("860x700")
    root.minsize(720, 620)   # mínimo que garantiza que el botón Convertir sea visible
    root.configure(bg=BG)
    root.resizable(True, True)

    # ── Estilos ttk ──
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".",               background=BG, foreground=FG, font=("Segoe UI", 10))
    style.configure("TFrame",          background=BG)
    style.configure("TLabel",          background=BG, foreground=FG)
    style.configure("Footer.TLabel",   background=SURFACE, foreground=FG_DIM, font=("Segoe UI", 8))
    style.configure("Dim.TLabel",      background=BG, foreground=FG_DIM, font=("Segoe UI", 9))
    style.configure("Accent.TButton",  background=ACCENT, foreground="#ffffff",
                    borderwidth=0, relief="flat", font=("Segoe UI", 10, "bold"), padding=(16, 8))
    style.map("Accent.TButton",
              background=[("active", "#c73652"), ("disabled", "#444")],
              foreground=[("disabled", "#888")])
    style.configure("Secondary.TButton", background=SURFACE2, foreground=FG,
                    borderwidth=0, relief="flat", font=("Segoe UI", 10), padding=(12, 7))
    style.map("Secondary.TButton", background=[("active", "#1a4a7a")])
    style.configure("TEntry",
                    fieldbackground=SURFACE, foreground=FG, insertcolor=FG,
                    bordercolor=SURFACE2, lightcolor=SURFACE2, darkcolor=SURFACE2)
    style.configure("Horizontal.TProgressbar",
                    troughcolor=SURFACE, background=ACCENT, borderwidth=0, thickness=8)
    style.configure("TLabelframe",       background=BG, foreground=FG_DIM,
                    relief="flat", borderwidth=1)
    style.configure("TLabelframe.Label", background=BG, foreground=FG_DIM,
                    font=("Segoe UI", 9))

    # ── Estado compartido ──
    input_var    = tk.StringVar()
    output_var   = tk.StringVar()
    mode_var     = tk.StringVar(value="files")
    status_var   = tk.StringVar(value="Listo · Selecciona archivos .evtx para comenzar")
    progress_var = tk.DoubleVar(value=0)
    log_q: queue.Queue = queue.Queue()
    selected_files: list = []

    # ════════════════════════════════════════════════
    # Funciones helper — definidas ANTES de los widgets
    # ════════════════════════════════════════════════

    def gui_log(msg: str, tag: str = "default") -> None:
        """Agrega un mensaje al log (thread-safe)."""
        ts = datetime.now().strftime("%H:%M:%S")
        log_q.put((f"[{ts}] {msg}", tag))

    def flush_log() -> None:
        """Vacía la cola de mensajes de log hacia el widget Text."""
        while not log_q.empty():
            msg, tag = log_q.get_nowait()
            log_text.configure(state="normal")
            log_text.tag_configure("success", foreground=SUCCESS)
            log_text.tag_configure("error",   foreground=ERROR_COL)
            log_text.tag_configure("accent",  foreground=ACCENT2)
            log_text.insert("end", msg + "\n", tag)
            log_text.see("end")
            log_text.configure(state="disabled")
        root.after(100, flush_log)

    def on_mode_change() -> None:
        """Cambia entre modo archivos individuales y carpeta."""
        input_var.set("")
        selected_files.clear()
        files_list.delete(0, "end")
        if mode_var.get() == "files":
            clear_btn.grid()
        else:
            clear_btn.grid_remove()

    def pick_input() -> None:
        """Abre el diálogo para seleccionar archivos o carpeta de entrada."""
        if mode_var.get() == "files":
            paths = filedialog.askopenfilenames(
                title="Seleccionar archivos EVTX",
                filetypes=[("Windows Event Log", "*.evtx"), ("Todos", "*.*")])
            if paths:
                for p in paths:
                    if p not in selected_files:
                        selected_files.append(p)
                        files_list.insert("end", Path(p).name)
                input_var.set(f"{len(selected_files)} archivo(s) seleccionado(s)")
        else:
            folder = filedialog.askdirectory(title="Seleccionar carpeta con archivos EVTX")
            if folder:
                input_var.set(folder)

    def pick_output() -> None:
        """Abre el diálogo para seleccionar la carpeta de salida."""
        folder = filedialog.askdirectory(title="Seleccionar carpeta de salida")
        if folder:
            output_var.set(folder)

    def clear_files() -> None:
        """Limpia la lista de archivos seleccionados."""
        selected_files.clear()
        files_list.delete(0, "end")
        input_var.set("")

    def set_ui_running(running: bool) -> None:
        """Habilita o deshabilita controles durante la conversión."""
        state = "disabled" if running else "normal"
        convert_btn.configure(state=state)
        input_btn.configure(state=state)

    def start_conversion() -> None:
        """Valida entradas e inicia la conversión en un hilo separado."""
        out_dir = output_var.get().strip()
        if not out_dir:
            messagebox.showerror("Error", "Selecciona una carpeta de salida.")
            return

        if mode_var.get() == "files":
            if not selected_files:
                messagebox.showerror("Error", "Selecciona al menos un archivo .evtx.")
                return
            to_convert = list(selected_files)
        else:
            folder = input_var.get().strip()
            if not folder:
                messagebox.showerror("Error", "Selecciona una carpeta de entrada.")
                return
            to_convert = [str(p) for p in Path(folder).glob("*.evtx")]
            if not to_convert:
                messagebox.showerror("Error", "No se encontraron archivos .evtx en la carpeta.")
                return

        Path(out_dir).mkdir(parents=True, exist_ok=True)
        set_ui_running(True)
        progress_var.set(0)
        status_var.set("Convirtiendo…")
        threading.Thread(target=_worker, args=(to_convert, out_dir), daemon=True).start()

    def _worker(files: list, out_dir: str) -> None:
        """Hilo de conversión: procesa cada archivo EVTX y actualiza la UI."""
        total_files  = len(files)
        total_events = 0
        errors       = 0

        gui_log(f"Iniciando conversión de {total_files} archivo(s)…", "accent")

        for idx, evtx_path in enumerate(files):
            csv_path = str(Path(out_dir) / (Path(evtx_path).stem + ".csv"))

            def _prog(current, total, _i=idx, _n=total_files) -> None:
                pct = ((_i + (current / total if total else 0)) / _n) * 100
                root.after(0, lambda p=pct: progress_var.set(p))
                root.after(0, lambda c=current, t=total: status_var.set(
                    f"Archivo {_i+1}/{_n}  —  Evento {c:,}"
                    + (f" / {t:,}" if t else "")
                ))

            try:
                count = convert_file(evtx_path, csv_path, _prog, gui_log)
                total_events += count
                gui_log(f"✔  {Path(evtx_path).name}  →  {count:,} eventos", "success")
            except Exception as exc:
                errors += 1
                gui_log(f"✘  {Path(evtx_path).name}: {exc}", "error")

        root.after(0, lambda: progress_var.set(100))
        summary = (
            f"Completado: {total_files - errors} archivo(s), "
            f"{total_events:,} eventos exportados."
            + (f"  ({errors} error(es))" if errors else "")
        )
        root.after(0, lambda: status_var.set(summary))
        gui_log(f"{'─'*50}\n{summary}\nDestino: {out_dir}",
                "accent" if not errors else "error")
        root.after(0, lambda: set_ui_running(False))
        if not errors:
            root.after(200, lambda: messagebox.showinfo(
                "Completado",
                f"✔ Conversión exitosa\n\n"
                f"Archivos: {total_files}\n"
                f"Eventos:  {total_events:,}\n"
                f"Destino:  {out_dir}",
            ))

    # ════════════════════════════════════════════════
    # Construcción de widgets
    # ════════════════════════════════════════════════

    # ── Header ──
    header = tk.Frame(root, bg=SURFACE, pady=14, padx=24)
    header.pack(fill="x", side="top")
    tk.Label(header, text="⚡ EVTX → CSV", bg=SURFACE, fg=ACCENT,
             font=("Segoe UI", 18, "bold")).pack(side="left")
    tk.Label(header, text="Windows Event Log Converter",
             bg=SURFACE, fg=FG_DIM, font=("Segoe UI", 10)).pack(
             side="left", padx=12, pady=(6, 0))

    # ── Footer con créditos — siempre visible abajo ──
    footer = tk.Frame(root, bg=SURFACE, pady=6, padx=24)
    footer.pack(fill="x", side="bottom")
    ttk.Label(footer, text=f"Creado por {AUTOR}  ·  v{VERSION}",
              style="Footer.TLabel").pack(side="left")

    # ── Botón Convertir — encima del footer, siempre visible ──
    btn_frame = tk.Frame(root, bg=BG, pady=10)
    btn_frame.pack(fill="x", side="bottom")
    convert_btn = ttk.Button(btn_frame, text="▶  Convertir",
                             style="Accent.TButton", command=start_conversion)
    convert_btn.pack()

    # ── Cuerpo principal (ocupa el espacio restante) ──
    body = ttk.Frame(root, padding=(24, 12))
    body.pack(fill="both", expand=True, side="top")
    body.columnconfigure(1, weight=1)

    # Selector de modo
    mode_frame = ttk.LabelFrame(body, text="Modo de entrada", padding=(12, 8))
    mode_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))

    def _rb(text: str, value: str) -> tk.Radiobutton:
        return tk.Radiobutton(
            mode_frame, text=text, variable=mode_var, value=value,
            bg=BG, fg=FG, selectcolor=SURFACE2,
            activebackground=BG, activeforeground=ACCENT,
            font=("Segoe UI", 10), command=on_mode_change)

    _rb("Archivos individuales (.evtx)", "files").pack(side="left", padx=(0, 24))
    _rb("Carpeta completa (todos los .evtx)", "folder").pack(side="left")

    # Fila de entrada
    ttk.Label(body, text="Entrada:").grid(row=1, column=0, sticky="w", pady=4)
    ttk.Entry(body, textvariable=input_var, state="readonly").grid(
        row=1, column=1, sticky="ew", padx=8)
    input_btn = ttk.Button(body, text="Seleccionar…", style="Secondary.TButton",
                           command=pick_input)
    input_btn.grid(row=1, column=2)

    # Lista de archivos
    files_frame = ttk.LabelFrame(body, text="Archivos seleccionados", padding=(8, 4))
    files_frame.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=(6, 0))
    body.rowconfigure(2, weight=1)

    files_list = tk.Listbox(
        files_frame, bg=SURFACE, fg=FG, selectbackground=SURFACE2,
        font=MONO, relief="flat", borderwidth=0, activestyle="none")
    files_scroll = ttk.Scrollbar(files_frame, orient="vertical", command=files_list.yview)
    files_list.configure(yscrollcommand=files_scroll.set)
    files_list.pack(side="left", fill="both", expand=True)
    files_scroll.pack(side="right", fill="y")

    clear_btn = ttk.Button(body, text="✕ Limpiar lista",
                           style="Secondary.TButton", command=clear_files)
    clear_btn.grid(row=3, column=2, pady=(4, 0), sticky="e")

    # Fila de salida
    ttk.Label(body, text="Salida:").grid(row=4, column=0, sticky="w", pady=(10, 4))
    ttk.Entry(body, textvariable=output_var).grid(row=4, column=1, sticky="ew", padx=8)
    ttk.Button(body, text="Seleccionar…", style="Secondary.TButton",
               command=pick_output).grid(row=4, column=2)
    ttk.Label(body, text="Carpeta de destino para los archivos CSV generados.",
              style="Dim.TLabel").grid(row=5, column=0, columnspan=3, sticky="w")

    # Barra de progreso
    ttk.Progressbar(body, variable=progress_var, maximum=100,
                    style="Horizontal.TProgressbar").grid(
        row=6, column=0, columnspan=3, sticky="ew", pady=(12, 0))
    ttk.Label(body, textvariable=status_var, style="Dim.TLabel").grid(
        row=7, column=0, columnspan=3, sticky="w")

    # Panel de log
    log_frame = ttk.LabelFrame(body, text="Log de conversión", padding=(8, 4))
    log_frame.grid(row=8, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
    body.rowconfigure(8, weight=2)

    log_text = tk.Text(log_frame, bg=SURFACE, fg=FG_DIM, font=MONO,
                       relief="flat", borderwidth=0, state="disabled",
                       height=7, wrap="none")
    log_sy = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
    log_text.configure(yscrollcommand=log_sy.set)
    log_text.pack(side="left", fill="both", expand=True)
    log_sy.pack(side="right", fill="y")

    flush_log()
    root.mainloop()


# ──────────────────────────────────────────────
# Modo CLI
# ──────────────────────────────────────────────

def launch_cli(args) -> None:
    """Ejecuta la conversión en modo línea de comandos."""
    input_path  = Path(args.input)
    output_path = Path(args.output) if args.output else None

    def log(msg: str, *_) -> None:
        print(msg)

    def prog(current, total) -> None:
        if total:
            filled = int(40 * current / total)
            bar    = "█" * filled + "░" * (40 - filled)
            print(f"\r  [{bar}] {current:,}/{total:,}", end="", flush=True)

    if input_path.is_dir():
        out_dir = output_path or input_path
        print(f"Carpeta entrada : {input_path}")
        print(f"Carpeta salida  : {out_dir}")
        results = convert_folder(str(input_path), str(out_dir), prog, log)
        print()
        total  = sum(v for v in results.values() if v >= 0)
        errors = sum(1 for v in results.values() if v < 0)
        print(f"\nResumen: {total:,} eventos exportados. {errors} error(es).")
    else:
        if not input_path.exists():
            print(f"ERROR: Archivo no encontrado: {input_path}", file=sys.stderr)
            sys.exit(1)
        out_file = output_path or input_path.with_suffix(".csv")
        print(f"Archivo entrada : {input_path}")
        print(f"Archivo salida  : {out_file}")
        count = convert_file(str(input_path), str(out_file), prog, log)
        print(f"\n✔ {count:,} eventos exportados → {out_file}")


# ──────────────────────────────────────────────
# Punto de entrada
# ──────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"EVTX to CSV Converter v{VERSION} — por {AUTOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python evtx_to_csv.py                     # Abre la GUI\n"
            "  python evtx_to_csv.py -i Security.evtx    # CLI: un archivo\n"
            "  python evtx_to_csv.py -i Logs -o Output   # CLI: carpeta completa\n"
        ),
    )
    parser.add_argument("-i", "--input",  metavar="RUTA",
                        help="Archivo .evtx o carpeta de entrada")
    parser.add_argument("-o", "--output", metavar="RUTA",
                        help="Archivo .csv o carpeta de salida")
    args = parser.parse_args()

    if args.input:
        launch_cli(args)
    else:
        launch_gui()


if __name__ == "__main__":
    main()
