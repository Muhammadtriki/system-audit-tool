"""Building the full system report and exporting it as text or HTML."""

import html
import os
import platform
from datetime import datetime

from .network import get_active_connections, get_network_interfaces
from .system_info import (
    check_privileges,
    get_cpu_telemetry,
    get_environment_info,
    get_memory_and_disk_telemetry,
    get_top_processes,
)


def build_full_report():
    """Collect the report as a list of lines, so it can be printed, logged or exported."""
    lines = []
    lines.append(f"PRIVILEGE LEVEL: {'ADMIN/ROOT' if check_privileges() else 'STANDARD USER'}")
    lines.append(f"SYSTEM: {platform.system()} {platform.release()}")

    env_info = get_environment_info()
    lines.append(f"User='{env_info['user']}' | PATH entries={env_info['path_count']}")

    cpu = get_cpu_telemetry()
    lines.append(
        f"CPU: {cpu['physical_cores']} physical / {cpu['logical_cores']} logical"
        f" | {cpu['overall_percent']:.1f}% used"
    )

    mem_disk = get_memory_and_disk_telemetry()
    lines.append(
        f"RAM: {mem_disk['ram_used_gb']:.2f}/{mem_disk['ram_total_gb']:.2f} GB ({mem_disk['ram_percent']}%)"
    )
    lines.append(f"Disk free: {mem_disk['disk_free_gb']:.2f}/{mem_disk['disk_total_gb']:.2f} GB")

    top_cpu, _ = get_top_processes(limit=5)
    lines.append("Top 5 processes by CPU:")
    for proc in top_cpu:
        lines.append(f"  PID {proc['pid']:<8} {proc['name'][:25]:<25} {proc['cpu_percent']:>5.1f}%")

    lines.append("Network interfaces:")
    for name, ips in get_network_interfaces().items():
        lines.append(f"  {name}: {', '.join(ips)}")

    connections = get_active_connections()
    lines.append(f"Active connections (showing up to 10 of {len(connections)}):")
    for conn in connections[:10]:
        lines.append(f"  {conn['type']} {conn['local']} [{conn['status']}] {conn['process']}")

    return lines


def export_report_text(report_lines, output_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"System Audit Report - {timestamp}\n")
        f.write("=" * 55 + "\n\n")
        f.write("\n".join(report_lines))
    print(f"[+] Report exported to {output_path}")


def export_report_html(report_lines, output_path):
    # html.escape matters: process names and paths come from the system and could
    # contain characters like < or & that would otherwise break the page.
    rows = "\n".join(f"<div class='line'>{html.escape(line)}</div>" for line in report_lines)
    page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>System Report</title>
<style>
  body {{ font-family: 'Consolas', monospace; background: #1e1e1e; color: #d4d4d4; padding: 24px; }}
  h1 {{ color: #4ec9b0; }}
  .meta {{ color: #808080; margin-bottom: 16px; }}
  .line {{ white-space: pre; line-height: 1.5; }}
</style></head>
<body>
  <h1>System Audit Report</h1>
  <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
  {rows}
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"[+] Report exported to {output_path}")


def run_full_report(save_log=True, log_dir="logs"):
    """Print the full report and, by default, save a copy in the logs folder."""
    lines = build_full_report()
    for line in lines:
        print(line)
    if save_log:
        os.makedirs(log_dir, exist_ok=True)
        filename = os.path.join(log_dir, f"report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt")
        export_report_text(lines, filename)
    return lines
