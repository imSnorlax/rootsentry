"""
RootSentry modules package.
"""
from .process_scanner  import scan_hidden_processes
from .syscall_inspector import scan_syscalls
from .fs_checker        import scan_filesystem
from .removal_engine    import remediate_scan, kill_process, unload_module, clean_file
from .report_generator  import generate_html_report, save_report

__all__ = [
    "scan_hidden_processes",
    "scan_syscalls",
    "scan_filesystem",
    "remediate_scan",
    "kill_process",
    "unload_module",
    "clean_file",
    "generate_html_report",
    "save_report",
]
