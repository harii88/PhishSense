"""Colours and the application style sheet (one place for the look)."""

from __future__ import annotations

from phishsense import config

NAVY = "#0f172a"
NAVY_2 = "#1e293b"
SLATE = "#64748b"
BORDER = "#e2e8f0"
BACKGROUND = "#f1f5f9"
CARD = "#ffffff"
TEXT = "#0f172a"
ACCENT = "#2563eb"
GOOD = "#16a34a"
WARN = "#d97706"
BAD = "#dc2626"

RISK_COLOURS = {config.RISK_LOW: GOOD, config.RISK_MODERATE: WARN, config.RISK_HIGH: BAD}

PROFILE_COLOURS = {
    config.PROFILE_VIGILANT: "#16a34a",
    config.PROFILE_IMPULSIVE: "#dc2626",
    config.PROFILE_PASSIVE: "#7c3aed",
    config.PROFILE_REPEATER: "#d97706",
}

CODE_STYLE = "font-family: Consolas, 'Courier New'; font-size: 9.5pt; color: #1e3a8a;"


def rich(html_text: str) -> str:
    """Rich text for QLabel/QTextBrowser: give <code> a readable monospace font
    (Qt's default fallback for <code> is cramped)."""
    return html_text.replace("<code>", f"<span style=\"{CODE_STYLE}\">").replace("</code>", "</span>")


STYLE_SHEET = f"""
QScrollArea, QScrollArea > QWidget > QWidget {{ background: {BACKGROUND}; border: none; }}
QWidget {{ font-family: "Segoe UI"; font-size: 10pt; color: {TEXT}; }}
QMainWindow, QDialog, QStackedWidget > QWidget {{ background: {BACKGROUND}; }}

#Sidebar {{ background: {NAVY}; }}
#Sidebar QLabel {{ color: #e2e8f0; }}
#AppTitle {{ font-size: 14pt; font-weight: 600; color: white; }}
#AppSubtitle {{ color: #94a3b8; font-size: 9pt; }}
#NavList {{ background: transparent; border: none; color: #cbd5e1; outline: 0; }}
#NavList::item {{ padding: 10px 14px; border-radius: 6px; margin: 2px 8px; }}
#NavList::item:selected {{ background: {ACCENT}; color: white; }}
#NavList::item:hover:!selected {{ background: {NAVY_2}; }}
#SidebarButton {{ background: {NAVY_2}; color: #e2e8f0; border: none; border-radius: 6px;
                  padding: 7px; margin: 0 8px; }}
#SidebarButton:hover {{ background: #334155; }}

#PageTitle {{ font-size: 16pt; font-weight: 600; }}
#Muted {{ color: {SLATE}; }}
#Card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 10px; }}
#CardTitle {{ color: {SLATE}; font-size: 9pt; text-transform: uppercase; }}
#CardValue {{ font-size: 20pt; font-weight: 600; }}
#Banner {{ background: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px; padding: 10px; }}
#Disclaimer {{ color: {SLATE}; font-size: 8.5pt; }}

QPushButton {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 6px;
               padding: 7px 14px; }}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: #94a3b8; background: #f8fafc; }}
QPushButton#Primary {{ background: {ACCENT}; color: white; border: none; font-weight: 600; }}
QPushButton#Primary:disabled {{ background: #93c5fd; }}
QPushButton#Danger {{ background: {BAD}; color: white; border: none; font-weight: 600; }}
QPushButton#Danger:disabled {{ background: #fca5a5; }}
QPushButton#Safe {{ background: {GOOD}; color: white; border: none; font-weight: 600; }}
QPushButton#Safe:disabled {{ background: #86efac; }}
QPushButton#Attachment {{ text-align: left; background: #f8fafc; }}

QLineEdit, QComboBox {{ background: white; border: 1px solid {BORDER}; border-radius: 6px;
                        padding: 6px; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QListWidget, QTreeWidget, QTableWidget, QTextBrowser {{ background: white;
    border: 1px solid {BORDER}; border-radius: 8px; }}
QListWidget#MessageList::item {{ padding: 8px; border-bottom: 1px solid {BORDER}; }}
QListWidget#MessageList::item:selected {{ background: #dbeafe; color: {TEXT}; }}
QHeaderView::section {{ background: #f8fafc; border: none; border-bottom: 1px solid {BORDER};
                        padding: 6px; font-weight: 600; }}
#StatusBarLink {{ background: #f8fafc; border: 1px solid {BORDER}; border-radius: 6px;
                  padding: 4px 8px; color: {SLATE}; font-family: Consolas; }}
QTabWidget::pane {{ border: none; }}
QTabBar::tab {{ padding: 8px 16px; }}
QTabBar::tab:selected {{ border-bottom: 2px solid {ACCENT}; font-weight: 600; }}
"""
