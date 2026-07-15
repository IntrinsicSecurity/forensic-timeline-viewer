#!/usr/bin/env python3
"""
timeline-viewer: Standalone interactive CSV timeline viewer for Linux
Designed for evtx-parse output but accepts any CSV.

Usage:
  python3 timeline_viewer.py [file.csv]
"""

import sys
import csv
import json
import base64
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("[!] pandas not installed. Run: pip install pandas", file=sys.stderr)
    sys.exit(1)

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTableView, QLineEdit, QLabel, QPushButton, QTextEdit, QSplitter,
        QFileDialog, QHeaderView, QFrame, QAbstractItemView, QComboBox, QMessageBox, QDialog,
    )
    from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QTimer, QSize, QRect, QEvent, pyqtSignal
    from PyQt6.QtGui import QColor, QFont, QAction, QKeySequence, QBrush, QPixmap, QIcon
except ImportError:
    print("[!] PyQt6 not installed. Run: pip install PyQt6", file=sys.stderr)
    sys.exit(1)


FONT_SIZE = 12

# Provider-specific colour rules (checked first).
ROW_COLOURS_SPECIFIC: dict[tuple[str, str], QColor] = {
    ("microsoft-windows-eventlog",           "104"):  QColor(255, 160, 160),
    ("microsoft-windows-security-auditing",  "1102"): QColor(255, 160, 160),
}

# Event-ID-only colour rules (checked when no provider-specific match found).
ROW_COLOURS_EID: dict[str, QColor] = {
    "7045": QColor(255, 195, 120),
    "4719": QColor(255, 195, 120),
    "4720": QColor(255, 195, 120),
    "4726": QColor(255, 195, 120),
    "5861": QColor(255, 195, 120),
    "4698": QColor(255, 195, 120),
    "4648": QColor(255, 240, 100),
    "4625": QColor(255, 240, 100),
    "4771": QColor(255, 240, 100),
    "4740": QColor(255, 240, 100),
    "4624": QColor(185, 215, 255),
    "4634": QColor(220, 235, 255),
    "4672": QColor(220, 235, 255),
}

LEGEND = [
    (QColor(255, 160, 160), "Critical  — log cleared / tampered",
     {("microsoft-windows-eventlog", "104"), ("microsoft-windows-security-auditing", "1102")}),
    (QColor(255, 195, 120), "High      — persistence, privilege, policy",
     {(None, "7045"), (None, "4719"), (None, "4720"), (None, "4726"), (None, "5861"), (None, "4698")}),
    (QColor(255, 240, 100), "Notable   — review required",
     {(None, "4648"), (None, "4625"), (None, "4771"), (None, "4740")}),
    (QColor(185, 215, 255), "Logon     — successful logon / privileges",
     {(None, "4624"), (None, "4672")}),
    (QColor(220, 235, 255), "Logoff    — session ended",
     {(None, "4634")}),
]

BOLD_SPECIFIC: set[tuple[str, str]] = {
    ("microsoft-windows-eventlog",          "104"),
    ("microsoft-windows-security-auditing", "1102"),
}
BOLD_EID: set[str] = {"7045", "4719", "4720", "4726", "5861", "4698"}

BOOKMARK_COLOUR = QColor(140, 220, 180)

SEARCH_COLS = {"event_id", "description", "computer", "user_sid", "event_data", "channel", "provider"}

# Columns that get a disabled filter input in the header (content better queried via Search or pandas).
FILTER_SKIP_COLS = {"event_data", "raw_data", "data", "attributes", "content", "xml", "json"}

TIMESTAMP_COL_KEYWORDS = ("timestamp", "created", "modified", "accessed", "datetime", "date", "time", "write", "last")

DEFAULT_WIDTHS = {
    "timestamp_utc": 195,
    "record_id":     75,
    "event_id":      70,
    "level":         80,
    "channel":       110,
    "provider":      240,
    "computer":      170,
    "user_sid":      220,
    "process_id":    70,
    "thread_id":     70,
    "description":   270,
    "event_data":    380,
    "source_file":   140,
}

DARK_STYLESHEET = """
QMainWindow, QWidget { background-color: #1e1e1e; color: #d4d4d4; }
QTableView {
    background-color: #252526; color: #d4d4d4;
    gridline-color: #3c3c3c;
    selection-background-color: #094771; selection-color: #ffffff;
}
QHeaderView::section {
    background-color: #2d2d30; color: #d4d4d4;
    border: 1px solid #3c3c3c; padding: 2px 4px;
}
QHeaderView { background-color: #2d2d30; }
QLineEdit {
    background-color: #3c3c3c; color: #d4d4d4;
    border: 1px solid #555555; border-radius: 2px; padding: 1px 3px;
}
QLineEdit:disabled { background-color: #2a2a2a; color: #555555; border-color: #3a3a3a; }
QPushButton {
    background-color: #3c3c3c; color: #d4d4d4;
    border: 1px solid #555555; border-radius: 3px; padding: 3px 8px;
}
QPushButton:hover { background-color: #4a4a4a; }
QPushButton:checked { background-color: #0e639c; border-color: #1177bb; color: #ffffff; }
QPushButton:pressed { background-color: #0a4f7e; }
QToolBar { background-color: #2d2d30; border: none; spacing: 4px; }
QMenuBar { background-color: #2d2d30; color: #d4d4d4; }
QMenuBar::item:selected { background-color: #3c3c3c; }
QMenu { background-color: #2d2d30; color: #d4d4d4; border: 1px solid #555555; }
QMenu::item:selected { background-color: #094771; }
QStatusBar { background-color: #007acc; color: #ffffff; }
QTextEdit { background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #3c3c3c; }
QSplitter::handle { background-color: #3c3c3c; }
QComboBox {
    background-color: #3c3c3c; color: #d4d4d4;
    border: 1px solid #555555; border-radius: 2px; padding: 1px 3px;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background-color: #2d2d30; color: #d4d4d4; selection-background-color: #094771; }
QScrollBar:horizontal { background-color: #2d2d30; height: 12px; }
QScrollBar::handle:horizontal { background-color: #555555; border-radius: 3px; min-width: 20px; }
QScrollBar:vertical { background-color: #2d2d30; width: 12px; }
QScrollBar::handle:vertical { background-color: #555555; border-radius: 3px; min-height: 20px; }
QScrollBar::add-line, QScrollBar::sub-line { background: none; border: none; }
"""

# Intrinsic Security logo embedded as base64 PNG
_LOGO_B64 = (
    "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"
    "0RAYyiEAABwtAJqVs3m+AAAAAElFTkSuQmCC"
)

def _load_logo(height_px: int = 32) -> "QPixmap | None":
    try:
        data = base64.b64decode(_LOGO_B64)
        pix = QPixmap()
        pix.loadFromData(data)
        return pix.scaledToHeight(height_px, Qt.TransformationMode.SmoothTransformation)
    except Exception:
        return None


class TimelineModel(QAbstractTableModel):

    def __init__(self):
        super().__init__()
        self._headers: list[str] = []
        self._all_rows: list[list[str]] = []
        self._visible: list[int] = []
        self._eid_col: int = -1
        self._provider_col: int = -1
        self._df: "pd.DataFrame | None" = None
        self._query_indices: "set[int] | None" = None
        self._bookmarked: set[int] = set()
        self._sort_col: int = -1
        self._sort_reverse: bool = False

    def load(self, path: str):
        self.beginResetModel()
        self._headers = []
        self._all_rows = []
        csv.field_size_limit(10_000_000)
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            self._headers = next(reader, [])
            for row in reader:
                while len(row) < len(self._headers):
                    row.append("")
                self._all_rows.append(row)
        self._visible = list(range(len(self._all_rows)))
        self._eid_col = self._headers.index("event_id") if "event_id" in self._headers else -1
        self._provider_col = self._headers.index("provider") if "provider" in self._headers else -1
        self._df = pd.DataFrame(self._all_rows, columns=self._headers)
        self._query_indices = None
        self._bookmarked = set()
        self._sort_col = -1
        self._sort_reverse = False
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._visible)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self._headers)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._all_rows[self._visible[index.row()]]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            val = row[col] if col < len(row) else ""
            return val[:300] + "…" if len(val) > 300 else val

        if role == Qt.ItemDataRole.BackgroundRole:
            raw_idx = self._visible[index.row()]
            if raw_idx in self._bookmarked:
                return QBrush(BOOKMARK_COLOUR)
            eid = row[self._eid_col] if self._eid_col >= 0 and self._eid_col < len(row) else ""
            provider = (row[self._provider_col].lower() if self._provider_col >= 0 and self._provider_col < len(row) else "")
            colour = ROW_COLOURS_SPECIFIC.get((provider, eid)) or ROW_COLOURS_EID.get(eid, QColor(255, 255, 255))
            return QBrush(colour)

        if role == Qt.ItemDataRole.ForegroundRole:
            return QBrush(QColor(20, 20, 20))

        if role == Qt.ItemDataRole.FontRole:
            if self._eid_col >= 0:
                eid = row[self._eid_col] if self._eid_col < len(row) else ""
                provider = (row[self._provider_col].lower() if self._provider_col >= 0 and self._provider_col < len(row) else "")
                if (provider, eid) in BOLD_SPECIFIC or eid in BOLD_EID:
                    f = QFont()
                    f.setBold(True)
                    return f
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            val = row[col] if col < len(row) else ""
            if val.startswith("{"):
                try:
                    d = json.loads(val)
                    items = list(d.items())[:3]
                    tip = "\n".join(f"{k}: {v}" for k, v in items)
                    if len(d) > 3:
                        tip += f"\n… ({len(d) - 3} more fields — click row to see all)"
                    return tip
                except Exception:
                    pass
            if len(val) > 80:
                return val[:200] + "…" if len(val) > 200 else val
            return None

        return None

    def headerData(self, section: int, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section] if section < len(self._headers) else ""
        return None

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder):
        self._sort_col = column
        self._sort_reverse = (order == Qt.SortOrder.DescendingOrder)
        self.beginResetModel()
        self._visible.sort(
            key=lambda i: self._all_rows[i][column] if column < len(self._all_rows[i]) else "",
            reverse=self._sort_reverse,
        )
        self.endResetModel()

    def apply_query(self, query: str) -> str:
        query = query.strip()
        if not query:
            self._query_indices = None
            return ""
        if self._df is None:
            return "No data loaded."
        try:
            result = self._df.query(query, engine="python")
            self._query_indices = set(result.index.tolist())
            return ""
        except Exception as e:
            self._query_indices = None
            msg = str(e)
            if "multi-line" in msg or "only valid in the context" in msg:
                return "Syntax error: check all clauses are joined with 'and' or 'or'"
            if "not defined" in msg or "UndefinedVariable" in msg:
                cols = ", ".join(self._df.columns.tolist())
                return f"Column not found. Available: {cols}"
            return msg

    def apply_filter(self, search: str, col_filters: dict[str, str],
                     date_from: str = "", date_to: str = "",
                     legend_filter: "set[tuple[str | None, str]] | None" = None,
                     ts_col_name: str = "timestamp_utc",
                     bookmark_only: bool = False):
        search_raw = search.strip()
        search_lower = search_raw.lower()
        search_negate = search_lower.startswith("not ")
        search_term = search_lower[4:].strip() if search_negate else search_lower
        specific = [i for i, h in enumerate(self._headers) if h in SEARCH_COLS]
        search_col_indices = specific if specific else list(range(len(self._headers)))

        col_pairs: list[tuple[int, str, bool]] = []
        for col_name, text in col_filters.items():
            text = text.strip().lower()
            if not text or col_name not in self._headers:
                continue
            col_idx = self._headers.index(col_name)
            if col_name == "event_id" and "," in text:
                values = [v.strip() for v in text.split(",") if v.strip()]
                col_pairs.append((col_idx, values, "multi"))
            elif text.lstrip("-").isdigit():
                col_pairs.append((col_idx, text, "exact"))
            else:
                col_pairs.append((col_idx, text, "contains"))

        ts_col = self._headers.index(ts_col_name) if ts_col_name in self._headers else -1
        date_from = date_from.strip()
        date_to = date_to.strip()
        if date_to and len(date_to) == 10:
            date_to = date_to + " 23:59:59"

        eid_col = self._eid_col
        no_filters = not search_lower and not col_pairs and not date_from and not date_to and not legend_filter
        if no_filters:
            new_visible = list(range(len(self._all_rows)))
        else:
            new_visible = []
            for i, row in enumerate(self._all_rows):
                if col_pairs:
                    match = True
                    for ci, value, mode in col_pairs:
                        cell = row[ci].lower() if ci < len(row) else ""
                        if mode == "multi":
                            if cell not in value:
                                match = False
                                break
                        elif mode == "exact":
                            if cell != value:
                                match = False
                                break
                        else:
                            if value not in cell:
                                match = False
                                break
                    if not match:
                        continue
                if search_term:
                    hit = any(
                        search_term in (row[ci].lower() if ci < len(row) else "")
                        for ci in search_col_indices
                    )
                    if search_negate and hit:
                        continue
                    if not search_negate and not hit:
                        continue
                if ts_col >= 0 and (date_from or date_to):
                    ts = row[ts_col] if ts_col < len(row) else ""
                    ts_cmp = ts[:19]
                    if date_from and ts_cmp < date_from[:19]:
                        continue
                    if date_to and ts_cmp > date_to[:19]:
                        continue
                if legend_filter:
                    eid = row[eid_col] if eid_col >= 0 and eid_col < len(row) else ""
                    provider = (row[self._provider_col].lower() if self._provider_col >= 0 and self._provider_col < len(row) else "")
                    if not any(
                        (p is None and eid == e) or (p is not None and provider == p and eid == e)
                        for p, e in legend_filter
                    ):
                        continue
                new_visible.append(i)

        if bookmark_only:
            new_visible = [i for i in new_visible if i in self._bookmarked]
        if self._query_indices is not None:
            new_visible = [i for i in new_visible if i in self._query_indices]
        if self._sort_col >= 0:
            new_visible.sort(
                key=lambda i: self._all_rows[i][self._sort_col] if self._sort_col < len(self._all_rows[i]) else "",
                reverse=self._sort_reverse,
            )

        self.beginResetModel()
        self._visible = new_visible
        self.endResetModel()

    def get_row_dict(self, visible_row: int) -> dict:
        if visible_row < 0 or visible_row >= len(self._visible):
            return {}
        row = self._all_rows[self._visible[visible_row]]
        return {h: (row[i] if i < len(row) else "") for i, h in enumerate(self._headers)}

    def toggle_bookmark(self, visible_row: int):
        if visible_row < 0 or visible_row >= len(self._visible):
            return
        raw_idx = self._visible[visible_row]
        if raw_idx in self._bookmarked:
            self._bookmarked.discard(raw_idx)
        else:
            self._bookmarked.add(raw_idx)
        top_left = self.index(visible_row, 0)
        bottom_right = self.index(visible_row, len(self._headers) - 1)
        self.dataChanged.emit(top_left, bottom_right)

    def clear_bookmarks(self):
        self._bookmarked.clear()
        self.beginResetModel()
        self.endResetModel()

    def get_visible_rows(self) -> list[dict]:
        return [
            {h: (self._all_rows[i][j] if j < len(self._all_rows[i]) else "")
             for j, h in enumerate(self._headers)}
            for i in self._visible
        ]

    def get_bookmarked_rows(self) -> list[dict]:
        return [
            {h: (self._all_rows[i][j] if j < len(self._all_rows[i]) else "")
             for j, h in enumerate(self._headers)}
            for i in sorted(self._bookmarked)
        ]

    @property
    def total(self) -> int:
        return len(self._all_rows)

    @property
    def visible(self) -> int:
        return len(self._visible)

    @property
    def bookmark_count(self) -> int:
        return len(self._bookmarked)


class FilterHeader(QHeaderView):
    """Column header with an embedded filter input in the lower half of each cell."""

    filter_changed = pyqtSignal()

    _INPUT_H = 24  # height of filter input row in pixels

    def __init__(self, parent=None):
        super().__init__(Qt.Orientation.Horizontal, parent)
        self._inputs: list[QLineEdit] = []
        self._col_names: list[str] = []
        self.sectionResized.connect(self._reposition)
        self.sectionMoved.connect(self._reposition)

    def rebuild(self, headers: list[str]):
        for inp in self._inputs:
            inp.deleteLater()
        self._inputs = []
        self._col_names = list(headers)
        for name in headers:
            inp = QLineEdit(self)
            inp.setPlaceholderText("filter…")
            inp.setFrame(True)
            if name.lower() in FILTER_SKIP_COLS:
                inp.setEnabled(False)
                inp.setPlaceholderText("")
                inp.setToolTip("Use Search or Query bar for this column")
            inp.textChanged.connect(self.filter_changed)
            self._inputs.append(inp)
        self._reposition()
        self.update()

    def get_filters(self) -> dict[str, str]:
        result = {}
        for col, inp in enumerate(self._inputs):
            if col < len(self._col_names) and inp.isEnabled() and inp.text():
                result[self._col_names[col]] = inp.text()
        return result

    def clear_filters(self):
        for inp in self._inputs:
            inp.blockSignals(True)
            inp.clear()
            inp.blockSignals(False)

    def sizeHint(self):
        s = super().sizeHint()
        return QSize(s.width(), s.height() + self._INPUT_H + 4)

    def _label_h(self) -> int:
        return super().sizeHint().height()

    def _reposition(self):
        y = self._label_h() + 2
        h = self._INPUT_H
        pad = 2
        for col, inp in enumerate(self._inputs):
            if self.isSectionHidden(col):
                inp.hide()
                continue
            x = self.sectionViewportPosition(col) + pad
            w = self.sectionSize(col) - 2 * pad
            if w < 8:
                inp.hide()
                continue
            inp.setGeometry(x, y, w, h)
            inp.show()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reposition()

    def paintSection(self, painter, rect, logical_index):
        label_h = self._label_h()
        label_rect = QRect(rect.x(), rect.y(), rect.width(), label_h)
        painter.save()
        painter.setClipRect(label_rect)
        super().paintSection(painter, label_rect, logical_index)
        painter.restore()


class MainWindow(QMainWindow):

    def __init__(self, csv_path: str | None = None, dark: bool = False):
        super().__init__()
        self._dark = dark
        self.setWindowTitle("Timeline Viewer")
        self.resize(1500, 950)
        self._model = TimelineModel()
        self._filter_timer = QTimer()
        self._filter_timer.setSingleShot(True)
        self._filter_timer.timeout.connect(self._apply_filters)
        self._ts_col_name: str = "timestamp_utc"
        self._bookmark_anchor: int = -1
        self._build_ui()
        if csv_path:
            self._load(csv_path)

    def _build_ui(self):
        # Menu bar: File menu holds Open and Export actions
        file_menu = self.menuBar().addMenu("File")
        open_act = QAction("Open CSV…", self)
        open_act.setShortcut(QKeySequence.StandardKey.Open)
        open_act.triggered.connect(self._open_dialog)
        file_menu.addAction(open_act)
        file_menu.addSeparator()
        export_visible_act = QAction("Export visible…", self)
        export_visible_act.triggered.connect(self._export_visible)
        file_menu.addAction(export_visible_act)
        export_bm_act = QAction("Export bookmarked…", self)
        export_bm_act.triggered.connect(self._export_bookmarked)
        file_menu.addAction(export_bm_act)

        help_menu = self.menuBar().addMenu("Help")
        shortcuts_act = QAction("Keyboard Shortcuts…", self)
        shortcuts_act.triggered.connect(self._show_help)
        help_menu.addAction(shortcuts_act)

        # Toolbar: actions only, no search bar
        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)
        toolbar.addAction(open_act)
        toolbar.addSeparator()
        toolbar.addSeparator()

        fit_btn = QPushButton("Fit columns")
        fit_btn.setToolTip("Resize all columns to fit their content")
        fit_btn.clicked.connect(self._fit_columns)
        toolbar.addWidget(fit_btn)
        toolbar.addSeparator()

        bookmark_act = QAction("☆ Bookmark", self)
        bookmark_act.setShortcut(QKeySequence("Ctrl+B"))
        bookmark_act.setToolTip("Toggle bookmark on selected row (Space or Ctrl+B). Shift+Space or Shift+Click to bookmark a range.")
        bookmark_act.triggered.connect(self._toggle_bookmark)
        toolbar.addAction(bookmark_act)

        self._bookmark_only_btn = QPushButton("☆ Only")
        self._bookmark_only_btn.setCheckable(True)
        self._bookmark_only_btn.setToolTip("Show bookmarked rows only")
        self._bookmark_only_btn.clicked.connect(self._apply_filters)
        toolbar.addWidget(self._bookmark_only_btn)

        clear_bm_btn = QPushButton("Clear ☆")
        clear_bm_btn.setToolTip("Clear all bookmarks")
        clear_bm_btn.clicked.connect(self._clear_bookmarks)
        toolbar.addWidget(clear_bm_btn)

        # Logo at the right end of the toolbar
        spacer = QWidget()
        spacer.setSizePolicy(
            spacer.sizePolicy().horizontalPolicy(),
            spacer.sizePolicy().verticalPolicy(),
        )
        from PyQt6.QtWidgets import QSizePolicy
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)
        logo_label = QLabel()
        logo_pix = _load_logo(32)
        if logo_pix:
            logo_label.setPixmap(logo_pix)
            logo_label.setToolTip("Intrinsic Security")
            toolbar.addWidget(logo_label)

        # Central layout
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(6)
        self.setCentralWidget(splitter)

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(2, 2, 2, 2)
        top_layout.setSpacing(2)

        # Row 1: Search + pandas query on one line
        sq_frame = QFrame()
        sq_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        sq = QHBoxLayout(sq_frame)
        sq.setContentsMargins(6, 3, 6, 3)
        sq.setSpacing(6)

        sq.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Key fields… prefix NOT to exclude  (e.g. NOT miiserver.exe)")
        self._search.textChanged.connect(self._schedule_filter)
        sq.addWidget(self._search, stretch=1)

        sq.addWidget(QLabel("Query:"))
        self._query_input = QLineEdit()
        self._query_input.setPlaceholderText(
            'pandas — e.g.  filename == "cmd.exe"  or  reason.str.contains("CREATE")'
        )
        self._query_input.setFont(QFont("Courier New", FONT_SIZE))
        self._query_input.returnPressed.connect(self._apply_query)
        sq.addWidget(self._query_input, stretch=2)

        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._apply_query)
        sq.addWidget(apply_btn)

        clear_q_btn = QPushButton("✕")
        clear_q_btn.setToolTip("Clear query")
        clear_q_btn.setFixedWidth(28)
        clear_q_btn.clicked.connect(self._clear_query)
        sq.addWidget(clear_q_btn)

        error_style = (
            "background-color: #3d1515; color: #ff6666; border: 1px solid #cc0000;"
            if self._dark else
            "background-color: #fff0f0; color: #cc0000; border: 1px solid #cc0000;"
        )
        self._query_error = QLineEdit()
        self._query_error.setReadOnly(True)
        self._query_error.setStyleSheet(error_style)
        self._query_error.setMinimumWidth(200)
        self._query_error.hide()
        sq.addWidget(self._query_error)

        top_layout.addWidget(sq_frame)

        # Row 2: Date range + clear all
        date_frame = QFrame()
        date_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        df = QHBoxLayout(date_frame)
        df.setContentsMargins(6, 3, 6, 3)
        df.setSpacing(6)

        df.addWidget(QLabel("Filter on:"))
        self._ts_col_combo = QComboBox()
        self._ts_col_combo.setMinimumWidth(160)
        self._ts_col_combo.setToolTip("Timestamp column the date range applies to")
        self._ts_col_combo.currentTextChanged.connect(self._on_ts_col_changed)
        df.addWidget(self._ts_col_combo)

        df.addWidget(QLabel("From:"))
        self._date_from = QLineEdit()
        self._date_from.setPlaceholderText("YYYY-MM-DD HH:MM:SS")
        self._date_from.setFixedWidth(165)
        self._date_from.setToolTip("Start of date range (UTC). Accepts YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
        self._date_from.textChanged.connect(self._schedule_filter)
        self._date_from.returnPressed.connect(self._apply_filters)
        df.addWidget(self._date_from)

        df.addWidget(QLabel("To:"))
        self._date_to = QLineEdit()
        self._date_to.setPlaceholderText("YYYY-MM-DD HH:MM:SS")
        self._date_to.setFixedWidth(165)
        self._date_to.setToolTip("End of date range (UTC). Accepts YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
        self._date_to.textChanged.connect(self._schedule_filter)
        self._date_to.returnPressed.connect(self._apply_filters)
        df.addWidget(self._date_to)

        df.addStretch()

        clear_btn = QPushButton("✕ Clear all")
        clear_btn.setToolTip("Clear all filters")
        clear_btn.clicked.connect(self._clear_filters)
        df.addWidget(clear_btn)

        top_layout.addWidget(date_frame)

        # Table with in-header column filters
        self._filter_header = FilterHeader()
        self._filter_header.filter_changed.connect(self._schedule_filter)

        self._table = QTableView()
        self._table.setHorizontalHeader(self._filter_header)
        self._table.setModel(self._model)
        self._table.setSortingEnabled(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(False)
        self._filter_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._filter_header.setStretchLastSection(False)
        self._filter_header.setSortIndicatorShown(True)
        self._filter_header.setSectionsClickable(True)
        self._table.verticalHeader().setDefaultSectionSize(FONT_SIZE + 12)
        self._table.verticalHeader().hide()
        self._table.setFont(QFont("Courier New", FONT_SIZE))
        self._table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        self._filter_header.sortIndicatorChanged.connect(self._on_sort)
        self._table.horizontalScrollBar().valueChanged.connect(self._filter_header._reposition)
        self._table.installEventFilter(self)
        self._table.viewport().installEventFilter(self)
        top_layout.addWidget(self._table)
        splitter.addWidget(top)

        # Bottom pane: event detail + legend
        bottom = QWidget()
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(4, 4, 4, 4)
        bl.setSpacing(6)

        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(2)
        detail_layout.addWidget(QLabel("Event detail:"))
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setFont(QFont("Courier New", FONT_SIZE))
        detail_layout.addWidget(self._detail)
        bl.addWidget(detail_widget, stretch=1)

        self._legend_frame = QFrame()
        legend_frame = self._legend_frame
        legend_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        legend_frame.setFixedWidth(340)
        lf = QVBoxLayout(legend_frame)
        lf.setContentsMargins(8, 8, 8, 8)
        lf.setSpacing(4)
        lf.addWidget(QLabel("<b>Filter by category</b>"))
        self._legend_buttons: list[tuple[QPushButton, set]] = []
        for colour, label, eids in LEGEND:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setStyleSheet(
                f"QPushButton {{"
                f"  background-color: rgb({colour.red()},{colour.green()},{colour.blue()});"
                f"  color: #141414;"
                f"  border: 1px solid #aaa;"
                f"  border-radius: 3px;"
                f"  padding: 4px 6px;"
                f"  text-align: left;"
                f"}}"
                f"QPushButton:checked {{"
                f"  border: 2px solid #333;"
                f"  font-weight: bold;"
                f"}}"
            )
            btn.clicked.connect(self._on_legend_click)
            self._legend_buttons.append((btn, eids))
            lf.addWidget(btn)
        lf.addStretch()
        bl.addWidget(legend_frame)

        splitter.addWidget(bottom)
        splitter.setSizes([680, 220])
        self.statusBar().showMessage("No file loaded — open a CSV to begin.")

    def _on_sort(self, col: int, order):
        widths = self._save_col_widths()
        self._model.sort(col, order)
        self._restore_col_widths(widths)

    def _on_ts_col_changed(self, col_name: str):
        self._ts_col_name = col_name
        self._apply_filters()

    def _rebuild_col_filters(self, headers: list[str]):
        ts_cols = [h for h in headers if any(kw in h.lower() for kw in TIMESTAMP_COL_KEYWORDS)]
        self._ts_col_combo.blockSignals(True)
        self._ts_col_combo.clear()
        for col in ts_cols:
            self._ts_col_combo.addItem(col)
        self._ts_col_name = ts_cols[0] if ts_cols else ""
        if self._ts_col_name:
            self._ts_col_combo.setCurrentText(self._ts_col_name)
        self._ts_col_combo.blockSignals(False)
        self._filter_header.rebuild(headers)

    def eventFilter(self, obj, event):
        if obj is self._table and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Space:
                self._space_bookmark(bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier))
                return True
        if obj is self._table.viewport() and event.type() == QEvent.Type.MouseButtonPress:
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                row = self._table.rowAt(int(event.position().y()))
                if row >= 0:
                    self._shift_click_bookmark(row)
                return True
        return super().eventFilter(obj, event)

    def _space_bookmark(self, shift: bool):
        idx = self._table.currentIndex()
        if not idx.isValid():
            return
        row = idx.row()
        if shift and self._bookmark_anchor >= 0:
            self._bookmark_range(self._bookmark_anchor, row)
            next_row = min(max(self._bookmark_anchor, row) + 1, self._model.visible - 1)
            self._table.selectRow(next_row)
            self._bookmark_anchor = row
        else:
            self._model.toggle_bookmark(row)
            self._bookmark_anchor = row
            self._table.selectRow(min(row + 1, self._model.visible - 1))
            self._update_status()

    def _shift_click_bookmark(self, row: int):
        if self._bookmark_anchor < 0:
            self._model.toggle_bookmark(row)
            self._bookmark_anchor = row
        else:
            self._bookmark_range(self._bookmark_anchor, row)
            self._bookmark_anchor = row
        self._table.selectRow(row)

    def _bookmark_range(self, from_row: int, to_row: int):
        start, end = min(from_row, to_row), max(from_row, to_row)
        n = self._model.visible
        for r in range(start, min(end + 1, n)):
            self._model._bookmarked.add(self._model._visible[r])
        if start < n:
            tl = self._model.index(start, 0)
            br = self._model.index(min(end, n - 1), self._model.columnCount() - 1)
            self._model.dataChanged.emit(tl, br)
        self._update_status()

    def _toggle_bookmark(self):
        idx = self._table.currentIndex()
        if not idx.isValid():
            return
        self._model.toggle_bookmark(idx.row())
        self._bookmark_anchor = idx.row()
        self._update_status()

    def _clear_bookmarks(self):
        self._bookmark_anchor = -1
        self._model.clear_bookmarks()
        if self._bookmark_only_btn.isChecked():
            self._bookmark_only_btn.setChecked(False)
        self._apply_filters()
        self._update_status()

    def _export_csv(self, rows: list[dict], label: str):
        if not rows:
            QMessageBox.information(self, "Export", f"No {label} rows to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, f"Export {label}", "", "CSV files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._model._headers)
            writer.writeheader()
            writer.writerows(rows)
        self.statusBar().showMessage(f"Exported {len(rows):,} rows to {Path(path).name}")

    def _export_visible(self):
        self._export_csv(self._model.get_visible_rows(), "visible")

    def _export_bookmarked(self):
        self._export_csv(self._model.get_bookmarked_rows(), "bookmarked")

    def _open_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open CSV", "", "CSV files (*.csv);;All files (*)")
        if path:
            self._load(path)

    def _load(self, path: str):
        self.setWindowTitle(f"Timeline Viewer — {Path(path).name}")
        self.statusBar().showMessage(f"Loading {path}…")
        QApplication.processEvents()
        self._model.load(path)
        self._rebuild_col_filters(self._model._headers)
        self._update_legend_visibility()
        for i, col in enumerate(self._model._headers):
            self._table.setColumnWidth(i, DEFAULT_WIDTHS.get(col, 120))
        self._update_status()

    def _update_legend_visibility(self):
        eid_col = self._model._eid_col
        if eid_col < 0:
            self._legend_frame.hide()
            return
        all_eids = {row[eid_col] for row in self._model._all_rows if eid_col < len(row)}
        has_match = bool(all_eids & (set(ROW_COLOURS_EID) | {e for _, e in ROW_COLOURS_SPECIFIC}))
        self._legend_frame.setVisible(has_match)

    def _on_legend_click(self):
        sender = self.sender()
        for btn, _ in self._legend_buttons:
            if btn is not sender:
                btn.setChecked(False)
        self._apply_filters()

    def _active_legend_filter(self) -> "set[tuple] | None":
        for btn, pairs in self._legend_buttons:
            if btn.isChecked():
                return pairs
        return None

    def _fit_columns(self):
        header = self._filter_header
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        widths = [header.sectionSize(i) for i in range(header.count())]
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for i, w in enumerate(widths):
            self._table.setColumnWidth(i, min(w, 400))

    def _apply_query(self):
        err = self._model.apply_query(self._query_input.text())
        if err:
            self._query_error.setText(f"Query error: {err}")
            self._query_error.show()
        else:
            self._query_error.clear()
            self._query_error.hide()
        self._apply_filters()

    def _clear_query(self):
        self._query_input.clear()
        self._query_error.clear()
        self._query_error.hide()
        self._model.apply_query("")
        self._apply_filters()

    def _schedule_filter(self):
        self._filter_timer.start(200)

    def _save_col_widths(self) -> list[int]:
        h = self._filter_header
        return [h.sectionSize(i) for i in range(h.count())]

    def _restore_col_widths(self, widths: list[int]):
        for i, w in enumerate(widths):
            self._table.setColumnWidth(i, w)

    def _apply_filters(self):
        widths = self._save_col_widths()
        self._model.apply_filter(
            self._search.text(),
            self._filter_header.get_filters(),
            date_from=self._date_from.text(),
            date_to=self._date_to.text(),
            legend_filter=self._active_legend_filter(),
            ts_col_name=self._ts_col_name,
            bookmark_only=self._bookmark_only_btn.isChecked(),
        )
        self._restore_col_widths(widths)
        self._update_status()

    def _clear_filters(self):
        for w in [self._search, self._date_from, self._date_to]:
            w.blockSignals(True)
            w.clear()
            w.blockSignals(False)
        self._filter_header.clear_filters()
        if self._ts_col_combo.count():
            self._ts_col_combo.blockSignals(True)
            self._ts_col_combo.setCurrentIndex(0)
            self._ts_col_name = self._ts_col_combo.currentText()
            self._ts_col_combo.blockSignals(False)
        for btn, _ in self._legend_buttons:
            btn.setChecked(False)
        self._bookmark_only_btn.setChecked(False)
        self._query_input.clear()
        self._query_error.clear()
        self._query_error.hide()
        self._model.apply_query("")
        self._model.apply_filter("", {}, legend_filter=None)
        self._update_status()

    def _update_status(self):
        t, v, b = self._model.total, self._model.visible, self._model.bookmark_count
        msg = f"{t:,} records" if t == v else f"{v:,} of {t:,} records (filtered)"
        if b:
            msg += f" | {b:,} bookmarked"
        self.statusBar().showMessage(msg)

    def _on_row_changed(self, current: QModelIndex, _previous: QModelIndex):
        if not current.isValid():
            self._detail.clear()
            return
        row = self._model.get_row_dict(current.row())
        lines = []
        for key, val in row.items():
            if key == "event_data":
                continue
            lines.append(f"{key:<16} {val}")
        event_data = row.get("event_data", "")
        if event_data:
            lines.append("")
            lines.append("event_data:")
            try:
                for k, v in json.loads(event_data).items():
                    lines.append(f"  {k:<30} {v}")
            except Exception:
                lines.append(f"  {event_data}")
        self._detail.setPlainText("\n".join(lines))

    def _show_help(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Keyboard Shortcuts")
        dlg.setMinimumWidth(520)
        layout = QVBoxLayout(dlg)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        text.setPlainText(
            "BOOKMARKING\n"
            "─────────────────────────────────────────────────────\n"
            "Space             Toggle bookmark on selected row and advance\n"
            "                  to the next row. Sets the range anchor.\n"
            "Shift+Space       Bookmark all rows from the anchor to the\n"
            "                  current row (inclusive).\n"
            "Shift+Click       Bookmark all rows from the anchor to the\n"
            "                  clicked row (inclusive).\n"
            "☆ Only            Show bookmarked rows only / show all rows.\n"
            "Clear ☆           Clear all bookmarks.\n"
            "Ctrl+B            Toggle bookmark on the selected row\n"
            "                  (does not advance).\n"
            "File > Export bookmarked\n"
            "                  Save bookmarked rows to a new CSV file.\n"
            "\n"
            "NAVIGATION AND FILES\n"
            "─────────────────────────────────────────────────────\n"
            "Ctrl+O            Open a CSV file.\n"
            "\n"
            "FILTERING\n"
            "─────────────────────────────────────────────────────\n"
            "Column headers    Type in the filter box below each column\n"
            "                  label to filter that column. Event ID\n"
            "                  accepts comma-separated values: 4624,4625\n"
            "Search bar        Free-text search across event ID,\n"
            "                  description, computer, user, channel, and\n"
            "                  event_data. Prefix with NOT to exclude:\n"
            "                  NOT miiserver.exe\n"
            "Date range        Restrict to a UTC time window. Accepts\n"
            "                  YYYY-MM-DD or YYYY-MM-DD HH:MM:SS.\n"
            "Query bar         Full pandas query syntax. Press Enter to\n"
            "                  apply. Example:\n"
            "                  event_id == \"4648\" and not event_data.str.contains(\"NT SERVICE\")\n"
            "Clear all         Clear column filters, search, and date range.\n"
            "Sort              Click a column label to sort. Click again\n"
            "                  to reverse.\n"
            "\n"
            "DISPLAY\n"
            "─────────────────────────────────────────────────────\n"
            "Fit columns       Resize all columns to fit their content.\n"
            "--dark            Launch with dark colour scheme\n"
            "                  (command-line flag).\n"
            "--scale FACTOR    UI scale for 4K displays, e.g. --scale 1.75\n"
            "                  (command-line flag).\n"
        )
        layout.addWidget(text)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)

        dlg.exec()


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="timeline-viewer")
    ap.add_argument("csv", nargs="?", help="CSV file to open")
    ap.add_argument("--font-size", type=int, default=12, metavar="PT", help="Font size in points (default: 12)")
    ap.add_argument("--scale", type=float, default=None, metavar="FACTOR", help="UI scale factor e.g. 1.75 for 4K displays")
    ap.add_argument("--dark", action="store_true", help="Force dark mode (useful on Linux where system dark theme is not picked up)")
    args = ap.parse_args()

    global FONT_SIZE
    FONT_SIZE = args.font_size

    import os
    if args.scale:
        os.environ["QT_SCALE_FACTOR"] = str(args.scale)
    else:
        os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    app = QApplication(sys.argv[:1])
    app.setStyle("Fusion")
    app.setFont(QFont("Courier New", FONT_SIZE))
    logo_pix = _load_logo(64)
    if logo_pix:
        app.setWindowIcon(QIcon(logo_pix))
    tooltip_style = f"QToolTip {{ font-size: {FONT_SIZE}pt; padding: 4px; }}"
    if args.dark:
        app.setStyleSheet(DARK_STYLESHEET + "\n" + tooltip_style)
    else:
        app.setStyleSheet(tooltip_style)

    w = MainWindow(args.csv, dark=args.dark)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
