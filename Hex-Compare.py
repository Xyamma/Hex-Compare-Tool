import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel, QFrame, QSplitter,
    QTabWidget, QGroupBox, QMessageBox, QStatusBar,
    QMenuBar, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QTimer, QDateTime
from PyQt6.QtGui import QFont, QPalette, QColor, QAction, QIcon
import pyperclip
import hashlib
import binascii
import os
import re


class HexValidator:
    @staticmethod
    def is_valid_hex(hex_string):
        if not hex_string:
            return False
        
        cleaned = hex_string.replace(' ', '').replace('\n', '').replace('\t', '').replace(':', '').replace('-', '')
        
        if not cleaned:
            return False
        
        if len(cleaned) % 2 != 0:
            return False
        
        hex_pattern = re.compile(r'^[0-9A-Fa-f]+$')
        return bool(hex_pattern.match(cleaned))
    
    @staticmethod
    def normalize_hex(hex_string):
        cleaned = hex_string.replace(' ', '').replace('\n', '').replace('\t', '').replace(':', '').replace('-', '')
        return cleaned.upper()
    
    @staticmethod
    def format_hex(hex_string):
        normalized = HexValidator.normalize_hex(hex_string)
        if not normalized:
            return ''
        
        return ' '.join(normalized[i:i+2] for i in range(0, len(normalized), 2))
    
    @staticmethod
    def hex_to_bytes(hex_string):
        normalized = HexValidator.normalize_hex(hex_string)
        if not normalized:
            return b''
        
        try:
            return bytes.fromhex(normalized)
        except ValueError:
            return b''


class HexLineEdit(QLineEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFont(QFont("Consolas", 10))
        self.setPlaceholderText("Введите HEX...")
        self.setMaxLength(10000)
        
    def set_hex(self, hex_string):
        formatted = HexValidator.format_hex(hex_string)
        self.setText(formatted)


class ComparisonTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self._setup_table()
    
    def _setup_table(self):
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(["Позиция", "HEX1", "HEX2", "Статус"])
        
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    
    def update_data(self, comparison_data):
        self.setRowCount(0)
        
        if not comparison_data['result']:
            return
        
        self.setRowCount(len(comparison_data['result']))
        
        match_color = QColor(0, 128, 0)
        diff_color = QColor(220, 0, 0)
        
        for row, item in enumerate(comparison_data['result']):
            # Position
            pos_item = QTableWidgetItem(item['position'])
            pos_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            pos_item.setFlags(pos_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(row, 0, pos_item)
            
            # HEX1
            hex1_item = QTableWidgetItem(item['hex1'])
            hex1_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            hex1_item.setFlags(hex1_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(row, 1, hex1_item)
            
            # HEX2
            hex2_item = QTableWidgetItem(item['hex2'])
            hex2_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            hex2_item.setFlags(hex2_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(row, 2, hex2_item)
            
            # Status
            if item['match']:
                status_item = QTableWidgetItem("✓ Совпадает")
                status_item.setForeground(match_color)
            else:
                status_item = QTableWidgetItem("✗ Различие")
                status_item.setForeground(diff_color)
            
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(row, 3, status_item)


class HexCompareTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("HEX Compare Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        self._apply_dark_theme()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        self._create_input_section(main_layout)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        self._create_comparison_section(splitter)
        self._create_analysis_section(splitter)
        
        splitter.setSizes([400, 400])
        main_layout.addWidget(splitter, 1)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов")
        
        self._create_menu()
        
        self.auto_compare_timer = QTimer()
        self.auto_compare_timer.timeout.connect(self.auto_compare)
        self.auto_compare_timer.start(1000)
        
    def _apply_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        self.setPalette(palette)
        
    def _create_menu(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("Файл")
        
        load_hex1 = QAction("Загрузить HEX1...", self)
        load_hex1.triggered.connect(lambda: self.load_from_file(1))
        file_menu.addAction(load_hex1)
        
        load_hex2 = QAction("Загрузить HEX2...", self)
        load_hex2.triggered.connect(lambda: self.load_from_file(2))
        file_menu.addAction(load_hex2)
        
        file_menu.addSeparator()
        
        save_results = QAction("Сохранить результаты...", self)
        save_results.triggered.connect(self.save_results)
        file_menu.addAction(save_results)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        edit_menu = menubar.addMenu("Правка")
        
        copy_hex1 = QAction("Копировать HEX1", self)
        copy_hex1.triggered.connect(self.copy_hex1)
        edit_menu.addAction(copy_hex1)
        
        copy_hex2 = QAction("Копировать HEX2", self)
        copy_hex2.triggered.connect(self.copy_hex2)
        edit_menu.addAction(copy_hex2)
        
        edit_menu.addSeparator()
        
        swap_action = QAction("Поменять местами", self)
        swap_action.triggered.connect(self.swap_hex)
        edit_menu.addAction(swap_action)
        
        clear_action = QAction("Очистить всё", self)
        clear_action.triggered.connect(self.clear_all)
        edit_menu.addAction(clear_action)
        
        tools_menu = menubar.addMenu("Инструменты")
        
        checksum_action = QAction("Контрольные суммы", self)
        checksum_action.triggered.connect(self.show_checksums)
        tools_menu.addAction(checksum_action)
        
        find_diff = QAction("Найти все различия", self)
        find_diff.triggered.connect(self.find_all_differences)
        tools_menu.addAction(find_diff)
        
    def _create_input_section(self, parent_layout):
        input_group = QGroupBox("Ввод HEX данных")
        input_layout = QVBoxLayout(input_group)
        input_layout.setSpacing(10)
        
        # HEX 1
        hex1_layout = QHBoxLayout()
        hex1_layout.addWidget(QLabel("HEX 1:"))
        
        self.hex1_input = HexLineEdit()
        hex1_layout.addWidget(self.hex1_input, 1)
        
        hex1_btn_layout = QVBoxLayout()
        
        clear1_btn = QPushButton("Очистить")
        clear1_btn.clicked.connect(lambda: self.hex1_input.clear())
        hex1_btn_layout.addWidget(clear1_btn)
        
        paste1_btn = QPushButton("Вставить")
        paste1_btn.clicked.connect(lambda: self.paste_to_input(1))
        hex1_btn_layout.addWidget(paste1_btn)
        
        hex1_layout.addLayout(hex1_btn_layout)
        input_layout.addLayout(hex1_layout)
        
        # HEX 2
        hex2_layout = QHBoxLayout()
        hex2_layout.addWidget(QLabel("HEX 2:"))
        
        self.hex2_input = HexLineEdit()
        hex2_layout.addWidget(self.hex2_input, 1)
        
        hex2_btn_layout = QVBoxLayout()
        
        clear2_btn = QPushButton("Очистить")
        clear2_btn.clicked.connect(lambda: self.hex2_input.clear())
        hex2_btn_layout.addWidget(clear2_btn)
        
        paste2_btn = QPushButton("Вставить")
        paste2_btn.clicked.connect(lambda: self.paste_to_input(2))
        hex2_btn_layout.addWidget(paste2_btn)
        
        hex2_layout.addLayout(hex2_btn_layout)
        input_layout.addLayout(hex2_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.compare_btn = QPushButton("Сравнить")
        self.compare_btn.clicked.connect(self.compare_hex)
        self.compare_btn.setStyleSheet("background-color: #007acc; color: white; font-weight: bold; padding: 8px;")
        btn_layout.addWidget(self.compare_btn)
        
        self.swap_btn = QPushButton("↔ Поменять")
        self.swap_btn.clicked.connect(self.swap_hex)
        btn_layout.addWidget(self.swap_btn)
        
        self.clear_btn = QPushButton("Очистить всё")
        self.clear_btn.clicked.connect(self.clear_all)
        btn_layout.addWidget(self.clear_btn)
        
        btn_layout.addStretch()
        
        self.auto_checkbox = QLabel("Автосравнение")
        btn_layout.addWidget(self.auto_checkbox)
        
        input_layout.addLayout(btn_layout)
        parent_layout.addWidget(input_group)
    
    def _create_comparison_section(self, splitter):
        comparison_group = QGroupBox("Сравнение HEX")
        comparison_layout = QVBoxLayout(comparison_group)
        
        self.comparison_table = ComparisonTable()
        comparison_layout.addWidget(self.comparison_table, 1)
        
        self.stats_label = QLabel()
        self.stats_label.setStyleSheet("font-weight: bold; padding: 5px;")
        comparison_layout.addWidget(self.stats_label)
        
        splitter.addWidget(comparison_group)
    
    def _create_analysis_section(self, splitter):
        analysis_group = QGroupBox("Детальный анализ")
        analysis_layout = QVBoxLayout(analysis_group)
        
        self.tab_widget = QTabWidget()
        
        # HEX tab
        hex_widget = QWidget()
        hex_layout = QVBoxLayout(hex_widget)
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Consolas", 9))
        hex_layout.addWidget(self.hex_text)
        self.tab_widget.addTab(hex_widget, "HEX")
        
        # ASCII tab
        ascii_widget = QWidget()
        ascii_layout = QVBoxLayout(ascii_widget)
        self.ascii_text = QTextEdit()
        self.ascii_text.setReadOnly(True)
        self.ascii_text.setFont(QFont("Consolas", 9))
        ascii_layout.addWidget(self.ascii_text)
        self.tab_widget.addTab(ascii_widget, "ASCII")
        
        # Differences tab
        diff_widget = QWidget()
        diff_layout = QVBoxLayout(diff_widget)
        self.diff_text = QTextEdit()
        self.diff_text.setReadOnly(True)
        self.diff_text.setFont(QFont("Consolas", 9))
        diff_layout.addWidget(self.diff_text)
        self.tab_widget.addTab(diff_widget, "Различия")
        
        analysis_layout.addWidget(self.tab_widget)
        splitter.addWidget(analysis_group)
    
    def paste_to_input(self, input_num):
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip()
        
        if input_num == 1:
            self.hex1_input.set_hex(text)
        else:
            self.hex2_input.set_hex(text)
    
    def auto_compare(self):
        hex1 = HexValidator.normalize_hex(self.hex1_input.text())
        hex2 = HexValidator.normalize_hex(self.hex2_input.text())
        
        if len(hex1) > 1 and len(hex2) > 1:
            self.compare_hex()
    
    def compare_hex(self):
        hex1_raw = self.hex1_input.text()
        hex2_raw = self.hex2_input.text()
        
        hex1 = HexValidator.normalize_hex(hex1_raw)
        hex2 = HexValidator.normalize_hex(hex2_raw)
        
        if not hex1 or not hex2:
            self.status_bar.showMessage("Введите оба HEX значения", 3000)
            return
        
        if not HexValidator.is_valid_hex(hex1):
            QMessageBox.warning(self, "Ошибка", 
                f"Некорректный HEX формат в HEX1\n\n{hex1_raw[:50]}..." if len(hex1_raw) > 50 else hex1_raw)
            return
        
        if not HexValidator.is_valid_hex(hex2):
            QMessageBox.warning(self, "Ошибка",
                f"Некорректный HEX формат в HEX2\n\n{hex2_raw[:50]}..." if len(hex2_raw) > 50 else hex2_raw)
            return
        
        try:
            comparison = self._compare_hex_data(hex1, hex2)
            self.comparison_table.update_data(comparison)
            
            total1 = comparison['len1_bytes']
            total2 = comparison['len2_bytes']
            diffs = comparison['differences']
            
            stats = f"HEX1: {total1} байт | HEX2: {total2} байт | Различий: {diffs}"
            self.stats_label.setText(stats)
            
            self._update_hex_view(hex1, hex2)
            self._update_ascii_view(hex1, hex2)
            self._update_diff_view(comparison)
            
            if diffs == 0:
                self.status_bar.showMessage("✓ HEX данные идентичны", 5000)
            else:
                self.status_bar.showMessage(f"✗ Найдено {diffs} различий", 5000)
                
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сравнения: {str(e)}")
    
    def _compare_hex_data(self, hex1, hex2):
        len1 = len(hex1)
        len2 = len(hex2)
        max_len = max(len1, len2)
        
        result = []
        differences = 0
        
        for i in range(0, max_len, 2):
            if i >= len1:
                byte1 = "??"
                byte2 = hex2[i:i+2] if i < len2 else "??"
            elif i >= len2:
                byte1 = hex1[i:i+2]
                byte2 = "??"
            else:
                byte1 = hex1[i:i+2]
                byte2 = hex2[i:i+2]
            
            byte_num = i // 2
            position = f"0x{byte_num:04X} ({byte_num})"
            
            match = (byte1 == byte2) and (byte1 != "??" and byte2 != "??")
            
            result.append({
                'position': position,
                'hex1': byte1,
                'hex2': byte2,
                'match': match,
                'difference': not match
            })
            
            if not match:
                differences += 1
        
        return {
            'result': result,
            'differences': differences,
            'len1_bytes': len1 // 2,
            'len2_bytes': len2 // 2,
            'len1': len1,
            'len2': len2
        }
    
    def _update_hex_view(self, hex1, hex2):
        hex1_fmt = HexValidator.format_hex(hex1)
        hex2_fmt = HexValidator.format_hex(hex2)
        
        lines1 = [hex1_fmt[i:i+48] for i in range(0, len(hex1_fmt), 48)]
        lines2 = [hex2_fmt[i:i+48] for i in range(0, len(hex2_fmt), 48)]
        
        max_lines = max(len(lines1), len(lines2))
        
        text = "HEX 1:\n"
        for i in range(max_lines):
            line_num = f"{i*16:04X}: "
            if i < len(lines1):
                text += line_num + lines1[i] + "\n"
            else:
                text += line_num + "\n"
        
        text += "\nHEX 2:\n"
        for i in range(max_lines):
            line_num = f"{i*16:04X}: "
            if i < len(lines2):
                text += line_num + lines2[i] + "\n"
            else:
                text += line_num + "\n"
        
        self.hex_text.setPlainText(text)
    
    def _update_ascii_view(self, hex1, hex2):
        try:
            bytes1 = HexValidator.hex_to_bytes(hex1)
            bytes2 = HexValidator.hex_to_bytes(hex2)
            
            ascii1 = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bytes1)
            ascii2 = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bytes2)
            
            lines1 = [ascii1[i:i+16] for i in range(0, len(ascii1), 16)]
            lines2 = [ascii2[i:i+16] for i in range(0, len(ascii2), 16)]
            
            max_lines = max(len(lines1), len(lines2))
            
            text = "HEX 1 ASCII:\n"
            for i in range(max_lines):
                line_num = f"{i*16:04X}: "
                if i < len(lines1):
                    text += line_num + lines1[i] + "\n"
                else:
                    text += line_num + "\n"
            
            text += "\nHEX 2 ASCII:\n"
            for i in range(max_lines):
                line_num = f"{i*16:04X}: "
                if i < len(lines2):
                    text += line_num + lines2[i] + "\n"
                else:
                    text += line_num + "\n"
            
            self.ascii_text.setPlainText(text)
        except:
            self.ascii_text.setPlainText("Ошибка преобразования в ASCII")
    
    def _update_diff_view(self, comparison):
        if not comparison['result']:
            self.diff_text.setPlainText("Нет данных для сравнения")
            return
        
        text = "Обнаруженные различия:\n" + "=" * 50 + "\n\n"
        
        diff_count = 0
        for item in comparison['result']:
            if item['difference']:
                text += f"Позиция {item['position']}:\n"
                text += f"  HEX1: {item['hex1']}\n"
                text += f"  HEX2: {item['hex2']}\n"
                text += "-" * 30 + "\n"
                diff_count += 1
        
        if diff_count == 0:
            text = "Различий не обнаружено"
        
        self.diff_text.setPlainText(text)
    
    def swap_hex(self):
        hex1 = self.hex1_input.text()
        hex2 = self.hex2_input.text()
        self.hex1_input.setText(hex2)
        self.hex2_input.setText(hex1)
    
    def clear_all(self):
        self.hex1_input.clear()
        self.hex2_input.clear()
        self.comparison_table.setRowCount(0)
        self.hex_text.clear()
        self.ascii_text.clear()
        self.diff_text.clear()
        self.stats_label.clear()
        self.status_bar.showMessage("Готов")
    
    def copy_hex1(self):
        hex1 = HexValidator.normalize_hex(self.hex1_input.text())
        if hex1:
            pyperclip.copy(hex1)
            self.status_bar.showMessage("HEX1 скопирован", 2000)
    
    def copy_hex2(self):
        hex2 = HexValidator.normalize_hex(self.hex2_input.text())
        if hex2:
            pyperclip.copy(hex2)
            self.status_bar.showMessage("HEX2 скопирован", 2000)
    
    def load_from_file(self, num):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Выберите файл для HEX{num}",
            "",
            "Все файлы (*.*);;Двоичные файлы (*.bin);;Текстовые файлы (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    hex_data = data.hex().upper()
                    
                    if num == 1:
                        self.hex1_input.set_hex(hex_data)
                    else:
                        self.hex2_input.set_hex(hex_data)
                    
                    filename = os.path.basename(file_path)
                    self.status_bar.showMessage(f"Загружен {filename} ({len(data)} байт)", 3000)
                    
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить файл:\n{str(e)}")
    
    def save_results(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить результаты сравнения",
            "hex_comparison.txt",
            "Текстовые файлы (*.txt);;Все файлы (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Результаты сравнения HEX\n")
                    f.write(f"Создано: {QDateTime.currentDateTime().toString()}\n\n")
                    f.write(f"HEX 1: {self.hex1_input.text()}\n")
                    f.write(f"HEX 2: {self.hex2_input.text()}\n\n")
                    f.write(self.diff_text.toPlainText())
                
                self.status_bar.showMessage(f"Результаты сохранены в {os.path.basename(file_path)}", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл:\n{str(e)}")
    
    def show_checksums(self):
        hex1 = HexValidator.normalize_hex(self.hex1_input.text())
        hex2 = HexValidator.normalize_hex(self.hex2_input.text())
        
        if not hex1 or not hex2:
            QMessageBox.warning(self, "Предупреждение", "Введите оба HEX значения")
            return
        
        try:
            data1 = bytes.fromhex(hex1)
            data2 = bytes.fromhex(hex2)
            
            md5_1 = hashlib.md5(data1).hexdigest()
            md5_2 = hashlib.md5(data2).hexdigest()
            
            sha1_1 = hashlib.sha1(data1).hexdigest()
            sha1_2 = hashlib.sha1(data2).hexdigest()
            
            sha256_1 = hashlib.sha256(data1).hexdigest()
            sha256_2 = hashlib.sha256(data2).hexdigest()
            
            text = "Контрольные суммы:\n\n"
            text += f"MD5:\nHEX1: {md5_1}\nHEX2: {md5_2}\n\n"
            text += f"SHA-1:\nHEX1: {sha1_1}\nHEX2: {sha1_2}\n\n"
            text += f"SHA-256:\nHEX1: {sha256_1}\nHEX2: {sha256_2}"
            
            msg = QMessageBox(self)
            msg.setWindowTitle("Контрольные суммы")
            msg.setText("Хэш-суммы данных:")
            msg.setDetailedText(text)
            msg.exec()
            
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось вычислить контрольные суммы:\n{str(e)}")
    
    def find_all_differences(self):
        hex1 = HexValidator.normalize_hex(self.hex1_input.text())
        hex2 = HexValidator.normalize_hex(self.hex2_input.text())
        
        if not hex1 or not hex2:
            QMessageBox.warning(self, "Предупреждение", "Введите оба HEX значения")
            return
        
        try:
            comparison = self._compare_hex_data(hex1, hex2)
            
            if comparison['differences'] == 0:
                QMessageBox.information(self, "Информация", "Различий не найдено")
            else:
                text = f"Найдено {comparison['differences']} различий\n\n"
                
                count = 0
                for item in comparison['result']:
                    if item['difference'] and count < 15:
                        text += f"Позиция {item['position']}: {item['hex1']} → {item['hex2']}\n"
                        count += 1
                
                if comparison['differences'] > 15:
                    text += f"\n... и еще {comparison['differences'] - 15} различий"
                
                QMessageBox.information(self, "Найденные различия", text)
                
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Ошибка поиска различий:\n{str(e)}")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = HexCompareTool()
    window.show()
    
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

# ==========================================
# Автор: https://github.com/Xyamma
# Лицензия: Apache 2.0
# ==========================================
