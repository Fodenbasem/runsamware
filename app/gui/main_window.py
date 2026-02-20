"""Minimal PySide6 GUI skeleton for the app."""
from PySide6 import QtWidgets


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, controller=None):
        super().__init__()
        self.controller = controller
        self.setWindowTitle("NovaVault")
        self._init_ui()

    def _init_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        self.status = QtWidgets.QLabel("Ready")
        layout.addWidget(self.status)

        btn = QtWidgets.QPushButton("Encrypt File")
        btn.clicked.connect(self._on_encrypt)
        layout.addWidget(btn)

        central.setLayout(layout)
        self.setCentralWidget(central)

    def _on_encrypt(self):
        self.status.setText("Encrypt action triggered")
        if self.controller:
            self.controller.handle_encrypt()
