# spinner_dialog.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk

@Gtk.Template(resource_path='/one/k8ie/Voucher/widgets/spinner-dialog.ui')
class VoucherSpinnerDialog(Adw.AlertDialog):
    __gtype_name__ = 'VoucherSpinnerDialog'
