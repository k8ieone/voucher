# key_info_dialog.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk
from gi.repository import GObject

@Gtk.Template(resource_path='/one/k8ie/Voucher/widgets/key-info-dialog.ui')
class VoucherKeyInfoDialog(Adw.PreferencesDialog):
    __gtype_name__ = 'VoucherKeyInfoDialog'

    key_name = GObject.Property(type=str, default="unknown")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title(self.key_name)
