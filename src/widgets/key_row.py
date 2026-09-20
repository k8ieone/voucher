# key_row.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk
from gi.repository import GObject

from .key_info_dialog import VoucherKeyInfoDialog

@Gtk.Template(resource_path='/one/k8ie/Voucher/widgets/key-row.ui')
class VoucherKeyRow(Adw.ActionRow):
    __gtype_name__ = 'VoucherKeyRow'

    key_name = GObject.Property(type=str, default="unknown")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title(self.key_name)

    @Gtk.Template.Callback()
    def on_click(self, widget):
        # self.get_root().authenticate()
        VoucherKeyInfoDialog(key_name=self.key_name).present(parent=self.get_root())
