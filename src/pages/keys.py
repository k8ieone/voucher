# keys.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk

# from

@Gtk.Template(resource_path='/one/k8ie/Voucher/pages/keys.ui')
class VoucherKeysTab(Adw.NavigationPage):
    __gtype_name__ = 'VoucherKeysTab'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @Gtk.Template.Callback()
    def on_show(self, widget):
        print(self.get_root().settings)
