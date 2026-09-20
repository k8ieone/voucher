# keys.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk

from .key_row import VoucherKeyRow
from .lnutils import generate_key

@Gtk.Template(resource_path='/one/k8ie/Voucher/pages/keys.ui')
class VoucherKeysTab(Adw.NavigationPage):
    __gtype_name__ = 'VoucherKeysTab'

    keys_list = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @Gtk.Template.Callback()
    def on_show(self, widget):
        keys = self.get_root().settings.get_strv("identities")
        for key in keys:
            self.keys_list.add(VoucherKeyRow(key_name=key))

    @Gtk.Template.Callback()
    def new_key(self, widget):
        generate_key(_("New Key"), self.get_root().settings)
        self.keys_list.add(VoucherKeyRow(key_name=_("New Key")))
