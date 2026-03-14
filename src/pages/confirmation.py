# confirmation.py
# Copyright 2026 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk
from gi.repository import GObject

@Gtk.Template(resource_path='/one/k8ie/Voucher/pages/confirmation.ui')
class VoucherConfirmationPage(Adw.NavigationPage):
    __gtype_name__ = 'VoucherConfirmationPage'
    confirmation_status_page = Gtk.Template.Child()
    address = GObject.Property(type=str, default="unknown")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.confirmation_status_page.set_title(self.address)

    @Gtk.Template.Callback()
    def on_confirm(self, widget):
        #self.pop
        #self.get_parent().pop()
        self.get_root().authenticate()

    @Gtk.Template.Callback()
    def on_cancel(self, widget):
        #self.pop
        self.get_parent().pop()
