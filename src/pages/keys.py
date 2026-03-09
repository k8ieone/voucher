# menu_button.py
# Copyright 2025 Kate
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw
from gi.repository import Gtk

@Gtk.Template(resource_path='/one/k8ie/Voucher/pages/keys.ui')
class VoucherKeysTab(Adw.NavigationPage):
    __gtype_name__ = 'VoucherKeysTab'
