pkgdatadir = get_option('prefix') / get_option('datadir') / meson.project_name()
moduledir = pkgdatadir / 'voucher'
gnome = import('gnome')
blueprints = custom_target('blueprints',
  input: files(
    'window.blp',
    'shortcuts-dialog.blp',
    'widgets/menu-button.blp',
    'widgets/spinner-dialog.blp',
    'pages/confirmation.blp',
    'pages/keys.blp',
    'pages/sites.blp',
    'pages/status.blp'
  ),
  output: '.',
  command: [find_program('blueprint-compiler'), 'batch-compile', '@OUTPUT@', '@CURRENT_SOURCE_DIR@', '@INPUT@'],
)

gnome.compile_resources('voucher',
  'voucher.gresource.xml',
  gresource_bundle: true,
  install: true,
  install_dir: pkgdatadir,
  dependencies: blueprints,
)

python = import('python')

conf = configuration_data()
conf.set('PYTHON', python.find_installation('python3').full_path())
conf.set('VERSION', meson.project_version())
conf.set('localedir', get_option('prefix') / get_option('localedir'))
conf.set('pkgdatadir', pkgdatadir)

configure_file(
  input: 'voucher.in',
  output: 'voucher',
  configuration: conf,
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'r-xr-xr-x'
)

voucher_sources = [
  '__init__.py',
  'lnutils.py',
  'main.py',
  'window.py',
  'widgets/menu_button.py',
  'widgets/spinner_dialog.py',
  'pages/confirmation.py',
  'pages/keys.py',
  'pages/sites.py',
  'pages/status.py'
]

install_data(voucher_sources, install_dir: moduledir)
