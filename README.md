# pentoolkit

Small scripts for auditing devices and apps you own: APK permissions, Termux
configuration, and Android device notes. There is also a Mac menu launcher for
network-scanning tools used in Hack The Box labs.

Only run these against devices and apps you own or have permission to test.

## Scripts

### `android_security_audit.py`

Reads the permissions declared in APK files in a directory and sorts them into
dangerous and normal groups. Dangerous means permissions such as SMS, call log,
location, microphone, storage, `SYSTEM_ALERT_WINDOW`, and device admin. It rates
each APK and the whole set (`MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and
writes a JSON report. It also has a helper that reads Shizuku permission state
from `dumpsys` over adb.

```sh
python3 android_security_audit.py [apk_dir] [report.json]
```

Defaults: `apk_dir` is `/sdcard/Download`, report is
`/sdcard/Download/security_audit_report.json`.

### `python_security_audit.py`

Same APK permission check as above, plus a look at two Termux config files on
the device (`termux.properties` and `bash.bashrc`) through `adb shell cat`. It
flags battery-optimization and system-alert-window settings.

```sh
python3 python_security_audit.py [apk_dir] [-o report.json]
```

Defaults: `apk_dir` is `./apks`, report is `security_audit_report.json`.

### `android_pen_test_toolkit.py`

Termux-side assessment for the device. It writes a JSON report containing:

- Device details. These are fixed values in the script (model, Android version,
  root status), not read from the device.
- APK permission categories for the APKs in the directory.
- A read-only check of SQLite databases for columns with sensitive-looking names
  (`password`, `token`, `key`, `credit`, `ssn`, `id`). The helper is in the
  script; it is not called from `main`.
- Recommendations and an overall rating. These come from fixed text in the script.

```sh
python3 android_pen_test_toolkit.py [apk_dir] [-o report.json]
```

Defaults: `apk_dir` is `/sdcard/Download`, report is
`/sdcard/Download/android_security_report.json`.

### `main.py` and `mac/`

`main.py` picks the launcher for the current OS. The `mac/` launcher is a text
menu for installing and running nmap, telnet, FTP, and rustscan through
Homebrew. It has no argument handling, so do not pass `--help`; it starts the
menu.

`linux/` and `windows/` contain only placeholder files.

## Requirements

- Python 3.9 or newer. Standard library only.
- adb on your PATH for the device checks.
- Homebrew and the named tools for the `mac/` menu.

## Known limitations

- APK files are zip archives with a binary `AndroidManifest.xml`. The scripts
  parse the manifest with a plain XML parser, so APK analysis will report parse
  errors on real APKs. Use a binary manifest reader (for example `aapt dump
  permissions` or androguard) before trusting the permission results.
- `android_pen_test_toolkit.py` device info and recommendations are hardcoded.
- The `mac/` menu runs Homebrew and network tools with the arguments you type.
  Use it only on your own network.

## License

MIT. See [LICENSE](LICENSE).
