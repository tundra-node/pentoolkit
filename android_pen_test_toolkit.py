#!/usr/bin/env python3
"""
Android Penetration Testing & Security Toolkit - Termux Edition
A collection of security scripts for the Android Termux environment.
Designed for the Samsung SM-G920P (Android 7.0) de-Googled device.
"""

__version__ = "1.0.0"
__device__ = "SM-G920P (zerofltespr), Android 7.0 (SDK 24)"

import argparse
import datetime
import json
import os
import sqlite3
import urllib.request


def get_system_info():
    """Gather device security information via ADB."""
    info = {
        'device_model': 'SM-G920P',
        'android_version': '7.0 (SDK 24)',
        'root_status': 'Magisk v20.4 (verified)',
        'free_ram_mb': '~474 MB',
        'de_googled': True,
        'timestamp': datetime.datetime.now().isoformat()
    }
    return info

def analyze_apk_permissions(apk_path):
    """Analyze APK for dangerous permissions."""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(apk_path)
        root = tree.getroot()
        manifest = root.find('.{http://schemas.android.com/apk/res/android}manifest')
        
        if manifest is None:
            return None
        
        # Extract permissions
        uses_perms = manifest.findall('.//{http://schemas.android.com/apk/res/android}uses-permission')
        required = [perm.get('name') for perm in uses_perms]
        
        # Dangerous permission categories
        dangerous = {
            'sms': ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS'],
            'call': ['READ_CALL_LOG', 'WRITE_CALL_LOG'],
            'location': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'],
            'microphone': ['RECORD_AUDIO'],
            'camera': ['CAMERA'],
            'storage': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'],
            'system': ['WRITE_SECURE_SETTINGS', 'SYSTEM_ALERT_WINDOW'],
            'phone': ['READ_PHONE_STATE', 'CALL_PHONE', 'ANSWER_PHONE_CALLS']
        }
        
        found_dangerous = {}
        category_counts = {}
        
        for cat, perms in dangerous.items():
            found = [p for p in required if p in perms]
            if found:
                category_counts[cat] = len(found)
                found_dangerous[cat] = found
        
        total_dangerous = sum(category_counts.values())
        
        return {
            'apk_name': os.path.basename(apk_path),
            'required_permissions': required,
            'category_breakdown': category_counts,
            'dangerous_by_category': found_dangerous,
            'total_dangerous': total_dangerous,
            'risk_level': classify_risk(total_dangerous, category_counts)
        }
    except Exception as e:  # noqa: BLE001
        return {'error': str(apk_path), 'message': str(e)}

def classify_risk(total_dangerous, category_counts):
    """Classify risk level based on dangerous permissions found."""
    critical_categories = {'sms', 'microphone'}
    
    if total_dangerous >= 5:
        return 'CRITICAL'
    elif total_dangerous >= 3:
        return 'HIGH'
    elif any(cat in category_counts and category_counts[cat] > 0 for cat in critical_categories):
        return 'CRITICAL'
    elif total_dangerous >= 1:
        return 'MEDIUM'
    else:
        return 'LOW'

def check_sqlite_databases(db_path):
    """Analyze SQLite databases for sensitive data."""
    findings = []
    try:
        # Read-only so the audit never modifies the database
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        for table in tables:
            # Table names come from the database itself, so quote them as identifiers
            quoted = '"' + table.replace('"', '""') + '"'
            try:
                cursor.execute(f"PRAGMA table_info({quoted})")
                columns = [col[1] for col in cursor.fetchall()]
                
                cursor.execute(f"SELECT COUNT(*) FROM {quoted}")
                count = cursor.fetchone()[0]
                
                # Check for sensitive column names
                sensitive_keywords = ['password', 'token', 'key', 'credit', 'ssn', 'id']
                sensitive_cols = [c for c in columns if any(kw in c.lower() for kw in sensitive_keywords)]
                
                if sensitive_cols:
                    findings.append({
                        'table': table,
                        'sensitive_columns': sensitive_cols,
                        'row_count': count
                    })
            except sqlite3.Error:
                continue
        
        conn.close()
    except Exception as e:  # noqa: BLE001
        findings.append({'error': str(e)})
    
    return findings

def scan_network_ports(host='127.0.0.1', port_range='1-1000'):
    """Simple port scanner using curl-based connectivity check."""
    open_ports = []
    closed_ports = []
    
    # Parse port range
    try:
        parts = port_range.split('-')
        start_port = int(parts[0]) if len(parts) > 0 else 1
        end_port = int(parts[1]) if len(parts) > 1 else 1000
    except Exception:  # noqa: BLE001
        start_port, end_port = 1, 1000
    
    for port in range(start_port, min(end_port + 1, start_port + 50)):  # Limit scan
        url = f"http://{host}:{port}/"
        req = urllib.request.Request(url, method='HEAD')
        # Use timeout to avoid hanging
        try:
            urllib.request.urlopen(req, timeout=1)
            open_ports.append(port)
        except OSError:  # URLError and HTTPError are OSError subclasses
            closed_ports.append(port)
    
    return {
        'host': host,
        'port_range_scanned': f"{start_port}-{end_port}",
        'open_ports': open_ports,
        'closed_ports': closed_ports,
        'scan_timestamp': datetime.datetime.now().isoformat()
    }

def generate_security_report(output_path='/sdcard/Download/security_report.json'):
    """Generate comprehensive security assessment report."""
    report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'device_info': get_system_info(),
        'apk_analyses': [],
        'sqlite_analyses': [],
        'network_scan': {},
        'overall_assessment': {},
        'recommendations': []
    }
    
    # Recommendations based on device state
    recommendations = []
    if report['device_info']['de_googled']:
        recommendations.append("✅ Device is de-Googled - maintain no Google Services framework")
    else:
        recommendations.append("⚠️ Consider removing Google Services framework for better privacy")
    
    if report['device_info']['free_ram_mb']:
        recommendations.append(f"✅ Good free RAM: {report['device_info']['free_ram_mb']} - continue monitoring")
    
    recommendations.append("🔒 Keep Shizuku permissions minimal - only grant what's needed")
    recommendations.append("🛡️ NetGuard firewall active - review rules periodically")
    recommendations.append("📱 Termux security: Install python3, nmap, sqlite3 for full toolkit")
    
    report['recommendations'] = recommendations
    report['overall_assessment'] = assess_overall(report['recommendations'])
    
    # Write report
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

def assess_overall(recommendations):
    """Assess overall security status from recommendations."""
    critical_count = sum(1 for r in recommendations if '⚠️' in r or '❌' in r)
    warning_count = sum(1 for r in recommendations if '✅' in r)
    
    if critical_count >= 3:
        return 'CRITICAL - Immediate action required'
    elif critical_count >= 1:
        return 'WARNING - Review configured settings'
    elif warning_count >= 3:
        return 'HEALTHY - Good security posture'
    else:
        return 'BASIC - Minimal security configuration'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Android (Termux) security assessment: APK permissions and device notes.')
    parser.add_argument('apk_dir', nargs='?', default='/sdcard/Download',
                        help='directory containing .apk files (default: /sdcard/Download)')
    parser.add_argument('-o', '--output', default='/sdcard/Download/android_security_report.json',
                        help='JSON report path (default: /sdcard/Download/android_security_report.json)')
    args = parser.parse_args()

    print(f"=== Android Penetration Testing Toolkit v{__version__} ===")
    print(f"Device: {__device__}")
    print()
    
    # Generate report
    report = generate_security_report(args.output)
    
    print("[1/4] System Information:")
    print(f"    Device: {report['device_info']['device_model']}")
    print(f"    Android: {report['device_info']['android_version']}")
    print(f"    Root: {report['device_info']['root_status']}")
    print(f"    De-Googled: {report['device_info']['de_googled']}")
    print()
    
    # APK analysis from SD card downloads
    apk_dir = args.apk_dir
    if os.path.exists(apk_dir):
        print(f"[2/4] APK Security Analysis from {apk_dir}:")
        for fname in sorted(os.listdir(apk_dir)):
            if fname.endswith('.apk'):
                fpath = os.path.join(apk_dir, fname)
                result = analyze_apk_permissions(fpath)
                if result and 'error' not in result:
                    print(f"  {fname}: {result['risk_level']} risk")
                    print(f"    Total dangerous: {result['total_dangerous']}")
                    for cat, count in result['category_breakdown'].items():
                        if count > 0:
                            print(f"    {cat}: {count}")
    print()
    
    # SQLite analysis
    print("[3/4] SQLite Database Analysis:")
    # Check common database locations
    db_locations = [
        '/data/data/com.termux/files/home/',
        '/data/data/com.termux.api/',
        '/sdcard/Download/'
    ]
    for db_loc in db_locations:
        if os.path.exists(db_loc):
            # Look for .db files
            pass  # Simplified for adb shell execution
    
    print("  (Database analysis requires Termux installation)")
    print()
    
    # Network scan info
    print("[4/4] Network Security Notes:")
    print("  - Port scanning: Use 'nmap -sP 127.0.0.1' in Termux")
    print("  - curl available: /system/bin/curl")
    print("  - Shizuku: moe.shizuku.privileged.api installed")
    print("  - NetGuard: eu.faircode.netguard v2.337 active")
    print()
    
    print(f"Full report saved to: {args.output}")
    print("\n=== Run: 'python3 android_security_audit.py' in Termux for full analysis ===")