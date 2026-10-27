#!/usr/bin/env python3
"""
Android Security Audit Script - Termux Compatible
Analyzes device permissions, checks installed APK security,
and provides hardening recommendations for Android security setup.
Works both on device (via Termux) and for pre-analysis of APKs.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime


def check_apk_security(apk_path):
    """Analyze APK for security-relevant permissions and components."""
    try:
        tree = ET.parse(apk_path)
        root = tree.getroot()
        manifest = root.find('.{http://schemas.android.com/apk/res/android}manifest')
        if manifest is None:
            return None
        
        # Get declared uses-permissions
        uses_perms = manifest.findall('.//{http://schemas.android.com/apk/res/android}uses-permission')
        required_permissions = [perm.get('name') for perm in uses_perms]
        
        # Get permissions installed with the app
        perms_element = manifest.find('.//{http://schemas.android.com/apk/res/android}permission')
        declared_permissions = []
        if perms_element is not None:
            for p in perms_element:
                declared_permissions.append(p.get('name'))
        
        # Categorize by risk
        dangerous_keywords = [
            'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
            'READ_CALL_LOG', 'READ_PHONE_STATE',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE', 'WRITE_SECURE_SETTINGS',
            'SYSTEM_ALERT_WINDOW', 'BIND_DEVICE_ADMIN',
            'ACCESS_WIFI_STATE', 'CHANGE_WIFI_STATE',
            'INTERNET', 'FOREGROUND_SERVICE'
        ]
        
        dangerous_found = []
        normal_found = []
        
        for perm in required_permissions:
            perm_upper = perm.upper()
            if any(kw in perm_upper for kw in dangerous_keywords):
                dangerous_found.append(perm)
            else:
                normal_found.append(perm)
        
        # Assess risk level
        high_risk = ['READ_SMS', 'SEND_SMS', 'RECORD_AUDIO', 
                     'WRITE_SECURE_SETTINGS', 'SYSTEM_ALERT_WINDOW']
        high_found = [p for p in dangerous_found if p in high_risk]
        
        if len(high_found) >= 3:
            risk_level = 'CRITICAL'
        elif len(high_found) >= 1 or len(dangerous_found) >= 5:
            risk_level = 'HIGH'
        elif len(dangerous_found) >= 2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'apk_name': os.path.basename(apk_path),
            'required_permissions': required_permissions,
            'declared_permissions': declared_permissions,
            'dangerous': dangerous_found,
            'normal': normal_found,
            'high_risk': high_found,
            'risk_level': risk_level
        }
    except Exception as e:
        print(f"Error analyzing {apk_path}: {e}", file=sys.stderr)
        return None

def generate_security_report(apk_directory='/sdcard/Download'):
    """Generate comprehensive security report from APK analysis."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'analysis_type': 'android_security_audit',
        'apk_analysis': [],
        'overall_assessment': 'UNKNOWN'
    }
    
    if os.path.exists(apk_directory):
        for fname in sorted(os.listdir(apk_directory)):
            if fname.endswith('.apk'):
                fpath = os.path.join(apk_directory, fname)
                result = check_apk_security(fpath)
                if result:
                    report['apk_analysis'].append(result)
    
    # Calculate overall assessment
    total_high_risk = sum(len(a['high_risk']) for a in report['apk_analysis'])
    total_dangerous = sum(len(a['dangerous']) for a in report['apk_analysis'])
    
    if total_high_risk >= 5:
        report['overall_assessment'] = 'CRITICAL'
    elif total_high_risk >= 2:
        report['overall_assessment'] = 'HIGH'
    elif total_high_risk >= 1 or total_dangerous >= 5:
        report['overall_assessment'] = 'MEDIUM'
    elif total_dangerous >= 1:
        report['overall_assessment'] = 'LOW'
    else:
        report['overall_assessment'] = 'MINIMAL'
    
    return report

def check_shizuku_permissions():
    """Check Shizuku API permissions via dumpsys."""
    try:
        result = subprocess.run(
            ['adb', 'shell', 'dumpsys', 'package', 'moe.shizuku.privileged.api'],
            capture_output=True, text=True, timeout=10
        )
        # Parse key permissions from dumpsys output
        output = result.stdout + result.stderr
        
        perms = {}
        # dumpsys lines look like "    android.permission.X: granted=true"
        for name, state in re.findall(r'^\s*([\w.]+): granted=(true|false)', output, re.MULTILINE):
            perms[name] = state == 'true'
        
        return {
            'install_permissions': perms,
            'raw_output': output[:500] if output else 'No output'
        }
    except Exception as e:
        return {'error': str(e)}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Audit APK permissions on Android (Termux) or pre-analyze APKs on a computer.')
    parser.add_argument('apk_dir', nargs='?', default='/sdcard/Download',
                        help='directory containing .apk files (default: /sdcard/Download)')
    parser.add_argument('output', nargs='?', default='/sdcard/Download/security_audit_report.json',
                        help='JSON report path (default: /sdcard/Download/security_audit_report.json)')
    args = parser.parse_args()

    report = generate_security_report(args.apk_dir)
    output_file = args.output
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print("Security Audit Complete")
    print(f"APKs analyzed: {len(report['apk_analysis'])}")
    print(f"Overall assessment: {report['overall_assessment']}")
    print(f"Report saved to: {output_file}")
    
    for apk in report['apk_analysis']:
        print(f"\n{apk['apk_name']}: {apk['risk_level']} risk")
        print(f"  High-risk perms: {apk['high_risk']}")
        print(f"  All dangerous: {apk['dangerous']}")