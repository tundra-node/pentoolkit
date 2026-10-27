#!/usr/bin/env python3
"""
Python Security Audit Script for Android Termux Environment
Analyzes permissions, identifies potential security issues,
and provides recommendations for hardening the Android environment.
"""

import xml.etree.ElementTree as ET
import json
import sys
import os
from datetime import datetime

def check_apk_permissions(apk_path):
    """Analyze APK permissions and report risk level."""
    try:
        tree = ET.parse(apk_path)
        root = tree.getroot()
        
        # Get the manifest
        manifest = root.find('{http://schemas.android.com/apk/res/android}manifest')
        if manifest is None:
            return None
            
        # Get declared permissions
        perms = manifest.findall('.//{http://schemas.android.com/apk/res/android}permission')
        declared_permissions = [perm.get('name') for perm in perms]
        
        # Get uses-permission entries
        uses_perms = manifest.findall('.//{http://schemas.android.com/apk/res/android}uses-permission')
        required_permissions = [perm.get('name') for perm in uses_perms]
        
        # Categorize permissions by protection level
        dangerous = []
        normal = []
        dangerous_prefixes = ['android.permission.', 'com.'].
        
        for perm in required_permissions:
            if perm.startswith('android.permission.'):
                if any(perm.startswith(prefix) for prefix in [
                    'android.permission.READ_SMS',
                    'android.permission.SEND_SMS',
                    'android.permission.READ_CALL_LOG',
                    'android.permission.READ_PHONE_STATE',
                    'android.permission.LOCATION',
                    'android.permission.CAMERA',
                    'android.permission.MICROPHONE',
                    'android.permission.RECORD_AUDIO',
                ]):
                    dangerous.append(perm)
                else:
                    normal.append(perm)
            elif perm.startswith('com.'):
                dangerous.append(perm)
            else:
                normal.append(perm)
        
        return {
            'declared': declared_permissions,
            'required': required_permissions,
            'dangerous': dangerous,
            'normal': normal,
            'risk_level': 'HIGH' if len(dangerous) > 5 else 'MEDIUM' if len(dangerous) > 2 else 'LOW'
        }
    except Exception as e:
        print(f"Error analyzing {apk_path}: {e}")
        return None

def check_termux_config():
    """Check Termux configuration for security issues."""
    config_paths = [
        '/data/data/com.termux/files/usr/etc/termux.properties',
        '/data/data/com.termux/files/usr/etc/bash.bashrc',
    ]
    
    findings = []
    for path in config_paths:
        try:
            # Try to read the file via adb
            result = os.popen(f'adb shell "cat {path}"').read()
            if 'request_ignore_battery_optimizations' in result.lower():
                findings.append(f'{path}: Battery optimization disabled - may impact system performance')
            if 'system_alert_window' in result.lower():
                findings.append(f'{path}: System alert window setting present')
        except:
            pass
    
    return findings

def generate_security_report(apk_dir, output_file='security_audit_report.json'):
    """Generate comprehensive security audit report."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'analysis_type': 'android_security_audit',
        'apk_analysis': [],
        'config_findings': [],
        'overall_assessment': 'UNKNOWN'
    }
    
    # Analyze APKs in directory
    if os.path.exists(apk_dir):
        for fname in os.listdir(apk_dir):
            if fname.endswith('.apk'):
                fpath = os.path.join(apk_dir, fname)
                result = check_apk_permissions(fpath)
                if result:
                    report['apk_analysis'].append({
                        'filename': fname,
                        **result
                    })
    
    # Check Termux config
    config_findings = check_termux_config()
    report['config_findings'] = config_findings
    
    # Overall assessment
    total_dangerous = sum(len(a['dangerous']) for a in report['apk_analysis'])
    if total_dangerous > 10:
        report['overall_assessment'] = 'CRITICAL'
    elif total_dangerous > 5:
        report['overall_assessment'] = 'HIGH'
    elif total_dangerous > 2:
        report['overall_assessment'] = 'MEDIUM'
    else:
        report['overall_assessment'] = 'LOW'
    
    # Write report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

if __name__ == '__main__':
    apk_dir = sys.argv[1] if len(sys.argv) > 1 else '/Users/elias/s6-apks'
    report = generate_security_report(apk_dir)
    
    print(f"Security Audit Complete")
    print(f"Overall Assessment: {report['overall_assessment']}")
    print(f"Total dangerous permissions across {len(report['apk_analysis'])} APKs: {sum(len(a['dangerous']) for a in report['apk_analysis'])}")
    print(f"Report saved to: security_audit_report.json")
    
    # Print summary
    for apk in report['apk_analysis']:
        print(f"\n{apk['filename']}: {apk['risk_level']} risk")
        print(f"  Dangerous perms: {apk['dangerous']}")
        print(f"  Normal perms: {apk['normal']}")