"""AWS IAM credential auditor. No identity or permission mutations."""
import argparse
import csv
import io
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def date(value):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None


def evaluate(rows, now, inactivity=90, key_age=90, grace=30):
    findings = []
    def add(control, resource, status, severity, evidence, recommendation):
        findings.append(dict(control=control, resource=resource, status=status,
                             severity=severity, evidence=evidence, recommendation=recommendation))
    for row in rows:
        user = row['user']
        root = user == '<root_account>'
        console = row.get('password_enabled') == 'true'
        mfa = row.get('mfa_active')
        if root or console:
            status = 'PASS' if mfa == 'true' else 'FAIL' if mfa == 'false' else 'ERROR'
            add('IAM-001' if root else 'IAM-003', user, status,
                None if status == 'PASS' else 'HIGH' if root else 'MEDIUM',
                {'mfa_active': mfa, 'password_enabled': row.get('password_enabled')},
                'Review MFA configuration; centrally managed root credentials require contextual review.')
        if root:
            states = [row.get(f'access_key_{i}_active') for i in (1, 2)]
            status = 'FAIL' if 'true' in states else 'PASS' if states == ['false', 'false'] else 'ERROR'
            add('IAM-002', user, status, 'CRITICAL' if status == 'FAIL' else None,
                {'active_key_flags': states}, 'Remove root access keys manually after reviewing dependencies.' if status == 'FAIL' else 'No active root key observed; inactive-key absence is not established.')
            continue
        for i in (1, 2):
            active = row.get(f'access_key_{i}_active')
            if active != 'true':
                continue
            rotated = date(row.get(f'access_key_{i}_last_rotated'))
            used = date(row.get(f'access_key_{i}_last_used_date'))
            age = (now - rotated).days if rotated else None
            add('IAM-004', user, 'WARN' if age is None or age >= key_age or used is None else 'INFO',
                'MEDIUM' if age is not None and age >= key_age else 'LOW',
                {'key_slot': i, 'age_days': age, 'last_used': used.isoformat() if used else None},
                'Review justification and migrate to temporary credentials where appropriate.')
        created = date(row.get('user_creation_time'))
        activity = [date(row.get('password_last_used'))] + [date(row.get(f'access_key_{i}_last_used_date')) for i in (1, 2)]
        observed = [item for item in activity if item]
        last = max(observed) if observed else None
        if created is None:
            status, reason = 'ERROR', 'Creation time unavailable'
        elif (now - created).days < grace:
            status, reason = 'INFO', 'New account within grace period'
        elif last is None:
            status, reason = 'WARN', 'No activity observed in credential report'
        elif (now - last).days >= inactivity:
            status, reason = 'WARN', 'Observed credential activity exceeds inactivity threshold'
        else:
            status, reason = 'PASS', 'Recent credential activity observed'
        add('IAM-005', user, status, 'LOW' if status == 'WARN' else None,
            {'reason': reason, 'last_observed_activity': last.isoformat() if last else None},
            'Corroborate with CloudTrail before treating the identity as unused.')
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, help='Explicit AWS SSO profile')
    parser.add_argument('--expected-account', required=True, help='Expected 12-digit account ID')
    parser.add_argument('--output', default='reports/audit-report.json')
    parser.add_argument('--inactivity-days', type=int, default=90)
    parser.add_argument('--key-age-days', type=int, default=90)
    parser.add_argument('--grace-days', type=int, default=30)
    args = parser.parse_args(argv)
    if not (args.expected_account.isdigit() and len(args.expected_account) == 12):
        parser.error('expected-account must contain 12 digits')
    if min(args.inactivity_days, args.key_age_days, args.grace_days) < 1:
        parser.error('thresholds must be positive')
    report = {'schema_version': '1.0', 'started_at': datetime.now(timezone.utc).isoformat(),
              'coverage': ['IAM-001', 'IAM-002', 'IAM-003', 'IAM-004', 'IAM-005'],
              'scope': 'Single account credential report; IAM Users and root only',
              'complete': False, 'findings': []}
    try:
        import boto3
        from botocore.config import Config
        session = boto3.Session(profile_name=args.profile)
        # Require SSO configuration; never silently fall back to static keys.
        profile = session._session.full_config.get('profiles', {}).get(args.profile, {})
        if not (profile.get('sso_session') or profile.get('sso_start_url')):
            raise RuntimeError('Use a configured IAM Identity Center SSO profile')
        credentials = session.get_credentials()
        if credentials is None or credentials.method != 'sso':
            raise RuntimeError('Resolved credentials are not SSO credentials')
        config = Config(retries={'mode': 'standard', 'max_attempts': 3}, connect_timeout=10, read_timeout=30)
        identity = session.client('sts', config=config).get_caller_identity()
        report['identity'] = {key: identity[key] for key in ('Account', 'Arn', 'UserId')}
        if identity['Account'] != args.expected_account:
            raise RuntimeError('Account mismatch: audit stopped before IAM collection')
        if ':root' in identity['Arn']:
            raise RuntimeError('Root identity is forbidden for this auditor')
        iam = session.client('iam', config=config)
        for _ in range(15):
            if iam.generate_credential_report()['State'] == 'COMPLETE':
                break
            time.sleep(2)
        else:
            raise RuntimeError('Credential report generation timed out')
        result = iam.get_credential_report()
        report['credential_report_generated_at'] = result['GeneratedTime'].isoformat()
        rows = list(csv.DictReader(io.StringIO(result['Content'].decode('utf-8'))))
        if not rows or not any(row.get('user') == '<root_account>' for row in rows):
            raise RuntimeError('Credential report missing root row')
        report['iam_user_count'] = sum(row['user'] != '<root_account>' for row in rows)
        report['thresholds'] = {'inactivity_days': args.inactivity_days, 'key_age_days': args.key_age_days, 'grace_days': args.grace_days}
        report['findings'] = evaluate(rows, datetime.now(timezone.utc), args.inactivity_days, args.key_age_days, args.grace_days)
        report['complete'] = not any(f['status'] == 'ERROR' for f in report['findings'])
    except Exception as exc:
        # Keep actionable failure information; never print credential values.
        error = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
        report['findings'].append(dict(control='COLLECTION', resource='account', status='ERROR',
                                       severity=None, evidence={'error_type': error},
                                       recommendation=str(exc) if isinstance(exc, (RuntimeError, ImportError)) else 'Check SSO login, connectivity and audit permissions.'))
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('AWS IAM SECURITY AUDIT')
    for f in report['findings']:
        print(f"[{f['status']}] {f['control']} {f['resource']}: {json.dumps(f['evidence'])}")
    print(f'Report: {path.resolve()} | complete={report["complete"]}')
    return 2 if not report['complete'] else 1 if any(f['status'] == 'FAIL' for f in report['findings']) else 0


if __name__ == '__main__':
    sys.exit(main())
