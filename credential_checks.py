"""Inventory every IAM User key (including inactive keys), without secret access."""
from privilege_checks import items


def collect_keys(iam, now, max_age=90):
    inventory, findings = [], []
    def add(user, status, severity, evidence, recommendation):
        findings.append(dict(control='IAM-004', resource=user, status=status, severity=severity,
                             evidence=evidence, recommendation=recommendation))
    def error(user, operation, exc, key=None):
        code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
        add(user, 'ERROR', None, {'operation': operation, 'error_type': code, 'key_reference': key},
            'Key collection is incomplete; check permissions or concurrent key deletion.')
    try:
        users = items(iam, 'list_users', 'Users')
    except Exception as exc:
        error('account', 'ListUsers', exc)
        return inventory, findings
    for user in users:
        name = user['UserName']
        entry = {'user': name, 'keys': [], 'complete': False}
        inventory.append(entry)
        try:
            keys = items(iam, 'list_access_keys', 'AccessKeyMetadata', UserName=name)
        except Exception as exc:
            error(name, 'ListAccessKeys', exc)
            continue
        entry['complete'] = True
        if not keys:
            add(name, 'PASS', None, {'key_count': 0, 'source': 'ListAccessKeys'},
                'No IAM User access keys observed; service-specific credentials are outside scope.')
        for key in keys:
            reference = '…' + key['AccessKeyId'][-4:]
            created = key['CreateDate']
            age = (now - created).days
            record = {'key_reference': reference, 'status': key['Status'], 'created_at': created.isoformat(),
                      'age_days': age, 'complete': False}
            entry['keys'].append(record)
            try:
                used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])['AccessKeyLastUsed']
                last = used.get('LastUsedDate')
                record.update(last_used_at=last.isoformat() if last else None,
                              last_service=used.get('ServiceName'), last_region=used.get('Region'), complete=True)
            except Exception as exc:
                entry['complete'] = False
                error(name, 'GetAccessKeyLastUsed', exc, reference)
                continue
            if key['Status'] == 'Inactive':
                status, severity, reason = 'INFO', 'LOW', 'Inactive key retained; review whether it is still needed'
            elif key['Status'] != 'Active':
                status, severity, reason = 'WARN', 'LOW', 'Unexpected key state requires review'
            elif age >= max_age:
                status, severity, reason = 'WARN', 'MEDIUM', 'Active key exceeds configured age threshold'
            elif last is None:
                status, severity, reason = 'WARN', 'LOW', 'Active key with no observed usage data'
            else:
                status, severity, reason = 'INFO', 'LOW', 'Active long-lived key; review business justification'
            add(name, status, severity, {**record, 'reason': reason},
                'Prefer temporary credentials where possible. Confirm dependencies before any manual change; missing last-use data does not prove never used.')
    return inventory, findings
