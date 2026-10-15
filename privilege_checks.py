"""Collect attached/inline user and group policies; flag grants for human review.

This is a policy inventory, not an effective-permission simulator.
"""
import json
from urllib.parse import unquote


def items(iam, operation, key, **kwargs):
    return [item for page in iam.get_paginator(operation).paginate(**kwargs) for item in page[key]]


def normalize(document):
    if isinstance(document, str):
        document = json.loads(unquote(document))
    if not isinstance(document, dict):
        raise ValueError('Invalid policy document')
    statements = document.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(isinstance(s, dict) for s in statements):
        raise ValueError('Invalid statements')
    return statements


def as_list(value):
    return value if isinstance(value, list) else [value] if value is not None else []


def policy_signals(document):
    signals = []
    for index, statement in enumerate(normalize(document)):
        if statement.get('Effect') != 'Allow':
            continue
        actions = as_list(statement.get('Action'))
        resources = as_list(statement.get('Resource'))
        broad = [a for a in actions if isinstance(a, str) and '*' in a]
        admin_like = '*' in actions and '*' in resources
        if broad or '*' in resources or 'NotAction' in statement or 'NotResource' in statement:
            signals.append({'statement_index': index, 'sid': statement.get('Sid'),
                            'actions': actions, 'resources': resources,
                            'not_action': statement.get('NotAction'), 'not_resource': statement.get('NotResource'),
                            'condition': statement.get('Condition'), 'admin_like': admin_like,
                            'reason': 'Allow with wildcard or inverse matching requires contextual review'})
    return signals


def is_managed_admin(arn):
    return isinstance(arn, str) and arn.split(':', 5)[-1] == 'policy/AdministratorAccess' and arn.split(':')[4] == 'aws'


def collect_privileges(iam, developers_group='Developers'):
    findings, inventory, cache = [], [], {}
    def finding(control, user, status, severity, evidence, recommendation):
        findings.append(dict(control=control, resource=user, status=status, severity=severity,
                             evidence=evidence, recommendation=recommendation))
    def attempt(user, operation, call):
        try:
            return call()
        except Exception as exc:
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
            finding('PERMISSIONS-COLLECTION', user, 'ERROR', None,
                    {'operation': operation, 'error_type': code},
                    'Verify read permissions and resource existence; inventory is incomplete.')
            return None
    def managed_document(arn):
        if arn not in cache:
            policy = iam.get_policy(PolicyArn=arn)['Policy']
            version = policy['DefaultVersionId']
            document = iam.get_policy_version(PolicyArn=arn, VersionId=version)['PolicyVersion']['Document']
            normalize(document)
            cache[arn] = (document, version)
        return cache[arn]
    users = attempt('account', 'ListUsers', lambda: items(iam, 'list_users', 'Users'))
    if users is None:
        return inventory, findings
    for user in users:
        name = user['UserName']
        error_start = sum(f['status'] == 'ERROR' for f in findings)
        groups = attempt(name, 'ListGroupsForUser', lambda: items(iam, 'list_groups_for_user', 'Groups', UserName=name))
        group_names = [g['GroupName'] for g in groups] if groups is not None else None
        developer = name.lower().startswith('developer') or (group_names is not None and developers_group in group_names)
        entry = {'user': name, 'arn': user['Arn'], 'groups': group_names, 'policies': [], 'complete': False}
        inventory.append(entry)
        if group_names is not None:
            finding('IAM-008', name, 'WARN' if not group_names else 'INFO', 'LOW' if not group_names else None,
                    {'groups': group_names}, 'Review group membership against the approved RBAC model.')
        sources = [('user', name)] + [('group', g) for g in group_names or []]
        for kind, owner in sources:
            parameter = {f'{kind.title()}Name': owner}
            attached = attempt(name, f'ListAttached{kind.title()}Policies',
                               lambda: items(iam, f'list_attached_{kind}_policies', 'AttachedPolicies', **parameter))
            inline = attempt(name, f'List{kind.title()}Policies',
                             lambda: items(iam, f'list_{kind}_policies', 'PolicyNames', **parameter))
            for policy in attached or []:
                record = {'source': kind, 'owner': owner, 'type': 'managed',
                          'name': policy['PolicyName'], 'arn': policy['PolicyArn']}
                entry['policies'].append(record)
                fetched = attempt(name, 'GetPolicy/GetPolicyVersion', lambda: managed_document(record['arn']))
                if fetched:
                    record['document'], record['version'] = fetched
            for policy_name in inline or []:
                record = {'source': kind, 'owner': owner, 'type': 'inline', 'name': policy_name}
                entry['policies'].append(record)
                document = attempt(name, f'Get{kind.title()}Policy',
                                   lambda: getattr(iam, f'get_{kind}_policy')(**parameter, PolicyName=policy_name)['PolicyDocument'])
                if document is not None:
                    valid = attempt(name, 'ParsePolicyDocument', lambda: normalize(document))
                    if valid is not None:
                        record['document'] = document
        direct = [{'name': p['name'], 'type': p['type']} for p in entry['policies'] if p['source'] == 'user']
        finding('IAM-007', name, 'INFO', None, {'direct_policies': direct},
                'Review direct grants against the group-based RBAC model; direct attachment is not inherently a vulnerability.')
        admin_observed = False
        for record in entry['policies']:
            origin = {k: v for k, v in record.items() if k != 'document'}
            managed_admin = is_managed_admin(record.get('arn'))
            signals = policy_signals(record['document']) if 'document' in record else []
            admin_like = any(s['admin_like'] for s in signals)
            if managed_admin or admin_like:
                admin_observed = True
                finding('IAM-006', name, 'FAIL' if developer and managed_admin else 'WARN',
                        'HIGH' if developer else 'MEDIUM',
                        {'policy': origin, 'managed_administrator_access': managed_admin,
                         'admin_like_allow': admin_like, 'developer_scope': developer},
                        'Review against job needs; boundaries, SCPs, conditions and explicit denies can restrict effective access.')
            for signal in signals:
                finding('IAM-010', name, 'WARN', 'LOW', {'policy': origin, 'statement': signal},
                        'REVIEW: wildcard or inverse matching alone does not establish excessive effective permissions.')
        entry['complete'] = error_start == sum(f['status'] == 'ERROR' for f in findings)
        if developer and not admin_observed:
            finding('IAM-006', name, 'PASS' if entry['complete'] else 'SKIP', None,
                    {'administrator_pattern_observed': False, 'inventory_complete': entry['complete']},
                    'No administrator pattern observed in collected user/group policies; effective access is not proven limited.')
    return inventory, findings
