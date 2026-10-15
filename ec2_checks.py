"""Read-only instance-profile inventory, scoped to explicit EC2 regions."""


def collect_ec2(session, iam, regions, config=None):
    inventory, findings, coverage, profiles = [], [], [], {}

    def finding(resource, status, evidence, recommendation):
        findings.append(dict(control='IAM-009', resource=resource, status=status,
                             severity='LOW' if status == 'WARN' else None,
                             evidence=evidence, recommendation=recommendation))

    def error(resource, region, operation, exc):
        code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
        finding(resource, 'ERROR', {'region': region, 'operation': operation, 'error_type': code},
                'Collection incomplete; check read permissions, region and resource availability.')

    for region in dict.fromkeys(regions):
        scope = {'region': region, 'complete': False, 'instance_count': 0}
        coverage.append(scope)
        start_errors = sum(f['status'] == 'ERROR' for f in findings)
        try:
            ec2 = session.client('ec2', region_name=region, config=config)
            pages = ec2.get_paginator('describe_instances').paginate()
            for page in pages:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        if instance.get('State', {}).get('Name') == 'terminated':
                            continue
                        scope['instance_count'] += 1
                        record = {'instance_id': instance['InstanceId'], 'region': region,
                                  'name': next((t['Value'] for t in instance.get('Tags', []) if t['Key'] == 'Name'), None),
                                  'state': instance.get('State', {}).get('Name'),
                                  'instance_profile_arn': instance.get('IamInstanceProfile', {}).get('Arn'),
                                  'roles': [], 'complete': False}
                        inventory.append(record)
                        profile_arn = record['instance_profile_arn']
                        if not profile_arn:
                            record['complete'] = True
                            finding(record['instance_id'], 'WARN', dict(record),
                                    'Review whether this workload requires AWS access; absence of a role alone is not a vulnerability.')
                            continue
                        try:
                            if profile_arn not in profiles:
                                profile_name = profile_arn.rsplit('/', 1)[-1]
                                profile = iam.get_instance_profile(InstanceProfileName=profile_name)['InstanceProfile']
                                if profile['Arn'] != profile_arn:
                                    raise ValueError('Instance profile ARN mismatch')
                                profiles[profile_arn] = [{'name': role['RoleName'], 'arn': role['Arn']} for role in profile['Roles']]
                            record['roles'] = profiles[profile_arn]
                            record['complete'] = True
                            finding(record['instance_id'], 'PASS' if record['roles'] else 'WARN', dict(record),
                                    'Role attachment observed; permissions and application credential usage are not evaluated.'
                                    if record['roles'] else 'Instance profile exists but contains no role; review workload requirements.')
                        except Exception as exc:
                            error(record['instance_id'], region, 'GetInstanceProfile', exc)
            scope['complete'] = start_errors == sum(f['status'] == 'ERROR' for f in findings)
            if not scope['instance_count']:
                finding(region, 'INFO', {'region': region, 'instance_count': 0},
                        'No non-terminated instances observed in this region; other regions are not implied covered.')
        except Exception as exc:
            error(region, region, 'DescribeInstances', exc)
    return inventory, findings, coverage
