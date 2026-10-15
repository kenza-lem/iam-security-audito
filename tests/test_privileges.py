import json
import unittest
from unittest.mock import Mock
from urllib.parse import quote
from privilege_checks import collect_privileges, policy_signals, items

ADMIN = 'arn:aws:iam::aws:policy/AdministratorAccess'


def fake_iam(group_policies=None, user_inline=None):
    iam = Mock()
    def paginator(operation):
        data = {
            'list_users': {'Users': [{'UserName': 'developer02', 'Arn': 'arn:aws:iam::123456789012:user/developer02'}]},
            'list_groups_for_user': {'Groups': [{'GroupName': 'Developers'}]},
            'list_attached_user_policies': {'AttachedPolicies': []},
            'list_user_policies': {'PolicyNames': ['Custom'] if user_inline else []},
            'list_attached_group_policies': {'AttachedPolicies': group_policies or []},
            'list_group_policies': {'PolicyNames': []},
        }
        result = Mock()
        result.paginate.return_value = [data[operation]]
        return result
    iam.get_paginator.side_effect = paginator
    iam.get_policy.return_value = {'Policy': {'DefaultVersionId': 'v1'}}
    iam.get_policy_version.return_value = {'PolicyVersion': {'Document': {'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}}}}
    iam.get_user_policy.return_value = {'PolicyDocument': user_inline}
    return iam


class Privileges(unittest.TestCase):
    def test_group_admin_detected_with_origin(self):
        inventory, findings = collect_privileges(fake_iam([{'PolicyName': 'AdministratorAccess', 'PolicyArn': ADMIN}]))
        result = next(f for f in findings if f['control'] == 'IAM-006')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['evidence']['policy']['owner'], 'Developers')
        self.assertTrue(inventory[0]['complete'])

    def test_inline_wildcard_review_not_admin_fail(self):
        document = quote(json.dumps({'Statement': {'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*', 'Condition': {'StringEquals': {'aws:RequestedRegion': 'eu-north-1'}}}}))
        _, findings = collect_privileges(fake_iam(user_inline=document))
        signal = next(f for f in findings if f['control'] == 'IAM-010')
        self.assertEqual(signal['status'], 'WARN')
        self.assertIsNotNone(signal['evidence']['statement']['condition'])
        self.assertFalse(any(f['status'] == 'FAIL' for f in findings))

    def test_deny_not_treated_as_allow(self):
        self.assertEqual(policy_signals({'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]}), [])

    def test_access_denied_no_false_pass(self):
        iam = fake_iam()
        original = iam.get_paginator.side_effect
        def deny(operation):
            if operation == 'list_attached_group_policies':
                raise RuntimeError('AccessDenied')
            return original(operation)
        iam.get_paginator.side_effect = deny
        inventory, findings = collect_privileges(iam)
        self.assertFalse(inventory[0]['complete'])
        self.assertTrue(any(f['status'] == 'ERROR' for f in findings))
        self.assertEqual(next(f for f in findings if f['control'] == 'IAM-006')['status'], 'SKIP')

    def test_inventory_failure_reported(self):
        iam = Mock()
        iam.get_paginator.side_effect = RuntimeError('Denied')
        inventory, findings = collect_privileges(iam)
        self.assertEqual(inventory, [])
        self.assertEqual(findings[0]['status'], 'ERROR')

    def test_inverse_matching_review(self):
        signals = policy_signals({'Statement': {'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': '*'}})
        self.assertEqual(signals[0]['not_action'], 'iam:*')

    def test_real_sdk_pagination(self):
        import boto3
        from botocore.stub import Stubber
        from datetime import datetime, timezone
        iam = boto3.client('iam', region_name='eu-north-1', aws_access_key_id='test', aws_secret_access_key='test')
        user = {'Path': '/', 'UserName': 'developer02', 'UserId': 'AIDA12345678901234567',
                'Arn': 'arn:aws:iam::123456789012:user/developer02', 'CreateDate': datetime.now(timezone.utc)}
        with Stubber(iam) as stub:
            stub.add_response('list_users', {'Users': [], 'IsTruncated': True, 'Marker': 'next'}, {})
            stub.add_response('list_users', {'Users': [user], 'IsTruncated': False}, {'Marker': 'next'})
            self.assertEqual(items(iam, 'list_users', 'Users'), [user])
            stub.assert_no_pending_responses()
