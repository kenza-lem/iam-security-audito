import unittest
from unittest.mock import Mock
from datetime import datetime, timezone, timedelta
from credential_checks import collect_keys

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


def client(keys):
    iam = Mock()
    def paginator(operation):
        pager = Mock()
        pager.paginate.return_value = [{'Users': [{'UserName': 'test-user'}]}] if operation == 'list_users' else [{'AccessKeyMetadata': keys}]
        return pager
    iam.get_paginator.side_effect = paginator
    iam.get_access_key_last_used.return_value = {'AccessKeyLastUsed': {'LastUsedDate': NOW - timedelta(days=1), 'ServiceName': 's3', 'Region': 'eu-north-1'}}
    return iam


class Keys(unittest.TestCase):
    def test_empty_keys_pass(self):
        inventory, findings = collect_keys(client([]), NOW)
        self.assertTrue(inventory[0]['complete'])
        self.assertEqual(findings[0]['status'], 'PASS')

    def test_old_active_and_inactive_distinguished_ids_masked(self):
        keys = [{'AccessKeyId': 'FAKEEXAMPLEKEY1234', 'Status': s, 'CreateDate': NOW - timedelta(days=100)} for s in ['Active', 'Inactive']]
        inventory, findings = collect_keys(client(keys), NOW)
        self.assertEqual([f['status'] for f in findings], ['WARN', 'INFO'])
        self.assertNotIn('FAKEEXAMPLEKEY1234', str(inventory) + str(findings))

    def test_missing_usage_is_not_never_used(self):
        iam = client([{'AccessKeyId': 'FAKEEXAMPLEKEY1234', 'Status': 'Active', 'CreateDate': NOW}])
        iam.get_access_key_last_used.return_value = {'AccessKeyLastUsed': {'ServiceName': 'N/A', 'Region': 'N/A'}}
        _, findings = collect_keys(iam, NOW)
        self.assertEqual(findings[0]['status'], 'WARN')
        self.assertIsNone(findings[0]['evidence']['last_used_at'])

    def test_last_use_denied_no_pass(self):
        iam = client([{'AccessKeyId': 'FAKEEXAMPLEKEY1234', 'Status': 'Active', 'CreateDate': NOW}])
        iam.get_access_key_last_used.side_effect = RuntimeError('denied')
        inventory, findings = collect_keys(iam, NOW)
        self.assertFalse(inventory[0]['complete'])
        self.assertEqual(findings[0]['status'], 'ERROR')

    def test_listing_denied_not_empty(self):
        iam = client([])
        iam.get_paginator.side_effect = RuntimeError('denied')
        inventory, findings = collect_keys(iam, NOW)
        self.assertEqual(inventory, [])
        self.assertEqual(findings[0]['status'], 'ERROR')

    def test_real_key_pagination(self):
        import boto3
        from botocore.stub import Stubber
        from privilege_checks import items
        iam = boto3.client('iam', region_name='eu-north-1', aws_access_key_id='test', aws_secret_access_key='test')
        key = {'UserName': 'test-user', 'AccessKeyId': 'FAKEEXAMPLEKEY1234', 'Status': 'Inactive', 'CreateDate': NOW}
        with Stubber(iam) as stub:
            stub.add_response('list_access_keys', {'AccessKeyMetadata': [], 'IsTruncated': True, 'Marker': 'next'}, {'UserName': 'test-user'})
            stub.add_response('list_access_keys', {'AccessKeyMetadata': [key], 'IsTruncated': False}, {'UserName': 'test-user', 'Marker': 'next'})
            self.assertEqual(items(iam, 'list_access_keys', 'AccessKeyMetadata', UserName='test-user'), [key])
            stub.assert_no_pending_responses()
