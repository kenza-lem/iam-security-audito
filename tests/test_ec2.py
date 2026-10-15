import unittest
from unittest.mock import Mock
from ec2_checks import collect_ec2

PROFILE = 'arn:aws:iam::123456789012:instance-profile/path/InstanceProfile'
ROLE = {'RoleName': 'ActualWorkloadRole', 'Arn': 'arn:aws:iam::123456789012:role/ActualWorkloadRole'}


def instance(identifier='i-test', profile=PROFILE, state='running'):
    value = {'InstanceId': identifier, 'State': {'Name': state}, 'Tags': [{'Key': 'Name', 'Value': 'test-workload'}]}
    if profile:
        value['IamInstanceProfile'] = {'Arn': profile}
    return value


def clients(instances):
    session, iam = Mock(), Mock()
    session.client.return_value.get_paginator.return_value.paginate.return_value = [{'Reservations': [{'Instances': instances}]}]
    iam.get_instance_profile.return_value = {'InstanceProfile': {'Arn': PROFILE, 'Roles': [ROLE]}}
    return session, iam


class EC2Tests(unittest.TestCase):
    def test_resolves_actual_role_not_profile_name_and_caches(self):
        session, iam = clients([instance(), instance('i-second')])
        inventory, findings, coverage = collect_ec2(session, iam, ['eu-north-1', 'eu-north-1'])
        self.assertEqual(inventory[0]['roles'][0]['name'], 'ActualWorkloadRole')
        iam.get_instance_profile.assert_called_once_with(InstanceProfileName='InstanceProfile')
        self.assertEqual([f['status'] for f in findings], ['PASS', 'PASS'])
        self.assertEqual(len(coverage), 1)

    def test_no_role_and_empty_profile_warn(self):
        session, iam = clients([instance(profile=None), instance('i-empty')])
        iam.get_instance_profile.return_value['InstanceProfile']['Roles'] = []
        _, findings, coverage = collect_ec2(session, iam, ['eu-north-1'])
        self.assertEqual([f['status'] for f in findings], ['WARN', 'WARN'])
        self.assertTrue(coverage[0]['complete'])

    def test_profile_read_denied_never_pass(self):
        session, iam = clients([instance()])
        iam.get_instance_profile.side_effect = RuntimeError('denied')
        inventory, findings, coverage = collect_ec2(session, iam, ['eu-north-1'])
        self.assertEqual(findings[0]['status'], 'ERROR')
        self.assertFalse(inventory[0]['complete'])
        self.assertFalse(coverage[0]['complete'])

    def test_region_failure_continues_to_next_region(self):
        session, iam = clients([])
        good_client = session.client.return_value
        session.client.side_effect = [RuntimeError('denied'), good_client]
        _, findings, coverage = collect_ec2(session, iam, ['eu-west-1', 'eu-north-1'])
        self.assertFalse(coverage[0]['complete'])
        self.assertTrue(coverage[1]['complete'])
        self.assertEqual([f['status'] for f in findings], ['ERROR', 'INFO'])

    def test_terminated_excluded_stopped_included(self):
        session, iam = clients([instance('i-gone', state='terminated'), instance('i-stopped', state='stopped')])
        inventory, _, coverage = collect_ec2(session, iam, ['eu-north-1'])
        self.assertEqual([v['instance_id'] for v in inventory], ['i-stopped'])
        self.assertEqual(coverage[0]['instance_count'], 1)

    def test_real_sdk_pagination(self):
        import boto3
        from botocore.stub import Stubber
        ec2 = boto3.client('ec2', region_name='eu-north-1', aws_access_key_id='test', aws_secret_access_key='test')
        session, iam = Mock(), Mock()
        session.client.return_value = ec2
        with Stubber(ec2) as stub:
            stub.add_response('describe_instances', {'Reservations': [], 'NextToken': 'next'}, {})
            stub.add_response('describe_instances', {'Reservations': [{'Instances': [instance(profile=None)]}]}, {'NextToken': 'next'})
            inventory, findings, _ = collect_ec2(session, iam, ['eu-north-1'])
            self.assertEqual(len(inventory), 1)
            self.assertEqual(findings[0]['status'], 'WARN')
            stub.assert_no_pending_responses()
