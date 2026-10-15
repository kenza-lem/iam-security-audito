import unittest
from datetime import datetime, timezone
from auditor import evaluate, validate_identity

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


class Checks(unittest.TestCase):
    def test_expected_role_accepted(self):
        validate_identity({'Account': '123456789012', 'Arn': 'arn:aws:sts::123456789012:assumed-role/IAMSecurityAuditRole/test'}, '123456789012', 'IAMSecurityAuditRole')

    def test_user_and_other_role_rejected(self):
        for resource in ('user/lab-admin', 'root', 'assumed-role/Admin/test', 'assumed-role/IAMSecurityAuditRoleExtra/test'):
            with self.assertRaises(RuntimeError):
                validate_identity({'Account': '123456789012', 'Arn': 'arn:aws:sts::123456789012:' + resource}, '123456789012', 'IAMSecurityAuditRole')

    def test_wrong_account_rejected(self):
        with self.assertRaises(RuntimeError):
            validate_identity({'Account': '999999999999', 'Arn': 'arn:aws:sts::999999999999:assumed-role/IAMSecurityAuditRole/test'}, '123456789012', 'IAMSecurityAuditRole')

    def test_root_active_key_critical(self):
        result = evaluate([{'user': '<root_account>', 'mfa_active': 'true', 'access_key_1_active': 'true', 'access_key_2_active': 'false'}], NOW)
        self.assertEqual(result[1]['severity'], 'CRITICAL')
        self.assertEqual(result[1]['status'], 'FAIL')

    def test_missing_root_key_flags_not_pass(self):
        result = evaluate([{'user': '<root_account>', 'mfa_active': 'true'}], NOW)
        self.assertEqual(result[1]['status'], 'ERROR')

    def test_new_user_not_dormant(self):
        result = evaluate([{'user': 'new', 'user_creation_time': '2026-10-09T00:00:00Z'}], NOW)
        self.assertEqual(result[-1]['status'], 'INFO')

    def test_old_unused_key_and_console_without_mfa(self):
        row = {'user': 'developer', 'password_enabled': 'true', 'mfa_active': 'false',
               'user_creation_time': '2025-01-01T00:00:00Z', 'access_key_1_active': 'true',
               'access_key_1_last_rotated': '2025-01-01T00:00:00Z'}
        result = evaluate([row], NOW)
        self.assertEqual([f['status'] for f in result], ['FAIL', 'WARN', 'WARN'])


if __name__ == '__main__':
    unittest.main()
