import unittest
from unittest.mock import Mock
from remediate_mfa import enroll


class EnrollmentTests(unittest.TestCase):
    def client(self):
        iam = Mock()
        iam.get_paginator.return_value.paginate.side_effect = [
            [{'MFADevices': []}], [{'MFADevices': [{'SerialNumber': 'test-device'}]}]]
        iam.create_virtual_mfa_device.return_value = {'VirtualMFADevice': {'SerialNumber': 'test-device', 'QRCodePNG': b'fake'}}
        return iam

    def test_existing_mfa_stops_before_creation(self):
        iam = self.client()
        iam.get_paginator.return_value.paginate.side_effect = [[{'MFADevices': [{'SerialNumber': 'existing'}]}]]
        with self.assertRaises(RuntimeError):
            enroll(iam, 'auditor01', Mock(), Mock())
        iam.create_virtual_mfa_device.assert_not_called()

    def test_enables_and_verifies(self):
        iam = self.client()
        closed = Mock()
        self.assertEqual(enroll(iam, 'auditor01', Mock(return_value=closed), Mock(side_effect=['123456', '234567'])), 'test-device')
        iam.enable_mfa_device.assert_called_once_with(UserName='auditor01', SerialNumber='test-device', AuthenticationCode1='123456', AuthenticationCode2='234567')
        closed.assert_called_once()

    def test_bad_codes_never_enable_or_delete(self):
        iam = self.client()
        with self.assertRaises(RuntimeError):
            enroll(iam, 'auditor01', Mock(return_value=Mock()), Mock(side_effect=['123456', '123456']))
        iam.enable_mfa_device.assert_not_called()
        iam.delete_virtual_mfa_device.assert_not_called()

    def test_inconclusive_verification_does_not_delete(self):
        iam = self.client()
        iam.get_paginator.return_value.paginate.side_effect = [[{'MFADevices': []}], [{'MFADevices': []}]]
        with self.assertRaises(RuntimeError):
            enroll(iam, 'auditor01', Mock(return_value=Mock()), Mock(side_effect=['123456', '234567']))
        iam.delete_virtual_mfa_device.assert_not_called()
