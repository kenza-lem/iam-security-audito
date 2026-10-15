"""Interactive MFA enrollment. QR and codes stay in memory; no secret files."""
import argparse
import base64
import getpass
import re
import sys

from auditor import validate_identity


def enroll(iam, user, show_qr, read_code):
    iam.get_user(UserName=user)
    existing = [device for page in iam.get_paginator('list_mfa_devices').paginate(UserName=user)
                for device in page['MFADevices']]
    if existing:
        raise RuntimeError('User already has MFA; no device created.')
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=f'{user}-assisted-mfa')['VirtualMFADevice']
    serial = device['SerialNumber']
    print(f'Created virtual device: {serial}')
    close = None
    try:
        close = show_qr(device['QRCodePNG'])
        del device
        code1 = read_code('Code 1 (hidden): ')
        code2 = read_code('Wait for the next code, then code 2 (hidden): ')
        if not all(re.fullmatch(r'[0-9]{6}', code) for code in (code1, code2)) or code1 == code2:
            raise RuntimeError('Enter two distinct consecutive six-digit codes.')
        iam.enable_mfa_device(UserName=user, SerialNumber=serial,
                              AuthenticationCode1=code1, AuthenticationCode2=code2)
        del code1, code2
        devices = [item for page in iam.get_paginator('list_mfa_devices').paginate(UserName=user)
                   for item in page['MFADevices']]
        if not any(item['SerialNumber'] == serial for item in devices):
            raise RuntimeError('Enable request sent, but verification is inconclusive; inspect IAM console.')
        print(f'MFA attached to {user}. Test a fresh console login next.')
        return serial
    except BaseException:
        print(f'Enrollment interrupted or unverified. Inspect {serial} in IAM before retrying.')
        print('Do not delete a device that is attached. If unassigned, clean it up manually before retrying.')
        raise
    finally:
        if close:
            close()


def qr_window(png):
    import tkinter as tk
    window = tk.Tk()
    window.title('MFA enrollment - scan locally, do not capture or share')
    picture = tk.PhotoImage(data=base64.b64encode(png).decode('ascii'))
    label = tk.Label(window, image=picture)
    label.image = picture
    label.pack()
    tk.Label(window, text='Scan with Authenticator, then click Continue.').pack()
    done = tk.BooleanVar(window, False)
    tk.Button(window, text='Continue', command=lambda: done.set(True)).pack()
    cancelled = []
    window.protocol('WM_DELETE_WINDOW', lambda: (cancelled.append(True), done.set(True)))
    window.wait_variable(done)
    window.withdraw()
    window.destroy()
    if cancelled:
        raise RuntimeError('QR window closed without confirmation.')
    return lambda: None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='iam-mfa')
    parser.add_argument('--expected-account', required=True)
    parser.add_argument('--user', choices=['auditor01'], required=True)
    args = parser.parse_args()
    try:
        # Check local GUI support before any AWS mutation.
        import tkinter
        import boto3
        from botocore.config import Config
        session = boto3.Session(profile_name=args.profile)
        credentials = session.get_credentials()
        if credentials is None or credentials.method != 'assume-role':
            raise RuntimeError('Use the dedicated assumed-role profile iam-mfa.')
        config = Config(connect_timeout=10, read_timeout=30, retries={'mode': 'standard', 'max_attempts': 2})
        identity = session.client('sts', config=config).get_caller_identity()
        validate_identity(identity, args.expected_account, 'IAMMfaEnrollmentRole')
        print(f"Identity: {identity['Arn']}")
        print(f'Action: create and attach a virtual MFA device for {args.user}.')
        if input(f'Type {args.user} to proceed: ').strip() != args.user:
            print('Cancelled. No changes made.')
            return 0
        enroll(session.client('iam', config=config), args.user, qr_window, getpass.getpass)
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        # Never print SDK response bodies, QR seed or entered codes.
        error = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
        print(f'Error: {error}')
        if isinstance(exc, RuntimeError):
            print(str(exc))
        return 2


if __name__ == '__main__':
    sys.exit(main())
