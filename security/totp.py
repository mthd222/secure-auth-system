import pyotp
import time


def generate_totp_secret():
    return pyotp.random_base32()


def get_totp_uri(email, secret, issuer="Secure Auth System"):
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=issuer
    )


def generate_totp(secret, offset=0):
    return pyotp.TOTP(secret).at(int(time.time()) + (offset * 30))


def verify_totp(secret, code, window=2):
    if not code or not code.isdigit():
        return False

    return pyotp.TOTP(secret).verify(code, valid_window=window)
