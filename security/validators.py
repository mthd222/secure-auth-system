import re

def validate_password(password):

    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain lowercase letter"

    if not re.search(r"[0-9]", password):
        return False, "Password must contain a number"

    return True, "Valid Password"