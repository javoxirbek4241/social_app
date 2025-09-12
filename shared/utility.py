import re
import random

from users.models import CodeVerified

phone_regex = re.compile(r'^(?:\+998|998)[0-9]{9}$')
email_regex = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
username_regex = re.compile(r'^[a-zA-Z0-9._]+$')
def valid_username(user_input):
    return re.fullmatch(username_regex, user_input) is not None


def check_email_or_phone_number(user_input):
    if re.fullmatch(phone_regex, user_input):
        data = 'phone'
    elif re.fullmatch(email_regex, user_input):
        data = 'email'
    else:
        data = {
            'success': False,
            'msg':'notogri malumot kiritdingiz'
        }

def create_verify_code(self, verify_type):
    code = "".join([str(random.randint(0, 10000) % 10) for _ in range(4)])
    CodeVerified.objects.create(
        user_id=self.id,
        verify_type=verify_type,
        code=code
    )
    return code