import re

phone_regex = re.compile(r'^(?:\+998|998)[0-9]{9}$')
email_regex = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

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