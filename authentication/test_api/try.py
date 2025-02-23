import random
import string

generated_strings = set()
def generate_random_string():
    letters = string.ascii_uppercase  # Uppercase letters
    digits = string.digits  # Numbers 0-9

    first_part = ''.join(random.choices(letters, k=4))
    middle_part = ''.join(random.choices(digits, k=4))
    new_string = first_part + middle_part
    if new_string not in generated_strings:
        generated_strings.add(new_string)
        print(new_string)
        return new_string
    else:
        return generate_random_string()

generate_random_string()