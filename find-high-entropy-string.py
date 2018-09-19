import os
import sys

from high_entropy_string import PythonStringData


USAGE = '''\
python find-high-entropy-string.py document.json
'''

MIN_CONFIDENCE = 1
MIN_SEVERITY = 1

PATTERNS_TO_IGNORE = [r'arn:aws:',
                      '\d+\.\d+\.\d+\.\d+',
                      'vpc-',
                      'subnet-',
                      'sg-',
                      'awseb-']


def is_high_entropy_string(string_a):

    data = PythonStringData(
        string=string_a,
        node_type='assignment',
        target='json',
        patterns_to_ignore=PATTERNS_TO_IGNORE,
        entropy_patterns_to_discount=[r'/BEGIN.*PUBLIC KEY/']
    )

    if data.confidence >= MIN_CONFIDENCE:
        return True

    if data.severity >= MIN_SEVERITY:
        return True

    return False


def find_high_entropy_strings(filename):
    inside_string = False
    escape_next = False
    data = ''

    with open(filename, 'rb') as f:
        while 1:
            char = f.read(1)

            if char == '"':

                if not inside_string:
                    inside_string = True
                    continue

                if inside_string and escape_next:
                    # Found the " after the \
                    continue

                if inside_string:
                    # We were inside a string, but found the closing "
                    inside_string = False
                    if data and is_high_entropy_string(data):
                        print(data)
                    
                    # Next string
                    data = ''
                    continue

            elif char == '\\':

                if inside_string:
                    escape_next = True
                    continue

            else:

                if inside_string:
                    data += char
                    continue

            # Only escape one character
            if escape_next:
                escape_next = False


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(USAGE)
        sys.exit(1)

    filename = sys.argv[1]
    filename = os.path.expanduser(filename)

    if not os.path.exists(filename):
        print('%s does not exist' % filename)
        sys.exit(2)

    find_high_entropy_strings(filename)
