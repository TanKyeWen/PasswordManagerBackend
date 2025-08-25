from collections import defaultdict
from datetime import datetime
import time

import zxcvbn

test1 = defaultdict(list)

t = '1'

result = zxcvbn.zxcvbn("123")

weak = result['score'] <= 2

print(t)