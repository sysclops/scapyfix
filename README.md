# scapyfix
Evil tools are evil.

>>> request_packet = IP(dst="www.google.com")/ICMP(type="echorequest")/"Very reliable!"
>>> response_packet = sr1(request_packet)
