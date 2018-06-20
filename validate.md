 ### IP正则：
  - 一般形式
  <pre>IP_PATTERN = r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
              \.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
              \.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
              \.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"</pre>
  - IP地址
  <pre>SINGLE_IP_PATTERN = "^%s$" % IP_PATTERN  # match example 192.168.1.1</pre>
  - IP子网 
  <pre> IP_MASK_PATTERN = "^%s/%s$" % (IP_PATTERN, IP_PATTERN) # match example 192.168.1.1/255.255.0.0
  IP_MASKLEN_PATTERN = "^%s/[\d]{1,2}$" % IP_PATTERN # match example 192.168.1.1/24</pre>
  - IP网段 
  <pre>IP_SEGMENT_PATTERN = "^%s-%s$" % (IP_PATTERN, IP_PATTERN) # match example 192.168.1.1-192.168.1.255</pre>
