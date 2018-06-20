 import ipaddr
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
 
 ### ipv6
 <pre>v6helper = ipaddr._BaseV6(0)</pre>
  - ip to long 可以用来根据ip排序
  <pre>
    def ip2long(ip_str):
        return v6helper._ip_int_from_string(ip_str)
  </pre>
  - long to ip
 <pre>
    def long2ip(ip_int):
        return v6helper._string_from_ip_int(ip_int)
 </pre>
 - 将IPv6网段展开为IPv6地址集合 返回set([<str>])
 <pre>
    def unfold(network):
        ip, prefix = network.split('/')
        start = ip2long(ip)
        count = 1 << (128 - int(prefix))
        results = []
        for _ in xrange(count):
            results.append(start)
            start += 1
        return results
</pre>
- 将IPv6地址压缩，去掉多个连续的0
<pre>
    def compress(ipstr):
        return ipaddr.IPAddress(ipstr).compressed
</pre>
- 将IPv6地址解压缩
<pre>
    def compress(ipstr):
        return ipaddr.IPAddress(ipstr).exploded
</pre>
### IPv4
- ip to long
<pre>
def ip2long(ip):
    p1, p2, p3, p4 = str(ip).split('.')
    return (int(p1) << 24) + (int(p2) << 16) + (int(p3) << 8) + int(p4)
</pre>
- long to ip
<pre>
def long2ip(lint):
    return "%d.%d.%d.%d" % (lint >> 24 & 0xff, lint >> 16 & 0xff, lint >> 8 & 0xff, lint & 0xff)
</pre>
- long to int
<pre>
def long2int(lint):
    return struct.unpack('!i',struct.pack("!I",lint))[0]//i int, I unsigned int,! network 
</pre>
- ip to int 先转成long 再转int
<pre>
def ip2int(ip):
    lint = ip2long(ip)
    return long2int(lint)
</pre>
- int to ip 
<pre>
def int2ip(lint):
    return long2ip(lint)
</pre>
- 判断是否为掩码
<pre>
def is_netmask(mask):
    if mask == '255.255.255.255':
        return True
    from .lang import dec2bin
    if is_ipaddr(mask):
        bin = dec2bin(ip2long(mask))
        return re.match(r'^1+0*$', bin) != None
    else:
        return False
</pre>
- 子网（IP+掩码）转为地址段
<pre>
def ipmask2seg(IP, mask):
    '''
    return tuple(begin, end), begin & end为IP地址段整数表现形式
    '''
    from .lang import dec2bin
    bits = dec2bin(ip2long(mask)).find("0")
    bitmask = 1
    for _ in range(32 - bits - 1):
        bitmask = bitmask << 1
        bitmask = bitmask | 1
    begin = ip2long(IP) & (~bitmask)
    end   = ip2long(IP) | bitmask
    return (begin + 1, end)
</pre>
- 将IPv4网段展开为IPv4地址集合
<pre>
def unfold(network):
    '''
    inet 多个IPv4网段，子网,IP
    return: set([<str>])
    '''
    def unfoldnetwork(inet):
        ip, prefix = inet.split('/')
        p1, p2, p3, p4 = ip.split('.')
        start = (int(p1) << 24) + (int(p2) << 16) + (int(p3) << 8) + int(p4)
        count = 1 << ( 32 - int(prefix))
        results = []
        for _ in xrange(count):
            results.append(long2ip(start))
            start += 1
        return results

    def unfoldsegment(seg):
        ip1, ip2 = seg.split('-')
        
        start = ip2long(ip1)
        end   = ip2long(ip2)
        results = []
        while start <= end:
            results.append(long2ip(start))
            start += 1
        return results

    if '/' in network:
        return unfoldnetwork(network)
    if '-' in network:
        return unfoldsegment(network)
</pre>
- 判断是否是网段
<pre>
def is_segment(segment, tail_unmask_len = 1):
    '''
    192.168.1.1-192.168.1.2, 和 192.168.1.1-200
    后面的地址必须大于前面的地址
    tail_unmask_len表示反掩码长度
    对于IPv4地址段，tail_unmask_len的单位是字节, 需要两个IP地址前（4-1 * tail_unmask_len）个字节相同
    对于IPv6地址段，tail_unmask_len的单位是双字节 需要两个IP地址前（16 - 2 * tail_unmask_len） 个字节相同
    '''
    if '-' not in segment:
        return False
    assert tail_unmask_len > 0
    segment = segment.strip()
    start_str, end_str = segment.split('-')
    start = end = None
    netmask = 0
    try:
        if ':' in start_str:
            netmask = ~int('ffff' * tail_unmask_len, 16)
            start = ipaddr.IPv6Address(start_str.strip())
            if re.match(r'^[a-fA-F0-9]{1,4}$', end_str):
                end_int = int(end_str, 16)
                end = ipaddr.IPv6Address("::1")
                end._ip = (start._ip & netmask) + end_int
            else:
                end = ipaddr.IPv6Address(end_str.strip())
        elif '.' in start_str:
            netmask = ~int('ff' * tail_unmask_len, 16)
            start = ipaddr.IPv4Address(start_str.strip())
            if re.match(r'^[0-9]{1,3}$', end_str):
                end_int = int(end_str)
                if 0 <= end_int < 256:
                    
                    end = ipaddr.IPv4Address("127.0.0.1")
                    end._ip = (start._ip & netmask) + end_int
                else:
                    return False
            else:
                end = ipaddr.IPv4Address(end_str.strip())
        else:
            return False
    except ValueError:
        return False
    return (start._ip & netmask) == (end._ip & netmask) and start._ip < end._ip
</pre>
- ip to segment    将IP范围字符串转换为IP段形式
<pre>
def iprange_to_segmnet(iprange):
    '''
    example:
    192.168.1.1 => 192.168.1.1-192.168.1.1
    192.168.1.1/24 => 192.168.1.0-192.168.1.255
    192.168.1.1-192.168.1.200 => 192.168.1.1-192.168.1.200
    192.168.1.1-200 => 192.168.1.1-192.168.1.200
    '''
    iprange = iprange.strip()
    if not iprange:
        return None
    if '-' in iprange:
        ip1, ip2 = split_ipsegment(iprange)
        return str(ipaddr.IPAddress(ip1)) + "-" + str(ipaddr.IPAddress(ip2))
    elif '/' in iprange:
        network = ipaddr.IPNetwork(iprange)
        start = network.network
        end = network.broadcast
        return str(start) + "-" + str(end)
    else:
        return str(ipaddr.IPAddress(iprange)) + "-" + str(ipaddr.IPAddress(iprange))
</pre>
- segment to ip将IP段尝试转换为IP地址或网络地址
<pre>
def segment_to_iprange(segment):
    '''
    如果不能转换，则返回原值
    example:
    192.168.1.1-192.168.1.1 => 192.168.1.1
    192.168.1.1-192.168.1.255 => 192.168.1.1/24
    192.168.1.2-192.168.1.20 => 192.168.1.2-20
    '''
    segment = segment.strip()
    if not segment or not '-' in segment:
        return segment
    start_str, end_str = segment.split('-')
    if start_str == end_str:
        return start_str
    
    if ':' not in end_str and '.' not in end_str:
        return segment
    
    
    prefixlen = 32
    sep = '.'
    masklen = 8
    if ':' in start_str:
        prefixlen = 128
        sep = ':'
        masklen = 16
    count = (2 << (masklen - 1)) - 1
    startv = ipaddr.IPAddress(start_str)
    endv = ipaddr.IPAddress(end_str)
    if endv._ip - startv._ip == count - 1:
        s1 = ipaddr.IPNetwork("%s/%s" % (start_str, (prefixlen - masklen)))
        if str(s1[1]) == start_str:
            return "%s/%s" % (start_str, (prefixlen - masklen))
    
    start_str = str(startv) #这里不直接使用前面的start_str， 是因为前面的start_str可能是ipv4 over ipv6的格式，如 ffff::192.168.1.1.
    end_str = str(endv)
    if start_str.split(sep)[0:-1] == end_str.split(sep)[0:-1]:
        return "%s-%s" % (start_str, end_str.split(sep)[-1])
    return segment
</pre>
- 压缩ip地址
<pre>
def compact_ipranges(ipranges):
    '''
    example:
     2001:0000:0000:0000:0000:0000:1 => 2001::1
     2001:0000:0000:0000:0000:0000:1/64 => 2001::1/64
     2001:0000:0000:0000:0000:0000:1 - 2001:0000:0000:0000:0000:0000:2 => 2001::1-2
     return list<string>
    '''
    assert isinstance(ipranges, (list, set))
    compacted_ipranges = []
    for iprange in ipranges:
        if ':' not in iprange: #IPv4地址不需要压缩
            if '-' in iprange:
                iprange = segment_to_iprange(iprange)
            compacted_ipranges.append(iprange)
            continue
        if '-' in iprange:
            ip1, ip2 = split_ipsegment(iprange)
            compacted_ipranges.append(segment_to_iprange(str(ip1) + "-" + str(ip2)))
        elif '/' in iprange:
            network = ipaddr.IPNetwork(iprange)
            compacted_ipranges.append(str(network))
        else:
            compacted_ipranges.append(str(ipaddr.IPAddress(iprange)))
    return compacted_ipranges
</pre>
- 格式化网段
<pre>
def format_network(net):
    '''
    10.66.10.1/255.255.0.0 => 10.66.0.0/255.255.0.0
    10.66.10.1/16 => 10.66.0.0/255.255.0.0
    '''
    if not net.find("/") == -1:
        this_net = ipaddr.IPNetwork(net)
        network = str(this_net.network)
        mask = this_net.netmask if this_net.version == 4 else this_net.prefixlen
        return "/".join([network, str(mask)])
    else:
        return net
</pre>
- 判断ip地址是否在inet中
<pre>
def ip_innet(ip, inet):
    '''
    example:
    ip_innet('192.168.1.1', '192.168.1.0/24') => True
    ip_innet('192.168.2.1', '192.168.1.0/24') => False
    return bool 
    '''
    ip = ipaddr.IPAddress(ip)
    if '-' in inet:
        start, end = split_ipsegment(inet)
        if start._version != ip._version:
            return False
        return start <= ip <= end
    else:
        nw = ipaddr.IPNetwork(inet)
        if nw._version != ip._version:
            return False
        return ip in ipaddr.IPNetwork(inet)
def split_ipsegment(segment):
    '''
    返回一个网络地址/地址段的首尾地址
    此函数不校验地址格式，如果参数有错误，会抛出异常异常
    example:
    split_ipsegment('192.168.1.1-192.168.1.23') => '192.168.1.1','192.168.2.23'
    split_ipsegment('192.168.1.1-200') => '192.168.1.1','192.168.2.200'
    split_ipsegment('192.168.1.1/24') => '192.168.1.0', '192.168.1.255'
    '''
    start, end = None, None
    if '-' in segment:
        start_str, end_str = segment.split('-')
        start = ipaddr.IPAddress(start_str.strip())
        if ':' in start_str:
            if re.match(r'^[a-fA-F0-9]{1,4}$', end_str):
                end = ipaddr.IPv6Address("::1")
                netmask = ~0xffff
                end._ip = (start._ip & netmask) + int(end_str, 16)
            else:
                end = ipaddr.IPAddress(end_str.strip())
        else:
            if re.match(r'^[0-9]{1,3}$', end_str):
                end = ipaddr.IPv4Address("127.0.0.1")
                netmask = ~0xff
                end._ip = (start._ip & netmask) + int(end_str)
            else:
                end = ipaddr.IPAddress(end_str.strip())
        if start > end:
            raise ValueError("Invalid network segment")
        return start, end
    elif '/' in segment:
        inetobj = ipaddr.IPNetwork(segment)
        start = inetobj.network
        start._ip += 1
        end = inetobj.broadcast
    else:
        start = ipaddr.IPAddress(segment)
        end = ipaddr.IPAddress(segment)
    return start, end
def split_ipsegment_int(segment):
    '''
    返回一个网络地址/地址段的首尾地址整数
    example:
    split_ipsegment('192.168.1.1-192.168.1.23') => ip2long('192.168.1.1'),ip2long('192.168.2.23')
    split_ipsegment('192.168.1.1/24') => ip2long('192.168.1.0'), ip2long('192.168.1.255')
    '''
    def _split_seg(mod, segment):
        start, end = split_ipsegment(segment)
        start = mod.ip2long(str(start))
        end   = mod.ip2long(str(end))
        return start, end
    
    def _split_network(mod, maxlen, network):
        start, prefixlen = network.split('/')
        prefixlen = int(prefixlen)
        suffixlen = maxlen - prefixlen
        start = mod.ip2long(start)
        start = (start >> suffixlen) << suffixlen
        end = start + ((1 << suffixlen) - 1)
        return start, end
    
    start, end = None, None
    if '-' in segment:
        if ':' in segment:
            start, end = _split_seg(ip6utils, segment)
        else:
            start, end = _split_seg(ip4utils, segment)
        if start > end:
            raise ValueError("Invalid network segment")
        return start, end
    elif '/' in segment:
        if ':' in segment:
            return _split_network(ip6utils, 128, segment)
        else:
            return _split_network(ip4utils, 32, segment)
    else:
        if ':' in segment:
            v = ip6utils.ip2long(segment)
            return v, v
        else:
            v = ip4utils.ip2long(segment)
            return v, v
</pre>
- 检查两个网段集合是否有重复IP
<pre>
def check_conflict(inets1, inets2):
    '''
    inets1和inets2都是IP网段集合
    检查两个网段集合是否有重复IP
    适用在inets2中包含大量的网段的情况
    '''
    if type(inets1) not in (list, tuple, set):
        inets1 = [inets1]
    if type(inets2) not in (list, tuple, set):
        inets2 = [inets2]
    iplist1             = unfold_to_intset(inets1)
    iplist2, ipsegments = unfold_to_int_segments(inets2)
    
    
    class IPSeg(object):
        def __init__(self, segment):
            self.begin, self.end = segment
        
        def __cmp__(self, seg):
            if isinstance(seg, (int, float, long)):
                if self.begin <= seg <= self.end:
                    return 0
                if self.end < seg:
                    return -1
                return 1
            
            if self.end < seg.begin:
                return -1
            if self.begin > seg.end:
                return 1
            return 0

        def __repr__(self):
            return "%s-%s" % (ip4utils.int2ip(self.begin), ip4utils.int2ip(self.end))
    
    def binary_search(a, x, lo=0, hi=None):
        if hi is None:
            hi = len(a)
        while lo < hi:
            mid = (lo+hi)//2
            midval = a[mid]
            cmp_result = cmp(midval, x)
            if cmp_result < 0:
                lo = mid + 1
            elif cmp_result > 0: 
                hi = mid
            else:
                return mid
        return -1
    
    ipsegments = [ IPSeg(seg) for seg in ipsegments ]
    ipsegments.sort()
    for ip in iplist1:
        if ip in iplist2:
            return True
        if binary_search(ipsegments, ip) >= 0:
            return True
    return False

def check_conflict2(inets1, inets2):
    '''
    inets1和inets2都是IP网段集合
    检查两个网段集合是否有重复IP
    此函数与check_conflict功能相同，在ip数量较少（10000以下)的时候性能良好
    '''
    if type(inets1) not in (list, tuple, set):
        inets1 = [inets1]
    if type(inets2) not in (list, tuple, set):
        inets2 = [inets2]
    iplist1 = unfold_to_intset(inets1)
    iplist2 = unfold_to_intset(inets2)
    for ip in iplist1:
        if ip in iplist2:
            return True
    return False
def unfold_to_intset(inets):
    '''
    将IP网段展开为IP整数值集合
    :inets 多个IP网段，子网,IP
    @return: set([<int>])
    '''
    if type(inets) not in (tuple, set, list):
        inets = [inets]
    ipset = set()
    for inet in inets:
        try:
            cursor, end = split_ipsegment_int(inet)
            while cursor <= end:
                ipset.add(cursor)
                cursor += 1
        except ValueError:
            continue
    return ipset
</pre>
- inets1中的所有IP是否都存在于inets2中
<pre>
def check_include(inets1, inets2):
    '''
    inets1中的所有IP是否都存在于inets2中
    '''
    if type(inets1) not in (list, tuple, set):
        inets1 = [inets1]
    if type(inets2) not in (list, tuple, set):
        inets2 = [inets2]
    iplist1 = unfold_to_intset(inets1)
    iplist2 = unfold_to_intset(inets2)
    for ip in iplist1:
        if ip not in iplist2:
            return False
    return True
</pre>
- 检查给定的ip地址或者范围是否合法
<pre>
'''
函数名称：checkIpRange
函数功能：检查给定的ip地址（或范围）是否是合法的格式。如果合法，返回true，如果不合法，返回false.
支持格式：
192.168.1.1
192.168.1.1-252
192.168.1.1/24
192.168.1.*
192.168.1-10.*
2001:2002::2003:7ab4
2001:2002:2003::/48
'''
def checkIpRange(ipRange,func=False):
    p = r"(0|[1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    m = r"([1-9]|[1-2][0-9]|3[0-2])"
    n = r"([1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    
    res = [
           r"^!?%s\.%s\.%s\.%s$"%(p,p,p,p), #匹配如192.168.1.1
           r"^!?%s\.%s\.%s\.%s\/%s$"%(p,p,p,p,m), #匹配如192.168.1.1/24
           r"^!?%s\.%s\.%s\.%s-%s$"%(p,p,p,p,n), #匹配如192.168.1.1-254 
           r"^!?%s\.%s\.%s\.(\*)$"%(p,p,p), #匹配如192.168.1.*
           r"^!?%s\.%s\.(\*)\.(\*)$"%(p,p), #匹配如192.168.*.*
           r"^!?%s\.(\*)\.(\*)\.(\*)$"%(p), #匹配如192.*.*.*
           r"^!?%s\.%s\.%s-%s\.(\*)$"%(p,p,p,n),#匹配如192.168.1-10.*
           r"^!?(\*)\.(\*)\.(\*)\.(\*)$", #匹配如*.*.*.*
           r"^!?\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$",#匹配如2001:2002::2003:7ab4
           r"^!?\A(?:(?:(?:[a-f0-9]{1,4}:){6}|::(?:[a-f0-9]{1,4}:){5}|(?:[a-f0-9]{1,4})?::(?:[a-f0-9]{1,4}:){4}|(?:(?:[a-f0-9]{1,4}:){0,1}[a-f0-9]{1,4})?::(?:[a-f0-9]{1,4}:){3}|(?:(?:[a-f0-9]{1,4}:){0,2}[a-f0-9]{1,4})?::(?:[a-f0-9]{1,4}:){2}|(?:(?:[a-f0-9]{1,4}:){0,3}[a-f0-9]{1,4})?::[a-f0-9]{1,4}:|(?:(?:[a-f0-9]{1,4}:){0,4}[a-f0-9]{1,4})?::)(?:[a-f0-9]{1,4}:[a-f0-9]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))|(?:(?:(?:[a-f0-9]{1,4}:){0,5}[a-f0-9]{1,4})?::[a-f0-9]{1,4}|(?:(?:[a-f0-9]{1,4}:){0,6}[a-f0-9]{1,4})?::))(\/([0][0-9]{1,2}|[0-9]{1,2}|1[0-1][0-9]|12[0-8])){0,1}\Z" #匹配如2001:2002:2003::/48
           ]
    
    for i in range(len(res)):
        ips = re.match(res[i],ipRange.strip())
        if ips: //strip() 去掉字符串首尾的指定字符，返回新的字符串，为空即删除空格
            data = [ipRange.strip()]
            for ip in ips.groups()://groups()返回匹配的元组
                data.append(ip)
            if func:
                return globals()[func](i,data)
            else: 
                return True;
    return False
    
函数名称：getIpMaxAndMinRange
函数功能：获取ip范围的最大最小值，
返回值：给定范围的最大最小值的区间.
'''
def getIpMaxAndMinRange(seq,m):
    if seq==0:
        return [m[0],m[0]]
    elif seq==1:
        pat1 = "";
        pat2 = "";
        for i in range(32):    
            if i< int(m[5]):
                pat1 += '1'
                pat2 += '0'
            else:
                pat1 += '0'
                pat2 += '1'
        min = int(pat1,2)
        max = int(pat2,2)
        ipnum = ip4utils.ip2long(".".join([m[1],m[2],m[3],m[4]]))
        minipnum = min & ipnum
        maxipnum = max | ipnum
        return ['%s'%(ip4utils.long2ip(minipnum)),'%s'%(ip4utils.long2ip(maxipnum))]
    elif seq==2:
        return ["%s.%s.%s.%s"%(m[1],m[2],m[3],m[4]),"%s.%s.%s.%s"%(m[1],m[2],m[3],m[5])]
    elif seq==3:
        return ["%s.%s.%s.0"%(m[1],m[2],m[3]),"%s.%s.%s.255"%(m[1],m[2],m[3])]
    elif seq==4: 
        return ["%s.%s.0.0"%(m[1],m[2]),"%s.%s.255.255"%(m[1],m[2])]
    elif seq == 5:
        return ["%s.0.0.0"%(m[1]),"%s.255.255.255"%(m[1])]
    elif seq == 6:
        return ["%s.%s.%s.0"%(m[1],m[2],m[3]),"%s.%s.%s.255"%(m[1],m[2],m[4])]
    elif seq == 7:
        return ['0.0.0.0', '255.255.255.255']
    elif seq == 8:
        return [m[0],m[0]] #单个ipv6地址
    elif seq == 9:
        ip_str,prefix_str=m[0].split("/")
        ip_long = ip6utils.ip2long(ip_str)
        prefix_int = int(prefix_str)
        return [ip6utils.uncompress(ip6utils.long2ip(ip_long>>(128-prefix_int)<<(128-prefix_int))),ip6utils.long2ip(~(~ip_long>>(128-prefix_int)<<(128-prefix_int)))]
</pre>
- 判断范围range1是否在范围range2之中，range1和range2都是网段的集合
<pre>
'''
函数名称：isRange1InRange2(range1,range2)
函数功能：判断范围range1是否在范围range2之中，range1和range2都是网段的集合.
返回值：如果range1 在 range2 之中，则返回true，否则返回false
参数range1,range2：用逗号，分号，回车或者空格分隔的ip网络范围的集合(ipv4 and ipv6).
'''
def isRange1InRange2(range1,range2):
    if not range1 or not range2:
        return False
    range1List = re.split(r'[\s;,]+',range1.strip()) #['192.168.0.1', '192.168.1.1-254','2001::db8:2003/48']
    range2List = re.split(r'[\s;,]+',range2.strip())
    range1List = list(set(range1List))
    range2List = list(set(range2List))
    list1Ipv4 = []
    list1Ipv6 = []
    list2Ipv4 = []
    list2Ipv6 = []
    listnotIpv4 = []
    listnotIpv6 = []
    for perRange1 in range1List:
        if perRange1[0:1] == "!":
            continue
        if perRange1.find(':') == -1:
            list1Ipv4.append(perRange1)
        else:
            list1Ipv6.append(perRange1)
    for perRange2 in range2List:
        if perRange2[0:1] == "!":
            if perRange2.find(':') == -1:
                listnotIpv4.append(perRange2[1:])
            else:
                listnotIpv6.append(perRange2[1:])
            continue
        if perRange2.find(':') == -1:
            list2Ipv4.append(perRange2)
        else:
            list2Ipv6.append(perRange2)
    
    if len(listnotIpv4)!=0:
        for notIpv4 in listnotIpv4:
            if isRange1InRange2(notIpv4, range1):
                return False
    
    if len(listnotIpv6)!=0:
        for notIpv6 in listnotIpv6:
            if isRange1InRange2(notIpv6, range1):
                return False
    
    #range1仅包含ipv4范围，range2仅包含ipv6范围
    if len(list1Ipv4)!=0 and len(list1Ipv6)==0 and len(list2Ipv4)==0 and len(list2Ipv6)!=0:
        return False
    
    #range1仅包含ipv6范围，range2仅包含ipv4范围
    if len(list1Ipv4)==0 and len(list1Ipv6)!=0 and len(list2Ipv4)!=0 and len(list2Ipv6)==0:
        return False
    
    #range1和range2都仅包含ipv4范围
    if len(list1Ipv4)!=0 and len(list2Ipv4)!=0 and len(list1Ipv6)==0 and len(list2Ipv6)==0:
        for seg1 in list1Ipv4:
            flag = False
            m1 = checkIpRange(seg1,'getIpMaxAndMinRange')
            for seg2 in list2Ipv4:
                m2 = checkIpRange(seg2,'getIpMaxAndMinRange')
                if ip4utils.ip2long(m1[0])>=ip4utils.ip2long(m2[0]) and ip4utils.ip2long(m1[1])<=ip4utils.ip2long(m2[1]):
                    flag = True
                    break
            if not flag:
                return False
        return True
    
    #range1和range2都仅包含ipv6范围
    if len(list1Ipv4)==0 and len(list2Ipv4)==0 and len(list1Ipv6)!=0 and len(list2Ipv6)!=0:
        for seg1 in list1Ipv6:
            flag = False
            m1 = checkIpRange(seg1,'getIpMaxAndMinRange')
            for seg2 in list2Ipv6:
                m2 = checkIpRange(seg2,'getIpMaxAndMinRange')
                if m2[0] == "::":
                    flag = True
                elif ip6utils.ip2long(m1[0])>=ip6utils.ip2long(m2[0]) and ip6utils.ip2long(m1[1])<=ip6utils.ip2long(m2[1]):
                    flag = True
                    break
            if not flag:
                return False
        return True
    
    #range1包含ipv4范围，range2包含ipv4和ipv6
    if len(list1Ipv4)!=0 and len(list1Ipv6)==0 and len(list2Ipv4)!=0 and len(list2Ipv6)!=0:
        for seg1 in list1Ipv4:
            flag = False
            m1 = checkIpRange(seg1,'getIpMaxAndMinRange')
            for seg2 in list2Ipv4:
                m2 = checkIpRange(seg2,'getIpMaxAndMinRange')
                if m2[0] == "*.*.*.*":
                    flag = True
                    break
                if ip4utils.ip2long(m1[0])>=ip4utils.ip2long(m2[0]) and ip4utils.ip2long(m1[1])<=ip4utils.ip2long(m2[1]):
                    flag = True
                    break
            if not flag:
                return False
        return True
       
    #range1包含ipv6范围，range2包含ipv4和ipv6
    if len(list1Ipv6)!=0 and len(list1Ipv4)==0 and len(list2Ipv6)!=0 and len(list2Ipv6)!=0:
        for seg1 in list1Ipv6:
            flag = False
            m1 = checkIpRange(seg1,'getIpMaxAndMinRange')
            for seg2 in list2Ipv6:
                m2 = checkIpRange(seg2,'getIpMaxAndMinRange')
                if m2[0] == "::":
                    flag = True
                    break
                elif ip6utils.ip2long(m1[0])>=ip6utils.ip2long(m2[0]) and ip6utils.ip2long(m1[1])<=ip6utils.ip2long(m2[1]):
                    flag = True
                    break
            if not flag:
                return False
        return True
        
    #range1和range2既包含ipv4范围，又包含ipv6范围
    if len(list1Ipv4)!=0 and len(list2Ipv4)!=0 and len(list1Ipv6)!=0 and len(list2Ipv6)!=0:
        for seg1 in list1Ipv4:
            flag1 = False
            m1 = checkIpRange(seg1,'getIpMaxAndMinRange')
            for seg2 in list2Ipv4:
                m2 = checkIpRange(seg2,'getIpMaxAndMinRange')
                if ip4utils.ip2long(m1[0])>=ip4utils.ip2long(m2[0]) and ip4utils.ip2long(m1[1])<=ip4utils.ip2long(m2[1]):
                    flag1 = True
                    break
            if not flag1:
                break
        for seg1 in list1Ipv6:
            flag2 = False
            m1 = checkIpRange(seg1,'getIpMaxAndMinRange')
            for seg2 in list2Ipv6:
                m2 = checkIpRange(seg2,'getIpMaxAndMinRange')
                if m2[0] == "::":
                    flag2 = True
                    break
                elif ip6utils.ip2long(m1[0])>=ip6utils.ip2long(m2[0]) and ip6utils.ip2long(m1[1])<=ip6utils.ip2long(m2[1]):
                    flag2 = True
                    break
            if not flag2:
                break
        if flag1 and flag2:
            return True
        return False
    
    if len(list1Ipv4)!=0 and len(list2Ipv4)!=0 and len(list1Ipv6)!=0 and len(list2Ipv6)==0:
        return False
    if len(list1Ipv4)!=0 and len(list2Ipv4)==0 and len(list1Ipv6)!=0 and len(list2Ipv6)!=0:
        return False

</pre>
