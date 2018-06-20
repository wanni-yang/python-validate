'''
#装饰器
视图函数应用验证装饰器：
1.在视图函数之前@ValidateDecorator()
2.定义_validate_function(request,context)
3.在_validate_function中验证各个字段
@ValidateDecorator()
def function(request):
    id = request.POST['id']

    return render_to_response('')

#验证方法以 _validate_ 做前缀
def _validate_function(request, context):
    if not context.validate_numeric('id'):
        context.add_error('非法ID！')
'''
'''
ValidateDecorator定义
为装饰了validate的视图函数找到_validate_function和验证上下文对象 context
'''
class ValidateDecorator (object):
    
    def __init__(self, **kwargs):
        self.args = kwargs
        pass
    
    def __call__(self, view_func):
        def delegate(request, *args, **kwargs):
            try:
                context, result = self.__validate(view_func, request, args, kwargs)
                if isinstance(result, HttpResponse):
                    return result
            except Http404:
                return HttpResponseNotFound()
            
            if not context.has_error():
                try:
                    return view_func(request, *args, **kwargs)
                except Exception, e:
                    logging.exception(e)
                    raise e
            else:
                result = dict(actionErrors = context.get_errors(), fieldErrors = context.get_fielderrors())
                return render_json(result, False) 
                
        return delegate
    
    def __validate(self, view_func, request, args, kwargs):
        validate_func = self.__lookup_validator(view_func)
        context = ValidatorContext(request)
        result = None
        if validate_func != None:
            result = validate_func(request, context, *args, **kwargs)
        return context, result
    
    def __lookup_validator(self, view_func):
        logging.info('#########')
        logging.info(sys.modules[view_func.__module__])
        
        if self.args.has_key('validator'):
            return self.args['validator']
        else:
            mod = sys.modules[view_func.__module__]
            if hasattr(mod, '_validate_%s' % view_func.__name__):
                return getattr(mod, '_validate_%s' % view_func.__name__)
            else:
                return None
'''
验证上下文定义

'''
class ValidatorContext(object):
    
    def __init__(self, request):
        self.request = request
        if 'GET' == request.META.get('REQUEST_METHOD'):
            params = request.GET
        elif 'POST' == request.META.get('REQUEST_METHOD'):
            params = request.POST
        from common.web.http import query2dict
        self.query = query2dict(params)
        
        self._field_errors = {}
        self._errors = []
        

    def add_error(self, msg):
        self._errors.append(msg)
    
    def add_fielderror(self, field, msg):
        stack = []
        if self._field_errors.has_key(field): 
            stack = self._field_errors[field]
        stack.append(msg)
        self._field_errors[field] = stack
    
    def has_error(self):
        return len(self._errors) > 0 or len(self._field_errors.keys()) > 0
    
    def get_errors(self):
        return self._errors
    
    def clear_errors(self):
        self._errors = []
        
    def get_fielderrors(self):
        return self._field_errors
    
    def clear_fielderrors(self):
        self._field_errors = {}
    @_validate_dec
    def validate_presented(self, field, msg = None):
        """
        校验字段不为空
        """
        value = self._parse_value(field)
        if value == None:
            return False
        if type(value) in (str, unicode):
            return value.strip() != ''
        if type(value) in (list, tuple):
            return len(value) > 0
    @_validate_dec
    def validate_dev(self, field, msg = None):
        """
        校验中英文 -_() 数字 长度不超过100

        """
        value = self._parse_value(field)
        if not value:
            return False
        return re.match(u'[\w\u4e00-\u9fa5\s\-\(\)\.\,]{1,100}', value)
    @_validate_dec
    def validate_dev_dec(self, field, msg = None):
        """
        校验中英文 -_() 数字 长度不超过100

        """
        value = self._parse_value(field)
        if not value:
            return False
        return re.match(u'[\w\u4e00-\u9fa5\s\-\(\)\.\,]{0,500}', value)
    @_validate_dec
    def validate_fieldequals(self, field, field2, msg = None):
        """
        校验两个字段相等 
        """
        return self._parse_value(field) != self._parse_value(field2)
    
    @_validate_dec
    def validate_equals(self, field, value, msg = None):
        """
        校验field的值是否等于value
        """
        fieldvalue = self._parse_value(field)
        return fieldvalue != str(value)
            
    @_validate_dec
    def validate_format(self, field, pattern, not_match = False, msg = None):
        """
        验证是否符合表达式'pattern'
        """
        value = self._parse_value(field)
        matched = re.match(pattern, value)
        return not_match and not matched or matched != None
    
    @_validate_dec   
    def validate_numeric(self, field, msg = None):
        """
        验证是否为整数
        """
        value = self._parse_value(field)
        if not value:
            return False
        return re.match(r'^[0-9]+$', value)
    
    
    @_validate_dec
    def validate_range(self, field, min = None, max = None, msg = None):
        """
        验证是否在数值范围之内
        """
        if min == None and max == None:
            assert False, 'min和max必须输入一项'
        value = self._parse_value(field)
        flag = True
        if type(min) == float or type(max) == float:
            value = float(value)
        elif type(min) == int or type(max) == int:
            value = int(value)
            
        if max == None:
            flag = value > min
        elif min == None:
            flag = max > value
        else:
            flag = min < value < max
        
        return flag        
    
    @_validate_dec
    def validate_ipv4(self, field, msg = None):
        """
        验证IPv4地址格式
        """
        value = self._parse_value(field)
        return is_ipv4(value)
    
    @_validate_dec
    def validate_subnet(self, field, msg = None):
        """
        验证子网格式
        """
        value = self._parse_value(field)
        return is_subnet(value)
    
    @_validate_dec
    def validate_ipsegment(self, field, msg = None):
        """
        验证IP段格式
        """
        value = self._parse_value(field)
        return is_ipsegment(value)
    
    @_validate_dec
    def validate_iprange(self, field, msg = None):
        """
        验证是否符合IPv4地址格式 或 子网格式 或 IP段格式
        """
        value = self._parse_value(field)
        return is_ipv4(value) or is_subnet(value) or is_ipsegment(value)
    
    @_validate_dec
    def validate_ipranges(self, field, separator_pattern = r"\n", msg = None):
        """
        验证是否符合IPv4地址格式 或 子网格式 或 IP段格式
        """
        values = self._parse_value(field)
        for ip_range in re.split(separator_pattern, values):
            if not (is_ipv4(value) or is_subnet(value) or is_ipsegment(value)):
                return False
        else:
            return True

    @_validate_dec
    def validate_ga(self,field,ip,mask, msg = None):
        """
        验证网关地址格式
        """
        value = self._parse_value(field)
        ip = self._parse_value(ip)
        mask = self._parse_value(mask)
        in_ip = ip2int(ip)
        in_mask = ip2int(mask)
        ipra = in_ip & in_mask
        ra = ipmasktseg(int2ip(ipra),mask)
        i = ip2int(value)
        if i<(ra[1]-1) and i>=ra[0]:
            return True
        else:
            return False

    @_validate_dec
    def validate_portnum(self, field, msg = None):
        """
        验证端口号
        """
        value = self._parse_value(field)
        return self.validate_numeric(field) and (0 <=  int(value) < 65536) 
    
    @_validate_dec
    def validate_mask(self, field, msg = None):
        value = self._parse_value(field)
        return is_ipmask(value)
    
    @_validate_dec
    def validate_strlen(self, field, min, max, msg = None):
        """
        验证字符串长度
        """
        if min == None and max == None:
            assert False, 'min和max必须输入一项'
        value = self._parse_value(field)
        if value == None:
            return False
        
        strlen = len(value)
            
        if max == None:
            flag = max >= strlen
        elif min == None:
            flag = strlen <= min
        else:
            flag = min <= strlen <= max
        
        return flag
    
    @_validate_dec
    def validate_email(self, field, msg = None):
        """
        验证邮件地址
        """
        pattern = r'^[^@]+@([-\w]+\.)+[A-Za-z]{2,4}$'
        value = self._parse_value(field)
        return value != None and re.match(pattern, value)
