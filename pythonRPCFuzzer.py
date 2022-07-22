
from ast import arg
import os
import re
import time
from tkinter import EXCEPTION
import windows
import windows.rpc
import windows.generated_def as gdef
import windows.rpc.ndr as ndr
import sys
import random
import struct


class IntGenerator(object):
    def __init__(self, max_num):
        self.choices = [0xff]
        self.max_num = (1 << max_num) - 1
        if self.max_num > 0x80000000:
            self.choices.append(0x7FFFFFFF)
            self.choices.append(0x80000000)
        self.add_integer_boundaries(0)
        self.add_integer_boundaries(self.max_num / 2)
        self.add_integer_boundaries(self.max_num / 3)
        self.add_integer_boundaries(self.max_num / 4)
        self.add_integer_boundaries(self.max_num / 8)
        self.add_integer_boundaries(self.max_num / 16)
        self.add_integer_boundaries(self.max_num / 32)
        self.add_integer_boundaries(self.max_num)
        # Add some randoms
        for _ in range(50):
            self.choices.append(random.randint(0, self.max_num))
    def add_integer_boundaries (self, integer):
        for i in range(-10, 10):
            case = integer + i
            if 0 <= case < self.max_num:
                if case not in self.choices:
                    self.choices.append(int(case))
class StringGenerator(object):
    def __init__(self):
        self.choices = [
            "",
            ".",
            "C:\\Windows\\aaa",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\cmdU.exe",
            "C:\\Windows\\System32",
            "C:\\Windows\\System32\\",
            "http://google.fr/",
            "https://google.fr/",
            "http://42424242.fr/",
            "ssh://42424242.fr/",
            # strings ripped from spike (and some others I added)
            "/.:/"  + "A"*400 + "\x00\x00",
            "/.../" + "A"*400 + "\x00\x00",
            "/.../.../.../.../.../.../.../.../.../.../",
            "/../../../../../../../../../../../../etc/passwd",
            "/../../../../../../../../../../../../boot.ini",
            "..:..:..:..:..:..:..:..:..:..:..:..:..:",
            "\\\\*",
            "\\\\?\\",
            "/\\" * 400,
            "/." * 400,
            "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
            "%01%02%03%04%0a%0d%0aADSF",
            "%01%02%03@%04%0a%0d%0aADSF",
            "/%00/",
            "%00/",
            "%00",
            "%u0000",
            "%\xfe\xf0%\x00\xff",
            "%\xfe\xf0%\x01\xff" * 20,
            
            # format strings.
            "%n"     * 100,
            "%n"     * 50,
            "\"%n\"" * 50,
            "%s"     * 100,
            "%s"     * 50,
            "\"%s\"" * 50,
            
            # command injection.
            "|touch /tmp/SULLEY",
            ";touch /tmp/SULLEY;",
            "|notepad",
            ";notepad;",
            "\nnotepad\n",
            "||cmd.exe&&id||",
            
            # SQL injection.
            "1;SELECT%20*",
            "'sqlattempt1",
            "(sqlattempt2)",
            "OR%201=1",
            
            # some binary strings.
            "\xde\xad\xbe\xef",
            "\xde\xad\xbe\xef" * 10,
            "\xde\xad\xbe\xef" * 100,
            "\xde\xad\xbe\xef" * 200,
            "\xde\xad\xbe\xef" * 200,
            "\x00"             * 200,
            
            # miscellaneous.
            "\r\n" * 100,
            "<>" * 400,         # sendmail crackaddr
        ]
        self.add_long_strings("A")
        self.add_long_strings("B")
        self.add_long_strings("1")
        self.add_long_strings("2")
        self.add_long_strings("3")
        self.add_long_strings("<")
        self.add_long_strings(">")
        self.add_long_strings("'")
        self.add_long_strings("\"")
        self.add_long_strings("/")
        self.add_long_strings("\\")
        self.add_long_strings("?")
        self.add_long_strings("=")
        self.add_long_strings("a=")
        self.add_long_strings("&")
        self.add_long_strings(".")
        self.add_long_strings(",")
        self.add_long_strings("(")
        self.add_long_strings(")")
        self.add_long_strings("]")
        self.add_long_strings("[")
        self.add_long_strings("%")
        self.add_long_strings("*")
        self.add_long_strings("-")
        self.add_long_strings("+")
        self.add_long_strings("{")
        self.add_long_strings("}")
        self.add_long_strings("\x14")
        self.add_long_strings("\xFE")   # expands to 4 characters under utf16
        self.add_long_strings("\xFF")   # expands to 4 characters under utf16
        
        # Strings with null bytes
        for length in [4, 8, 16, 32, 128, 256, 512]:
            s = "B" * length
            s = s[:int(len(s)/2)] + "\x00" + s[int(len(s)/2):]
            self.choices.append(s)
        
        # Add null bytes !
        choices_cp = self.choices[:]
        self.choices = []
        for i in choices_cp:
            self.choices.append(i + '\0')
        
    
    def add_long_strings(self, sequence):
        for length in [1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 255, 256, 257, 511, 512, 513, 1023, 1024]:
            long_string = sequence * length
            self.choices.append(long_string)

string_generator    = StringGenerator()
byte_generator      = IntGenerator(8)
short_generator     = IntGenerator(16)
long_generator      = IntGenerator(32)
hyper_generator     = IntGenerator(64)
def array_gengrator(intgenerator): 
    array = []
    for i in range(random.randint(1,20)):
        array.append(intgenerator.choices[random.randint(0,len(intgenerator.choices)-1)])
    return array
#解析c#文件获取类，结构体函数

def pack_dword(x):
	return struct.pack("<I", x)
	
	
def dword_pad(s):
    if (len(s) % 4) == 0:
        return s
    return s + (b"P" * (4 - len(s) % 4))
	
class analyze(object):
    def __init__(self,csfilepath):
        self.csfilepath = csfilepath
        self.filecontents = None
        self.construct = None
        self.index = -1
        
    
    def read_file(self):
        self.filecontents = open(self.csfilepath, 'r').read()

    #处理注释和#说明域
    def delete_notation(self,filecontents):
        result = ""
        condition = True
        for index_ in range(len(filecontents)):
            if filecontents[index_] == "/" and filecontents[index_+1] == "/":
                condition = False
                continue
            if filecontents[index_] == "#":
                condition = False
                continue
            if filecontents[index_] == "\n":
                condition = True
            if condition == True:
                result += filecontents[index_]
        return result

    #删除注释，说明域，缩进，换行
    def content_filter(self):
        self.filecontents = self.delete_notation(self.filecontents)
        self.filecontents = self.filecontents.replace("\n", "").replace("    ", "")


    def argument_analyze(self,index, filecontents):
        method_arg = []
        arg = ""
        while (index < len(filecontents)):
            index += 1
            # 遇到逗号认为是分开参数
            if (filecontents[index] == '('):
                method_arg.append([])
                if arg != "":
                    method_arg[-1].append(arg.strip())
                    arg = ""
                inner_arg = self.argument_analyze(index, filecontents)
                method_arg[-1].append(inner_arg[0])
                index = inner_arg[1]
                continue

            if (filecontents[index] == ','):
                if arg != "":
                    method_arg.append(arg.strip())
                    arg = ""
                continue

            # 遇到反括号表示该括号内参数解析完成
            if (filecontents[index] == ')'):
                if arg != "":
                    method_arg.append(arg.strip())
                    arg = ""
                return (method_arg, index)

            arg += filecontents[index]

    def method_analyze(self,index, filecontents):
        class_method = []
        method = ""
        while (index < len(filecontents)-1):
            index += 1
            # 遇到括号将前面函数名加入函数数组并调用参数解析
            # print(index)
            if (filecontents[index] == '('):
                if method != "":
                    class_method.append([])
                    class_method[-1].append(method.strip())
                    method = ""
                method_arg = self.argument_analyze(index, filecontents)
                index = method_arg[1]
                class_method[-1].append(method_arg[0])
                continue

            if (filecontents[index] == ';'):
                if method != "":
                    class_method.append([])
                    class_method[-1].append(method.strip())
                    method = ""
                continue

            if (filecontents[index] == '{'):
                if (method != ""):
                    class_method.append([])
                    class_method[-1].append(method.strip())
                    method = ""

                inner_methods = self.method_analyze(index, filecontents)
                class_method[-1].append(inner_methods[0])
                index = inner_methods[1]
                continue

            if (filecontents[index] == '}'):
                return (class_method, index)

            method += filecontents[index]
        return (class_method, index)

    def get_construct(self):
        self.read_file()
        self.content_filter()
        self.construct = self.method_analyze(self.index,self.filecontents)
    


class Interface(object):
    def __init__(self, uuid, version):
        """RPC Interface"""
        #rpc  唯一uuid 版本1.0/0.0 接口方法
        self.uuid = uuid
        self.version = version
    #    self.update_methods_ids()
        self.contexts = set([])
        self.client = None
        self.iid = None


    #给方法配id
    #def update_methods_ids(self):
    #    for i in range(len(self.methods)):
    #        self.methods[i].id = i
            
            #连接rpc服务器函数，用uuid和endpoints两种方式连接，将连接保存到self.client中
    def connect(self):
        """Connect to the interface using either epmapper RPC service or fixed ALPC endpoint name"""
        #记录日志
        print("Try to connect to {} - {}".format(self.uuid, self.version))
        if not hasattr(self, "is_registered") or self.is_registered:
            # Try epmapper to open ALPC endpoint and connect to it
            for known_sid in gdef.WELL_KNOWN_SID_TYPE.values:
                try:    
                    #尝试连接
                    self.client = windows.rpc.find_alpc_endpoint_and_connect(self.uuid, version=self.version, sid=known_sid)
                    self.iid = self.client.bind(self.uuid, version=self.version)
                    if self.iid:
                        print("Successfully connect to endpoint {} - {}".format(self.uuid, self.version))
                        break
                except Exception as e:
                    pass
                #iid记录连接
            if not self.iid:
                print("Could not find a valid endpoint for target <{0}> version <{1}> with epmapper".format(self.uuid, self.version))
        #有endpoints用endpoints连接        
        if hasattr(self, "endpoints"):
            # Try ncalrpc endpoints
            for endpoint in self.endpoints:
                try:
                    self.client = windows.rpc.RPCClient("\\RPC Control\\" + endpoint)
                    self.iid = self.client.bind(self.uuid, version=self.version)
                    if self.iid:
                        break
                except:
                    pass
            if not self.iid:
                print("Could not connect to a valid endpoint for target <{0}> version <{1}>".format(self.uuid, self.version))
        # Fail ...
        if not self.iid:
            raise ValueError("Impossible to connect to {}".format(self.uuid))

    #删除连接

    def disconnect(self):
        if hasattr(self, "client") and self.client:
            del self.client

    def call(self, method, argument):
        """Perform the RPC call"""
        #检查是否连接
        if not self.client:
            raise(Exception("Not connected!"))
        #判断输入method是字符串还说方法，并保存到
        #if isinstance(method, str):
        #    method = self.find_method_by_name(method)
        #if isinstance(method, Method):
        #    method = method.id
        return self._call(self.client, self.iid, method, argument)

    #client远程调用方法，client连接，iid连接id，方法和参数
    def _call(self, client, iid, method, arguments):
        #print(method,arguments)
        return client.call(iid, method, arguments)

    
    def get_arg():
        pass
    
    
    def generate_arg(self,arg_type_list): 
        args_packed = b""
        arg = ""
        for arg_type in arg_type_list:
            if isinstance(arg_type,ndr.NdrWString):
                #arg = string_generator.choices[random.randint(0,len(string_generator.choices)-1)]
                arg = "\\\\localhost\\pipe\\testpipe"
                args_packed += ndr.NdrWString.pack(arg)
            elif isinstance(arg_type,ndr.NdrLong):
                arg = long_generator.choices[random.randint(0,len(long_generator.choices)-1)]
                args_packed += ndr.NdrLong.pack(arg)
            elif isinstance(arg_type,ndr.NdrShort):
                arg = short_generator.choices[random.randint(0,len(short_generator.choices)-1)]
                args_packed += ndr.NdrShort.pack(arg)
            elif isinstance(arg_type,ndr.NdrByte):
                arg = byte_generator.choices[random.randint(0,len(byte_generator.choices)-1)]
                args_packed += ndr.NdrByte.pack(arg)
            elif isinstance(arg_type,ndr.NdrHyper):
                arg = hyper_generator.choices[random.randint(0,len(hyper_generator.choices)-1)]
                args_packed += ndr.NdrHyper.pack(arg)
            elif isinstance(arg_type,ndr.NdrGuid):
                arg =  self.uuid
                args_packed = ndr.NdrGuid.pack(arg)
            elif isinstance(arg_type,ndr.NdrContextHandle):
                arg = self.uuid
                args_packed = ndr.NdrContextHandle.pack(arg)
            elif isinstance(arg_type,list): #结构
                args_packed = self.generate_arg(arg_type)
            elif isinstance(arg_type,dict): #union
                union_selector = random.randint(0,len(arg_type["arg_type"])-1)
                args_packed = self.generate_arg([arg_type["arg_type"][union_selector]])
                args_packed = ndr.NdrLong.pack(union_selector) + args_packed
            elif isinstance(arg_type,ndr.NdrShortConformantArray):
                arg =  array_gengrator(short_generator)
                args_packed = ndr.NdrShortConformantArray.pack(arg)
            elif isinstance(arg_type,ndr.NdrHyperConformantArray):
                arg =  array_gengrator(hyper_generator)
                args_packed = ndr.NdrHyperConformantArray.pack(arg)
            elif isinstance(arg_type,ndr.NdrByteConformantArray):
                arg =  array_gengrator(byte_generator)
                args_packed = ndr.NdrByteConformantArray.pack(arg)
            elif isinstance(arg_type,ndr.NdrLongConformantArray):
                arg =  array_gengrator(long_generator)
                args_packed = ndr.NdrLongConformantArray.pack(arg)
            elif isinstance(arg_type,tuple): #uniqueptr
                args_packed = self.generate_arg(arg_type[1])
                args_packed += pack_dword(0x02020202)
        return args_packed


#RAiLaunchAdminProcess(
#            handle,                                                   handle
#            L"C:\\Windows\\System32\\mmc.exe",                        执行路径  
#            L"XXX,wf.msc \"\\\\127.0.0.1\\C$\\gweeperx\\test.msc\"",  执行命令  *
#            0x1,                                                      StartFlag  1是管理员0是当前用户
#            0x00000400,                                               CreateFlag
#            L"D:\\",                                                  当前目录
#            L"WinSta0\\Default",                                      WindowsStation
#            &StructMember0,                                           Struct APP_STARTUP_INFO
#            0,                                                        HWND
#            0xffffffff,                                               Timeout
#            &Struct_56,                                               Struct APP_PROCESS_INFORMATION
#            &arg_12                                                   ElevationType
#        );

#int retval = client.RAiLaunchAdminProcess(executable, cmdline, (int)flags, (int)create_flags,@"c:\windows", desktop, start_info, new NdrUInt3264(GetDesktopWindow()),-1, out Struct_2 proc_info, out int elev_type);

#DCE RPC 定义了 NDR (Network Data Representation) 用于对网络进行编码来封送信息
#   NdrSid

#   NdrWString              ---string
#   NdrCString
#   NdrLong                 ---int
#   NdrHyper
#   NdrShort
#   NdrByte
#   NdrUniquePTR

#   NdrLongConformantArray
#   NdrByteConformantArray

class idl():
    # a[0][0]为整体,两个子项namespace和内部，a[0][0][1]子项为类,a[0][0][1][-1]为接口函数类
    def __init__(self,idl):
        self.idl = idl
        self.methods = None
        self.structs = []
        self.unions = []
        self.classes = []  #所有类
        self.uuid = None
        self.version = None

    def run(self):
        self.get_classes()
        self.get_methods()
        self.get_structs()
        self.get_unions()
        self.get_uuid()
        method_arg = self.get_arg()
        method_arg["type"] = []
        for i in range(len(self.methods[1])):
            if self.methods[1][i][0] != "public Client" and "public" in self.methods[1][i][0]:
                method_arg["type"].append(self.get_arg_type(self.methods[1][i]))


        #for i in range(len(method_arg["type"])):
        #    print(method_arg["type"][i])
        #    print("\n")
        return method_arg

    def get_classes(self):
        #class里存(类名，下标)
        for i in range(len(self.idl[0][0][1])):
            self.classes.append((self.idl[0][0][1][i][0],i))

    def get_methods(self):
        #类中找方法类
        for class_name in self.classes:
            if "NtApiDotNet.Win32.Rpc.RpcClientBase" in class_name[0]:
                self.methods = self.idl[0][0][1][class_name[1]]

    def get_structs(self):
        for class_name in self.classes:
            if "NtApiDotNet.Ndr.Marshal.INdrStructure" in class_name[0]:
                self.structs.append(self.idl[0][0][1][class_name[1]])

    def get_unions(self):
        for class_name in self.classes:
            if "NtApiDotNet.Ndr.Marshal.INdrNonEncapsulatedUnion" in class_name[0]:
                self.unions.append(self.idl[0][0][1][class_name[1]])

    def get_uuid(self):
        self.uuid = self.methods[1][1][1][0].replace("\"","")
        self.version = (int(self.methods[1][1][1][1]),int(self.methods[1][1][1][2]))

    def get_arg(self):
        methods = {"name":[],"arg":[]}
        for i in range(len(self.methods[1])):
            #每个函数 self.methods[1][i]
            if self.methods[1][i][0] != "public Client" and "public" in self.methods[1][i][0]:
                methods["name"].append(self.methods[1][i][0])
                methods["arg"].append(self.methods[1][i][1])
        return methods



    def get_arg_type(self,method):
        args = []
        for i in range(len(method[2])):
            if '_Marshal_Helper' in method[2][i][0] or "_Unmarshal_Helper" in method[2][i][0] or "Read" in method[2][i][0]:
                continue
            if 'WriteTerminatedString' in method[2][i][0]:
                args.append(ndr.NdrWString())
            elif 'WriteReferent' in method[2][i][0]:
                arg_name = method[2][i][1][0]
                arg_name = re.findall(r'p\d+',str(arg_name))[0]
                real_arg_type = None
                for t in method[1]:
                    if isinstance(arg_name, str) and  arg_name in t:
                        arg_type = t.split(" ")[0]
                        if arg_type == "ref" or arg_type ==  "in":
                            arg_type = t.split(" ")[1]
                        
                        if "string" in arg_type:
                            real_arg_type = ndr.NdrWString()
                        elif "short" in arg_type or "ushort" in arg_type:
                            real_arg_type = ndr.NdrShort()
                        elif "int" in arg_type or "uint" in arg_type:
                            real_arg_type = ndr.NdrLong()
                        elif "long" in arg_type or "ulong" in arg_type:
                            real_arg_type = ndr.NdrHyper()
                        elif "byte" in arg_type or "char"  in arg_type or "sbyte" in arg_type:
                            real_arg_type = ndr.NdrByte()
                        elif "Guid" in arg_type:
                            real_arg_type = ndr.NdrGuid()
                        elif "byte[]" in arg_type or "sbyte[]" in arg_type or "char[]" in arg_type:
                            real_arg_type = ndr.NdrByteConformantArray()
                        elif "int[]" in arg_type or "uint[]" in arg_type:
                            real_arg_type = ndr.NdrLongConformantArray()
                        elif "short[]" in arg_type or "ushort[]" in arg_type:
                            real_arg_type = ndr.NdrShortConformantArray()
                        elif "long[]" in arg_type or "ulong[]" in arg_type:
                            real_arg_type = ndr.NdrHyperConformantArray()
                        elif "Struct" in arg_type:
                            real_arg_type = self.get_struct(arg_type)
                        elif "Union" in arg_type:
                            real_arg_type = self.get_union(arg_type)
                        else:
                            print("[!]Got An Unknown Type {0}, Use Byte Instead".format(arg_type))
                            real_arg_type = ndr.NdrByte()
                    elif isinstance(arg_name, str) == False: 
                        print("[!]Got An Unknown Type {0} {1}, Use Byte[] Instead".format(method[2][i][0],arg_type))
                        args.append(ndr.NdrByteConformantArray())
                        break
                args.append((ndr.NdrUniquePTR(real_arg_type),[real_arg_type]))
            elif 'WriteInt32' in method[2][i][0]:
                args.append(ndr.NdrLong())
            elif 'WriteSByte' in method[2][i][0]:
                args.append(ndr.NdrByte())
            elif 'WriteInt64' in method[2][i][0] or "WriteUInt3264" in method[2][i][0] or "WriteUInt3264" in method[2][i][0]:
                args.append(ndr.NdrHyper())
            elif 'WriteEnum16' in method[2][i][0] or "WriteInt16" in method[2][i][0] :
                args.append(ndr.NdrShort())
            elif 'WriteContextHandle' in method[2][i][0]:
                args.append(ndr.NdrContextHandle())
            elif 'WriteGuid' in method[2][i][0]:
                args.append(ndr.NdrGuid())
            elif 'WriteEnum16' in method[2][i][0]:
                args.append(ndr.NdrShort())
            elif 'Write_' in method[2][i][0]:   
                arg_name = method[2][i][1][0]
                arg_name = re.findall(r'p\d+',str(arg_name))[0]
                struct_name = None
                for t in method[1]:
                    if isinstance(arg_name, str) and  arg_name in t:
                        struct_name = t.split(" ")[0]
                        if struct_name == "ref" or struct_name == "in" :
                            struct_name = t.split(" ")[1]
                if "Struct" in struct_name or "struct" in struct_name:
                    args.append(self.get_struct(struct_name))
                elif "Union" in struct_name or "union" in struct_name:
                    args.append(self.get_union(struct_name))
                elif "byte[]" in struct_name or "sbyte[]" in struct_name or "char[]" in struct_name:
                    args.append(ndr.NdrByteConformantArray())
                elif "int[]" in struct_name or "uint[]" in struct_name:
                    args.append(ndr.NdrLongConformantArray())
                elif "short[]" in struct_name or "ushort[]" in struct_name:
                    args.append(ndr.NdrShortConformantArray())
                elif "long[]" in struct_name or "ulong[]" in struct_name:
                    args.append(ndr.NdrHyperConformantArray())
                else :
                    print("[!]Got An Unknown Type {0} {1}, Use Byte Instead".format(method[2][i][0],struct_name))
                    args.append(ndr.NdrByte())
                
            else :
                print("[!]Got An Unknown Type {0} {1}, Use Byte Instead".format(method[2][i][0],struct_name))
                args.append(ndr.NdrByte())
        return args

    def get_struct(self,struct_name):
        struct_name = re.findall(r"Struct_\d+",struct_name)[0]
        structs= []
        struct_index =  None
        for i in range(len(self.structs)):
            if isinstance(struct_name, str) and struct_name in self.structs[i][0]:
                struct_index = i
        if struct_index != None:
            for t in range(len(self.structs[struct_index][1][1][2])):
                if '_Marshal_Helper' in self.structs[struct_index][1][1][2][t][0] or "_Unmarshal_Helper" in self.structs[struct_index][1][1][2][t][0] or "Read" in self.structs[struct_index][1][1][2][t][0]:
                    continue
                if 'WriteTerminatedString' in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrWString())
                if 'WriteReferent' in self.structs[struct_index][1][1][2][t][0]:
                    arg_name = self.structs[struct_index][1][1][2][t][1][0]
                    arg_name = re.findall(r'member\d+',str(arg_name))[0]
                    real_arg_type = None
                    for g in self.structs[struct_index][1][-1][1]:
                        if isinstance(arg_name, str) and  arg_name in g:
                            arg_type = t.split(" ")[0]
                            if arg_type == "ref" or arg_type ==  "in":
                                arg_type = t.split(" ")[1]
                            if "string" in arg_type:
                                real_arg_type = ndr.NdrWString()
                            elif "short" in arg_type or "ushort" in arg_type:
                                real_arg_type = ndr.NdrShort()
                            elif "int" in arg_type or "uint" in arg_type:
                                real_arg_type = ndr.NdrLong()
                            elif "long" in arg_type or "ulong" in arg_type:
                                real_arg_type = ndr.NdrHyper()
                            elif "byte" in arg_type or "char"  in arg_type or "sbyte" in arg_type:
                                real_arg_type = ndr.NdrByte()
                            elif "Guid" in arg_type:
                                real_arg_type = ndr.NdrGuid()
                            elif "byte[]" in arg_type or "sbyte[]" in arg_type or "char[]" in arg_type:
                                real_arg_type = ndr.NdrByteConformantArray()
                            elif "int[]" in arg_type or "uint[]" in arg_type:
                                real_arg_type = ndr.NdrLongConformantArray()
                            elif "short[]" in arg_type or "ushort[]" in arg_type:
                                real_arg_type = ndr.NdrShortConformantArray()
                            elif "long[]" in arg_type or "ulong[]" in arg_type:
                                real_arg_type = ndr.NdrHyperConformantArray()
                            elif "Struct" in arg_type:
                                real_arg_type = self.get_struct(arg_type)
                            elif "Union" in arg_type:
                                real_arg_type = self.get_union(arg_type)
                            else:
                                print("[!]Got An Unknown Type {0}, Use Byte Instead".format(arg_type))
                                real_arg_type = ndr.NdrByte()
                        elif isinstance(arg_name, str) == False: 
                            
                            print("[!]Got An Unknown Type {0} {1}, Use Byte[] Instead".format(self.structs[struct_index][1][-1][1],arg_type))
                            structs.append(ndr.NdrByteConformantArray())
                            break

                    structs.append((ndr.NdrUniquePTR(real_arg_type),[real_arg_type]))
                elif 'WriteInt32' in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrLong())
                elif 'WriteSByte' in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrByte())
                elif 'WriteInt64' in self.structs[struct_index][1][1][2][t][0] or "WriteUInt3264" in self.structs[struct_index][1][1][2][t][0] or "WriteUInt3264" in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrHyper())
                elif 'WriteEnum16' in self.structs[struct_index][1][1][2][t][0] or "WriteInt16" in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrShort())
                elif 'WriteContextHandle' in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrContextHandle())
                elif 'WriteGuid' in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrGuid())
                elif 'WriteEnum16' in self.structs[struct_index][1][1][2][t][0]:
                    structs.append(ndr.NdrShort())
                elif 'WriteEmbeddedPointer' in self.structs[struct_index][1][1][2][t][0]:
                    arg_name = self.structs[struct_index][1][1][2][t][1][0]
                    for h in self.structs[struct_index][1][-1][1]:
                        if isinstance(arg_name, str) and  arg_name in h :
                            struct_name = h.split(" ")[0]
                            if struct_name == "ref" or struct_name ==  "in":
                                struct_name = t.split(" ")[1]
                            if "string" in struct_name:
                                real_arg_type = ndr.NdrWString()
                            elif "short" in struct_name or "ushort" in struct_name:
                                real_arg_type = ndr.NdrShort()
                            elif "int" in struct_name or "uint" in struct_name:
                                real_arg_type = ndr.NdrLong()
                            elif "long" in struct_name or "ulong" in struct_name:
                                real_arg_type = ndr.NdrHyper()
                            elif "byte" in struct_name or "char"  in struct_name or "sbyte" in struct_name:
                                real_arg_type = ndr.NdrByte()
                            elif "Guid" in struct_name:
                                real_arg_type = ndr.NdrGuid()
                            elif "byte[]" in struct_name or "sbyte[]" in struct_name or "char[]" in struct_name:
                                real_arg_type = ndr.NdrByteConformantArray()
                            elif "int[]" in struct_name or "uint[]" in struct_name:
                                real_arg_type = ndr.NdrLongConformantArray()
                            elif "short[]" in struct_name or "ushort[]" in struct_name:
                                real_arg_type = ndr.NdrShortConformantArray()
                            elif "long[]" in struct_name or "ulong[]" in struct_name:
                                real_arg_type = ndr.NdrHyperConformantArray()
                            elif "Struct" in struct_name:
                                real_arg_type = self.get_struct(struct_name)
                            elif "Union" in struct_name:
                                real_arg_type = self.get_union(struct_name)
                            else:
                                real_arg_type = ndr.NdrByte()
                    structs.append(real_arg_type)
                elif 'Write_' in self.structs[struct_index][1][1][2][t][0]:    
                    arg_name = self.structs[struct_index][1][1][2][t][1][0]

                    for h in self.structs[struct_index][1][-1][1]:
                        if isinstance(arg_name, str) and  arg_name in h:
                            struct_name = h.split(" ")[0]
                            if struct_name == "ref" or struct_name == "in":
                                struct_name = h.split(" ")[1]
                            if "Struct" in struct_name:
                                structs.append(self.get_struct(struct_name))
                            elif "Union" in struct_name or "union" in struct_name:
                                structs.append(self.get_union(struct_name))
                            elif "byte[]" in struct_name or "sbyte[]" in struct_name or "char[]" in struct_name:
                                structs.append(ndr.NdrByteConformantArray())
                            elif "int[]" in struct_name or "uint[]" in struct_name:
                                structs.append(ndr.NdrLongConformantArray())
                            elif "short[]" in struct_name or "ushort[]" in struct_name:
                                structs.append(ndr.NdrShortConformantArray())
                            elif "long[]" in struct_name or "ulong[]" in struct_name:
                                structs.append(ndr.NdrHyperConformantArray())
                            else : 
                                print("[!]Got An Unknown Type {0} {1}, Use Byte Instead".format(self.structs[struct_index][1][1][2][t][0],struct_name))
                                structs.append(ndr.NdrByte())
                        elif isinstance(arg_name, str) == False: 
                            
                            print("[!]Got An Unknown Type {0} {1}, Use Byte[] Instead".format(self.structs[struct_index][1][1][2][t][0],struct_name))
                            structs.append(ndr.NdrByteConformantArray())
                            break
                else :
                    print("[!]Got An Unknown Type {0} {1}, Use Byte Instead".format(self.structs[struct_index][1][1][2][t][0],struct_name))
                    structs.append(ndr.NdrByte())
        return structs


    def get_union(self,union_name):
        unions= {"selector":ndr.NdrLong(),"arg_type":[]}
        union_index =  None
        for i in range(len(self.unions)):
            if union_name in self.unions[i][0]:
                union_index = i
        if union_index != None:

            for t in range(len(self.unions[union_index][1][2][2])-2):
                if t == 0:
                    continue
                if '_Marshal_Helper' in self.unions[union_index][1][2][2][t][2][0][0] or "_Unmarshal_Helper" in self.unions[union_index][1][2][2][t][2][0][0] or "Read" in self.unions[union_index][1][2][2][t][2][0][0]:
                    continue
                if 'WriteTerminatedString' in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrWString())
                if 'WriteReferent' in self.unions[union_index][1][2][2][t][2][0][0]:
                    arg_name = self.unions[union_index][1][2][2][t][2][0][1][0]
                    real_arg_type = None
                    for g in self.structs[union_index][1][-1][1]:
                        if isinstance(arg_name, str) and  arg_name in g:
                            arg_type = t.split(" ")[0]
                            if arg_type == "ref" or arg_type ==  "in":
                                arg_type = t.split(" ")[1]
                            if "string" in arg_type:
                                real_arg_type = ndr.NdrWString()
                            elif "short" in arg_type or "ushort" in arg_type:
                                real_arg_type = ndr.NdrShort()
                            elif "int" in arg_type or "uint" in arg_type:
                                real_arg_type = ndr.NdrLong()
                            elif "long" in arg_type or "ulong" in arg_type:
                                real_arg_type = ndr.NdrHyper()
                            elif "byte" in arg_type or "char"  in arg_type or "sbyte" in arg_type:
                                real_arg_type = ndr.NdrByte()
                            elif "Guid" in arg_type:
                                real_arg_type = ndr.NdrGuid()
                            elif "byte[]" in arg_type or "sbyte[]" in arg_type or "char[]" in arg_type:
                                real_arg_type = ndr.NdrByteConformantArray()
                            elif "int[]" in arg_type or "uint[]" in arg_type:
                                real_arg_type = ndr.NdrLongConformantArray()
                            elif "short[]" in arg_type or "ushort[]" in arg_type:
                                real_arg_type = ndr.NdrShortConformantArray()
                            elif "long[]" in arg_type or "ulong[]" in arg_type:
                                real_arg_type = ndr.NdrHyperConformantArray()
                            elif "Struct" in arg_type:
                                real_arg_type = self.get_struct(arg_type)
                            elif "Union" in arg_type:
                                real_arg_type = self.get_union(arg_type)
                            else:
                                print("[!]Got An Unknown Type {0}, Use Byte Instead".format(arg_type))
                                real_arg_type = ndr.NdrByte()
                        elif isinstance(arg_name, str) == False: 
                            
                            print("[!]Got An Unknown Type {0} {1}, Use Byte[] Instead".format(self.structs[struct_index][1][1][2][t][0],struct_name))
                            unions["arg_type"].append(ndr.NdrByteConformantArray())
                            break
                    unions["arg_type"].append((ndr.NdrUniquePTR(real_arg_type),[real_arg_type]))
                elif 'WriteInt32' in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrLong())
                elif 'WriteSByte' in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrByte())
                elif 'WriteInt64' in self.unions[union_index][1][2][2][t][2][0][0] or "WriteUInt3264" in self.unions[union_index][1][2][2][t][2][0][0] or "WriteUInt3264" in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrHyper())
                elif 'WriteEnum16' in self.unions[union_index][1][2][2][t][2][0][0] or "WriteInt16" in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrShort())
                elif 'WriteContextHandle' in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrContextHandle())
                elif 'WriteGuid' in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrGuid())
                elif 'WriteEnum16' in self.unions[union_index][1][2][2][t][2][0][0]:
                    unions["arg_type"].append(ndr.NdrShort())
                elif 'WriteEmbeddedPointer' in self.unions[union_index][1][2][2][t][2][0][0]:
                    arg_name = self.unions[union_index][1][2][2][t][2][0][1][0]
                    for h in self.unions[union_index][1][-1][1]:
                        if isinstance(arg_name, str) and  arg_name in h:
                            struct_name = h.split(" ")[0]
                            if struct_name == "ref" or struct_name ==  "in":
                                struct_name = t.split(" ")[1]
                            if "string" in struct_name:
                                real_arg_type = ndr.NdrWString()
                            elif "short" in struct_name or "ushort" in struct_name:
                                real_arg_type = ndr.NdrShort()
                            elif "int" in struct_name or "uint" in struct_name:
                                real_arg_type = ndr.NdrLong()
                            elif "long" in struct_name or "ulong" in struct_name:
                                real_arg_type = ndr.NdrHyper()
                            elif "byte" in struct_name or "char"  in struct_name or "sbyte" in struct_name:
                                real_arg_type = ndr.NdrByte()
                            elif "Guid" in struct_name:
                                real_arg_type = ndr.NdrGuid()
                            elif "byte[]" in struct_name or "sbyte[]" in struct_name or "char[]" in struct_name:
                                real_arg_type = ndr.NdrByteConformantArray()
                            elif "int[]" in struct_name or "uint[]" in struct_name:
                                real_arg_type = ndr.NdrLongConformantArray()
                            elif "short[]" in struct_name or "ushort[]" in struct_name:
                                real_arg_type = ndr.NdrShortConformantArray()
                            elif "long[]" in struct_name or "ulong[]" in struct_name:
                                real_arg_type = ndr.NdrHyperConformantArray()
                            elif "Struct" in struct_name:
                                real_arg_type = self.get_struct(struct_name)
                            elif "Union" in struct_name:
                                real_arg_type = self.get_union(struct_name)
                            else:
                                real_arg_type = ndr.NdrByte()
                    unions["arg_type"].append(real_arg_type)
                elif 'Write_' in self.unions[union_index][1][2][2][t][2][0][0]:    
                    arg_name = self.unions[union_index][1][2][2][t][2][0][1][0]
                    for h in self.unions[union_index][1][-1][1]:
                        if isinstance(arg_name, str) and  arg_name in h:
                            struct_name = h.split(" ")[0]
                            if struct_name == "ref" or struct_name == "in":
                                struct_name = h.split(" ")[1]
                            if "Struct" in struct_name:
                                unions["arg_type"].append(self.get_struct(struct_name))
                                #unions["arg_type"].append(ndr.NdrByte())
                            elif "Union" in struct_name or "union" in struct_name:
                                unions["arg_type"].append(self.get_union(struct_name))
                            elif "byte[]" in struct_name or "sbyte[]" in struct_name or "char[]" in struct_name:
                                unions["arg_type"].append(ndr.NdrByteConformantArray())
                            elif "int[]" in struct_name or "uint[]" in struct_name:
                                unions["arg_type"].append(ndr.NdrLongConformantArray())
                            elif "short[]" in struct_name or "ushort[]" in struct_name:
                                unions["arg_type"].append(ndr.NdrShortConformantArray())
                            elif "long[]" in struct_name or "ulong[]" in struct_name:
                                unions["arg_type"].append(ndr.NdrHyperConformantArray())
                            else :
                                print("[!]Got An Unknown Type {0} {1}, Use Byte Instead".format(self.unions[union_index][1][2][2][t][2][0][0],struct_name))
                                unions["arg_type"].append(ndr.NdrByte())
                        elif isinstance(arg_name, str) == False: 
                            
                            print("[!]Got An Unknown Type {0} {1}, Use Byte[] Instead".format(self.structs[struct_index][1][1][2][t][0],struct_name))
                            unions["arg_type"].append(ndr.NdrByteConformantArray())
                            break
                else :
                    print("[!]Got An Unknown Type {0} {1}, Use Byte Instead".format(self.unions[union_index][1][2][2][t][2][0][0],struct_name))
                    unions["arg_type"].append(ndr.NdrByte())
        return unions
    
            
            

#Write_  --- string ---  WriteConformantVaryingString        byte[]/sbyte[]/char[] --- WriteConformantArray   struct   union
# union 选择
# WriteTerminatedString --- NdrWString
# WriteReferent  --- NdrUniquePTR --- 在数据前面加\x02\x02\x02\x02
# WriteInt32   --- NdrLong
# WriteSByte   --- NdrByte
# WriteInt64   --- NdrHyper
# WriteEnum16   --- NdrShort
# WriteContextHandle   --- NdrContextHandle    client.bind后返回的iid
# WriteGuid   --- NdrGuid
#  byte[]/sbyte[]/char[]  --- WriteConformantArray --- NdrConformantArray
#  int[]   --- WriteFixedPrimitiveArray    --- NdrFixedArray


uuid_black_list = [
    "5a0ce74d-f9cf-4dea-a4c1-2d5fe4c89d51",
    "2e7d4935-59d2-4312-a2c8-41900aa5495f",
    "850cee52-3038-4277-b9b4-e05db8b2c35c",
    "2eb08e3e-639f-4fba-97b1-14f878961076",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188",
    "4c9dbf19-d39e-4bb9-90ee-8f7179b20283",#存在提权漏洞
    "56244243-3ed3-4013-b3e7-0fc809e35fba",
    "5c9a4cd7-ba75-45d2-9898-1773b3d1e5f1",
    "a1d4eae7-39f8-4bca-8e72-832767f5082a",
    "a4b8d482-80ce-40d6-934d-b22a01a44fe7",
    "b18fbab6-56f8-4702-84e0-41053293a869",#main4卡住
    #"ae2dc901-312d-41df-8b79-e835e63db874"#存在提权
]




if __name__ == "__main__":
    #a = Interface("201ef99a-7fa0-444c-9399-19ba84f12a1a",(1,0),"RAiLaunchAdminProcess")
    #a.connect()
    
    #result = a.call(0,parameter_pack)
    #stream = ndr.NdrStream(result)
    #s = "D:/项目/com_bug_hunt/WindowsRpcClients-0ccb35c9684cbe54f4eb6673fdfaf06393c9f7ea/Win10_20H1"
    s = "D:/项目/com_bug_hunt/test"
    for dirpath, dirnames, filenames in os.walk(s):
        for filename in filenames:
            if (filename.split(".")[-1]) =="cs":
                try:
                    b = analyze(os.path.join(dirpath, filename))
                    b.get_construct()
                    c = idl(b.construct)
                    d = c.run()
                    print(c.uuid)
                    if c.uuid not in uuid_black_list:

                        a = Interface(c.uuid,c.version)
                        a.connect()
                        e = []
                        for i in range(len(d["type"])):
                            e.append(a.generate_arg(d["type"][i]))
                        for i in range(len(d["name"])):
                            try:
                                result = a.call(i,e[i])
                                stream = ndr.NdrStream(result)
                                print("Successfully request in {}".format(d["name"][i]))

                            except Exception as f:
                                print("[!]Exception while requesting method {} :>>".format(d["name"][i]),f)
                except Exception as f:
                    print("[!]Exception  ",f)

