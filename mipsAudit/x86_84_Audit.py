from idaapi import *
from idc import *
from prettytable import PrettyTable
import re

# set function_name
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink"
]


format_function_offset_dict = {
    "sprintf":1,
    "sscanf":1,
    "snprintf":2,
    "vprintf":0,
    "printf":0
}


def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    # func_addr = LocByName(func_name)
    func_addr=get_name_ea_simple(func_name)
    if func_addr != BADADDR:
        print printFunc(func_name)
        # print func_name + " Addr : 0x %x" % func_addr
        return func_addr
    return False

def getFunArg(func_addr):
    func_info=get_type(func_addr)
    searchObj=re.search('\((.*)\)', func_info, re.M|re.I)
    arg_list=searchObj.group(1).split(',')   
    if len(arg_list)==1:
        if arg_list[0]=='':
            return 0
    return arg_list

# show arg name
# def auditAddr(call_addr, func_name, arg_num,arg_list):
#     addr = "0x%x" % call_addr
#     ret_list = [func_name, addr]
#     # local buf size
#     local_buf_size = get_func_attr(call_addr , FUNCATTR_FRSIZE)
#     if local_buf_size == BADADDR :
#         local_buf_size = "get fail"
#     else:
#         local_buf_size = "0x%x" % local_buf_size
#     # get arg
#     # for num in xrange(0,arg_num):
#     #     ret_list.append(getArg(call_addr, num))

#     for arg in arg_list:
#         ret_list.append(arg)
#     ret_list.append(local_buf_size)
#     return ret_list

def getArg(call_addr,num,arg_list):
    ret='fail'
    prev_ins_addr=call_addr
    index=0
    while True:
        prev_ins_addr=prev_head(prev_ins_addr)
        ret=get_extra_cmt(prev_ins_addr,0)
        if ret is not None:
            for arg in arg_list:
                if ret in arg:
                    if index==num:     
                        return print_operand(prev_ins_addr, 1)
                    else:
                        index+=1
                        break
    return  ret


def getFormatString(call_addr):
    op_num = 1
    # GetOpType Return value
    #define o_void        0  // No Operand                           ----------
    #define o_reg         1  // General Register (al, ax, es, ds...) reg
    #define o_mem         2  // Direct Memory Reference  (DATA)      addr
    #define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
    #define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    #define o_imm         5  // Immediate Value                      value
    #define o_far         6  // Immediate Far Address  (CODE)        addr
    #define o_near        7  // Immediate Near Address (CODE)        addr
    #define o_idpspec0    8  // IDP specific type
    #define o_idpspec1    9  // IDP specific type
    #define o_idpspec2   10  // IDP specific type
    #define o_idpspec3   11  // IDP specific type
    #define o_idpspec4   12  // IDP specific type
    #define o_idpspec5   13  // IDP specific type
    prev_ins_addr=call_addr
    index=0
    while True:
        prev_ins_addr=prev_head(prev_ins_addr)   
        if GetMnem(prev_ins_addr) =='lea':
           
            if(get_operand_type(prev_ins_addr ,op_num) == 2):
                string_addr=get_operand_value(prev_ins_addr,op_num)
                string_name=GetOpnd(prev_ins_addr,op_num)
                if string_addr == BADADDR:
                    return "get fail"
                else:
                    break
        else:
            index+=1
            if index>20:
                return "get fail"
            continue

    string = str(GetString(string_addr))
    return [string_addr, string,string_name]


def auditFormat(call_addr, func_name, arg_num,arg_list):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = get_func_attr(call_addr , FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in xrange(0,arg_num-1):
        ret_list.append(getArg(call_addr, num,arg_list))  
    # arg_addr = getArgAddr(call_addr, format_function_offset_dict[func_name])
    string_and_addr =  getFormatString(call_addr)

    ret_list.append(string_and_addr[2])
    format_and_value = []
    if string_and_addr == "get fail":
        ret_list.append("get fail")
    else:
        string_addr = "0x%x" % string_and_addr[0]
        string = string_and_addr[1]
        format_string="addr: "+str(string_addr) +"  string: "+string
        ret_list.append(format_string)
        
        # fmt_num = string.count("%")
        # format_and_value.append(fmt_num)
        # mips arg reg is from a0 to a3
        # if fmt_num > 3:
        #     fmt_num = fmt_num - format_function_offset_dict[func_name] - 1
        # for num in xrange(0,fmt_num):
        #     if arg_num + num > 3:
        #         break
        #     format_and_value.append(getArg(call_addr, arg_num + num))
        # ret_list.append(format_and_value)
    # format_string = str(getFormatString(arg_addr)[1])

    # print " format String: " + format_string
  
    ret_list.append(local_buf_size)
    return ret_list

def auditAddr(call_addr, func_name, arg_num,arg_list):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = get_func_attr(call_addr , FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in xrange(0,arg_num):
        ret_list.append(getArg(call_addr, num,arg_list))

    ret_list.append(local_buf_size)
    return ret_list


def audit(func_name):
    func_addr = getFuncAddr(func_name)  

    if func_addr == False:
        return False

    if SegName(func_addr)=='extern':
        func_addr=getFuncAddr("."+func_name)

    if func_addr == False:
        return False

    arg_list=getFunArg(func_addr)
    arg_num=len(arg_list)
    if arg_list==0:
        arg_num=0
    
    if func_name in format_function_offset_dict:
        arg_num = format_function_offset_dict[func_name] + 1

    table_head = ["func_name", "addr"]
    for num in xrange(0,arg_num):
        table_head.append("arg"+str(num+1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)


    # call_addr = RfirstB(func_addr)
    call_addr=get_first_cref_to(func_addr)
    while call_addr != BADADDR:
        SetColor(call_addr, CIC_ITEM, 0x00ff00)

        Mnemonics = GetMnem(call_addr)

        if Mnemonics[0:4] == "call":
            if func_name in format_function_offset_dict:
                info = auditFormat(call_addr, func_name, arg_num,arg_list)
            else:
                info = auditAddr(call_addr, func_name, arg_num,arg_list)
            table.add_row(info)
     

        call_addr = get_next_cref_to(func_addr, call_addr)

        # call_addr = RnextB(func_addr, call_addr)
         
    print table

def x86_64_Audit():
    # the word create with figlet
    start = '''
           _              _             _ _ _   
 _ __ ___ (_)_ __  ___   / \  _   _  __| (_) |_ 
| '_ ` _ \| | '_ \/ __| / _ \| | | |/ _` | | __|
| | | | | | | |_) \__ \/ ___ \ |_| | (_| | | |_ 
|_| |_| |_|_| .__/|___/_/   \_\__,_|\__,_|_|\__|
            |_|                                 
                    code by giantbranch 2018.05
    '''
    print start
    print "Auditing dangerous functions ......"
    for func_name in dangerous_functions:
        audit(func_name)
        
    print "Auditing attention function ......"
    for func_name in attention_function:
        audit(func_name)

    print "Auditing command execution function ......"
    for func_name in command_execution_function:
        audit(func_name)
        
    print "Finished! Enjoy the result ~"       

if __name__ == "__main__":
    x86_64_Audit()