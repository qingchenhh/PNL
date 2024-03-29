import re
import os
import argparse
from colorama import init,Fore,Style

def print_banner():
    str = '''
     ____  _   _ _ 
    |  _ \| \ | | |
    | |_) |  \| | |
    |  __/| |\  | |___ 
    |_|   |_| \_|_____|
    '''
    print(Style.BRIGHT + Fore.MAGENTA+str)
    print('PNL Nginx攻击日志过滤工具 v0.4 --by 清晨\n')

def args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file',dest="filename",required=True, type=str,help="Please input the file name of nginx (e.g. -f \"/var/log/access.log\")")
    parser.add_argument('-e', '--excode', dest="excode", default='', type=str,
                        help="Specifies the excluded HTTP status code. (e.g. -e 500)")
    return parser.parse_args()

def removecode(filename,status_code,tmpname):
    res_path = os.path.dirname(os.path.abspath(filename)) + os.sep + tmpname
    re_str = '" {} \d+ "'.format(status_code)
    with open(filename,mode='r',encoding='utf8') as f:
        with open(res_path,mode='w',encoding='utf8') as res_f:
            for i in f:
                if not re.search(re_str,i):
                    res_f.writelines(i)
    return res_path

def re_normal_request(filename):
    res_path = os.path.dirname(os.path.abspath(filename)) + os.sep + "reslog.log"

    with open(filename, mode='r', encoding='utf8') as f:
        with open(res_path, mode='w', encoding='utf8') as res_f:
            for i in f:
                if re.search(' "GET ', i):
                    if not (re.search('\?.+=',i) or re.search('\?\w+:.+',i)):
                        continue
                    rest = (re.search('\.rar HTTP',i,flags=re.IGNORECASE) or re.search('\.zip HTTP',i,flags=re.IGNORECASE) or re.search('\.7z HTTP',i,flags=re.IGNORECASE) or re.search('\.gz HTTP',i,flags=re.IGNORECASE) or re.search('\.back HTTP',i,flags=re.IGNORECASE) or re.search('\.bck HTTP',i,flags=re.IGNORECASE) or re.search('\.tar HTTP',i,flags=re.IGNORECASE) or re.search('\.bz HTTP',i,flags=re.IGNORECASE) or re.search('\.bz2 HTTP',i,flags=re.IGNORECASE) or re.search('\.rpm HTTP',i,flags=re.IGNORECASE) or re.search('\.tgz HTTP',i,flags=re.IGNORECASE) or re.search('\.ded HTTP',i,flags=re.IGNORECASE) or re.search('\.jar HTTP',i,flags=re.IGNORECASE) or re.search('\.war HTTP',i,flags=re.IGNORECASE) or re.search('\.arc HTTP',i,flags=re.IGNORECASE) or re.search('\.z HTTP',i,flags=re.IGNORECASE) or re.search('/\.git/.+ HTTP',i,flags=re.IGNORECASE))
                    if rest and (re.search('" 200 \d+ "',i) or re.search('" 302 \d+ "',i)):
                        continue
                res_f.writelines(i)
    return res_path

def ext_feat(filename,ext_str):
    flags = False
    with open(filename, mode='r', encoding='utf8') as f:
        for i in f:
            if re.search(ext_str, i ,flags=re.IGNORECASE):
                print(Style.BRIGHT + Fore.GREEN+'[+]'+i)
                flags = True
    return flags

def excode():
    if args.excode != '':
        if re.findall('^[2-5][0-9][0-9]$',args.excode):
            # print(args.excode)
            print(Style.BRIGHT + Fore.YELLOW + '[*] 正在去除HTTP响应状态码为' + args.excode + '的日志。\n')
            exlog_path = removecode(args.filename,args.excode,'exlog')
            return exlog_path
        else:
            print(Style.BRIGHT + Fore.RED+'[-] 指定的状态码错误！\n')
            return False
    else:
        return False

def handle_log():
    # 去掉指定的http响应状态码
    excode_path = excode()
    if excode_path == False:
        excode_path = args.filename
    # 去掉500
    print(Style.BRIGHT + Fore.YELLOW+'[*] 正在去除HTTP响应状态码为500的日志。\n')
    re500_path = removecode(excode_path, '500', 'tmp_log_500')
    # 去掉400
    print(Style.BRIGHT + Fore.YELLOW+'[*] 正在去除HTTP响应状态码为400的日志。\n')
    re400_path = removecode(re500_path, '400', 'tmp_log_400')
    # 去掉405
    print(Style.BRIGHT + Fore.YELLOW + '[*] 正在去除HTTP响应状态码为405的日志。\n')
    re405_path = removecode(re400_path, '405', 'tmp_log_405')
    # 去掉404
    print(Style.BRIGHT + Fore.YELLOW+'[*] 正在去除HTTP响应状态码为404的日志。\n')
    re404_path = removecode(re405_path, '404', 'tmp_log_404')
    # 去掉403
    print(Style.BRIGHT + Fore.YELLOW+'[*] 正在去除HTTP响应状态码为403的日志。\n')
    re403_path = removecode(re404_path, '403', 'tmp_log_403')
    # print(re403_path)
    print(Style.BRIGHT + Fore.YELLOW+'[*] 正在去除正常访问日志。\n')
    # 去掉正常访问日志
    re_normal_data = re_normal_request(re403_path)
    # 删除处理过程产生的临时文件
    os.remove(re500_path)
    os.remove(re400_path)
    os.remove(re405_path)
    os.remove(re404_path)
    os.remove(re403_path)
    if os.path.isfile(excode_path) and (excode_path != args.filename):
        os.remove(excode_path)
    # print(re_normal_data)
    print(Style.BRIGHT + Fore.GREEN+'[+] 文件处理完毕,处理完成的文件为：', re_normal_data+'\n')
    return re_normal_data

if __name__ == '__main__':
    # 初始化，设置终端颜色自动恢复。
    init(autoreset=True)
    # 接受参数
    args = args()
    # 打印banner
    print_banner()
    # 判断文件是否存在
    if not os.path.isfile(args.filename):
        print(Style.BRIGHT + Fore.RED+"[-] 指定的日志文件路径错误，请输入正确的日志文件路径。\n")
        exit()
    # 处理日志
    ret_log = handle_log()


