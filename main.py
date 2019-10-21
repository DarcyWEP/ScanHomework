# coding=utf-8

import threading
import tkinter
from tkinter import *
from tkinter import filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.ttk import Treeview
from scapy.layers.inet6 import *
from scapy.layers.l2 import *

# 用来终止抓包线程的线程事件
stop_scanning = threading.Event()
# 用来给抓到扥数据包编号
packet_id = 1
# 用来存放抓到的数据包
packet_list = []
packet_list_test = []
# 暂停抓包的标志位
pause_flag = False
# 保存文件标志位
save_flag = False
# 停止抓包标志位
stop_flag = False
# 监控、嗅探、端口扫描标志位(0：无     1：监控、嗅探     2：端口扫描)
is_scan_port = 0


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    my_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return my_time

def clear_show_list():
    items = packet_list_tree.get_children()
    for item in items:
        packet_list_tree.delete(item)
    packet_list_tree.clipboard_clear()  # 清空已经抓到的数据包列表

# -------------------------------------以下是嗅探和监控的函数------------------------------


def save_scan():
    # 默认打开位置initialdir,默认命名initialfile='.txt'
    filename = tkinter.filedialog.asksaveasfilename(
        title='保存文件', filetypes=[('所有文件', '.*')], initialfile='.txt')
    if filename.find('.txt') == -1:
        filename = filename + '.txt'
    fp = open(filename, 'w')
    logs = open('scan.log', 'a')
    log = "No.\t\tTime\t\tSourceMac\t\tDestinationMac\t\tSourceIp" + \
          "\t\t\tDestinationIp\t\t\tProtocol\tSPort\tDPort\n"
    logs.write(log)
    for item in packet_list_test:
        id1 = item['id']
        time1 = item['time']
        src_mac = item['src_mac']
        dst_mac = item['dst_mac']
        src_ip = item['src_ip']
        dst_ip = item['dst_ip']
        proto = item['proto']
        sport = item['sport']
        dport = item['dport']
        if str(proto) == "IPv6":
            if (len(str(src_ip)) >= 24):
                if (len(str(dst_ip)) >= 24):
                    log = str(id1) + "\t" + str(time1) + "\t" + str(src_mac) + "\t" \
                          + str(dst_mac) + "\t" + str(src_ip) + "\t" + str(dst_ip) + "\t" + \
                          str(proto) + "\t\t" + str(sport) + "\t" + str(dport) + "\n"
                else:
                    log = str(id1) + "\t" + str(time1) + "\t" + str(src_mac) + "\t" \
                          + str(dst_mac) + "\t" + str(src_ip) + "\t" + str(dst_ip) + "\t\t" + \
                          str(proto) + "\t\t" + str(sport) + "\t" + str(dport) + "\n"
            else:
                if (len(str(dst_ip)) >= 24):
                    log = str(id1) + "\t" + str(time1) + "\t" + str(src_mac) + "\t" \
                          + str(dst_mac) + "\t" + str(src_ip) + "\t\t" + str(dst_ip) + "\t" + \
                          str(proto) + "\t\t" + str(sport) + "\t" + str(dport) + "\n"
                else:
                    log = str(id1) + "\t" + str(time1) + "\t" + str(src_mac) + "\t" \
                          + str(dst_mac) + "\t" + str(src_ip) + "\t\t" + str(dst_ip) + "\t\t" + \
                          str(proto) + "\t\t" + str(sport) + "\t" + str(dport) + "\n"
        else:
            log = str(id1) + "\t" + str(time1) + "\t" + str(src_mac) + "\t" \
                  + str(dst_mac) + "\t" + str(src_ip) + "\t\t\t" + str(dst_ip) + "\t\t\t" + \
                  str(proto) + "\t\t" + str(sport) + "\t" + str(dport) + "\n"
        logs.write(log)
        fp.write(str(item) + "\n")
    logs.write("\n本次共抓到{sum}个数据包\n\n".format(sum=id1))
    fp.close()
    logs.close()


def get_filter():
    global btn1, btn2, btn3, btn4, btn5
    IP_SRC = fitler_IP_SRC.get()
    flag = flag2 = flag3 = False
    if IP_SRC == "":
        filters = ""
    else:
        filters = '(ip src ' + IP_SRC + ')'
        flag = True
    if btn1.get() == 1:
        if flag:
            filters = filters + ' and (ip'
            flag3 = True
        else:
            filters = filters + 'ip'
            flag = True
            flag2 = True
    if btn2.get() == 1:
        if flag:
            if flag2:
                filters = filters + ' or icmp'
            else:
                filters = filters + ' and (icmp'
                flag3 = True
                flag2 = True
        else:
            if flag2:
                filters = filters + ' or icmp'
            else:
                filters = filters + 'icmp'
                flag2 = True
            flag = True
    if btn3.get() == 1:
        if flag:
            if flag2:
                filters = filters + ' or tcp'
            else:
                filters = filters + ' and (tcp'
                flag3 = True
                flag2 = True
        else:
            if flag2:
                filters = filters + ' or tcp'
            else:
                filters = filters + 'tcp'
                flag2 = True
            flag = True
    if btn4.get() == 1:
        if flag:
            if flag2:
                filters = filters + ' or udp'
            else:
                filters = filters + ' and (udp'
                flag3 = True
                flag2 = True
        else:
            if flag2:
                filters = filters + ' or udp'
            else:
                filters = filters + 'udp'
                flag2 = True
            flag = True
    if btn5.get() == 1:
        if flag:
            if flag2:
                filters = filters + ' or arp'
            else:
                filters = filters + ' and arp'
        else:
            if flag2:
                filters = filters + ' or arp'
            else:
                filters = filters + 'arp'
    if flag3:
        filters += ')'
    return filters


def start_capture():
    filters = get_filter()
    print("抓包条件：" + filters)

    stop_scanning.clear()

    global packet_list, packet_list_test
    packet_list.clear(), packet_list_test.clear()  # 清空列表

    sniff(prn=(lambda x: process_packet(x)),  # 抓取数据包并将抓到的包存在列表中
          filter=filters, stop_filter=(lambda x: stop_scanning.is_set()))


def process_packet(packet):
    """处理抓到的数据包"""
    global pause_flag, packet_list, packet_list_test
    if pause_flag is False:
        packet_list.append(packet)  # 将抓到的包存在列表中
        packet_time = timestamp2time(packet.time)  # 抓包的时间
        is_ip = is_tcp = is_udp = False

        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        type = packet[Ether].type
        types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6'}
        if type in types:
           proto = types[type]
        else:
             proto = 'LOOP'  # 协议
        # IPv4
        if proto == 'IPv4':
            is_ip = True
            # 建立协议查询字典
            protos = {1: 'ICMP', 4: 'IP', 6: 'TCP', 17: 'UDP', 41: 'IPv6'}
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            if proto in protos:
                proto = protos[proto]
        # IPv6
        if proto == 'IPv6':
            is_ip = True
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        # ARP
        if proto == 'ARP':
            is_ip = True
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst

        # tcp
        if TCP in packet:
            is_tcp = True
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif UDP in packet:
            is_udp = True
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        if is_ip is False:
            src_ip = ""
            dst_ip = ""
        if is_udp is False and is_tcp is False:
            sport = ""
            dport = ""

        global packet_id  # 数据包的编号
        packet_test = {'id': packet_id, 'time': packet_time, 'src_mac': src_mac,
                       'dst_mac': dst_mac, 'src_ip': src_ip, 'dst_ip': dst_ip,
                       'proto': proto, 'sport': sport, 'dport': dport}
        packet_list_test.append(packet_test)
        packet_list_tree.insert("", 'end', packet_id, text=packet_id,
                            values=(packet_id, packet_time, src_mac, dst_mac,
                                    src_ip, dst_ip, proto, sport, dport))
        packet_list_tree.update_idletasks()  # 更新列表，不需要修改
        packet_id = packet_id + 1


# -------------------------------------以下是端口扫描函数------------------------------


def tcp_connect(ip, port):
    """模拟TCP连接"""
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(0.1)  # 设置连接超时
    try:
        result = tcp_sock.connect_ex((ip, int(port)))
        if result == 0:
            global packet_id
            scan_time = timestamp2time(time.time())
            packet_list_tree.insert("", 'end', packet_id, text=packet_id,
                                    values=("", packet_id, scan_time, ip, port, "up", ""))
            packet_list_tree.update_idletasks()  # 更新列表，不需要修改
            packet_id += 1
        tcp_sock.close()
    except socket.error as e:
        tkinter.messagebox.showinfo("错误！", e)


def start_scan_port():
    scanning_button['state'] = pause_button['state'] = stop_button['state'] = save_button['state'] = 'disabled'

    scan_port_button['state'] = start_button['state'] = quit_button['state'] = fitler_IP_SRC['state'] = 'disable'

    filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = \
        filter_button5['state'] = 'disable'
    """扫描端口"""
    print("[*]开始扫描目标端口")
    ip = fitler_IP_SRC.get()
    if ip == "":
        tkinter.messagebox.showinfo("错误", "IP输入有误！")
        save_button['state'] = pause_button['state'] = stop_button['state'] = 'disabled'

        scanning_button['state'] = start_button['state'] = quit_button['state'] \
            = fitler_IP_SRC['state'] = 'normal'

        filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = \
            filter_button5['state'] = 'disable'
        return
    start = time.time()
    for port in range(1, 1024):
        tcp_connect(ip, port)
    end = time.time()
    info = "总耗时%s" % time.strftime("%H:%M:%S", time.gmtime(end-start))
    tkinter.messagebox.showinfo("扫描耗时", info)

    save_button['state'] = pause_button['state'] = stop_button['state'] =  'disabled'

    scanning_button['state'] = start_button['state'] = quit_button['state'] \
        = fitler_IP_SRC['state'] = 'normal'

    filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = \
        filter_button5['state'] = 'disable'


# -------------------------------------以下是相关的按钮点击函数------------------------------


def start_btn():
    # 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据

    filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = filter_button5['state'] = 'disabled'
    start_button['state'] = save_button['state'] = 'disabled'
    pause_button['state'] = stop_button['state'] = 'normal'

    global pause_flag, stop_flag, save_flag
    if stop_flag is True and save_flag is False:    # 已经停止，重新开始抓包但没进行保存操作
        result = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
        if result is False:
            pass
        elif result is True:
            if is_scan_port == 1:
                save_scan()
            else:
                pass
        else:   # 取消抓包操作
            stop_flag = False
            return
    stop_flag = False
    if pause_flag is False:
        clear_show_list()    # 清空已经抓到的数据包列表

        global packet_id
        packet_id = 1   # 包编号重新计数
        if is_scan_port == 1:
            t = threading.Thread(target=start_capture)
            t.setDaemon(True)
            t.start()  # 开启新线程进行抓包
        elif is_scan_port == 2:
            t = threading.Thread(target=start_scan_port)
            t.setDaemon(True)
            t.start()  # 开启新线程进行抓包
        save_flag = False
    else:
        pause_flag = False


def save_captured_data_to_file():
    """将抓到的数据包保存"""
    global save_flag
    save_flag = True
    save_scan()


def pause_capture():
    """暂停按钮单击响应函数,抓包处理函数停止运行，仍然在抓包"""
    filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = 'normal'
    filter_button5['state'] = start_button['state'] = 'normal'
    pause_button['state'] = 'disable'
    global pause_flag
    pause_flag = True


def stop_capture():
    """停止按钮单击响应函数,终止线程，停止抓包"""
    stop_scanning.set()     # 终止线程，停止抓包

    start_button['state'] = save_button['state'] = 'normal'
    pause_button['state'] = stop_button['state'] = 'disable'
    filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = filter_button5['state'] = 'normal'

    global pause_flag, stop_flag
    pause_flag = False
    stop_flag = True


def quit_program():
    """退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据"""
    stop_scanning.set()     # 终止线程，停止抓包
    if stop_flag is True or pause_flag is True:     # 已经暂停，或停止，需要提示保存在退出
        if save_flag is False:      # 没进行保存操作
            result = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
            if result is True:
                save_scan()
    tk12.destroy()


def scanning():
    stop_scanning.set()


    scanning_button['state'] = pause_button['state'] = stop_button['state'] = save_button['state'] = 'disabled'

    scan_port_button['state'] = start_button['state'] = quit_button['state'] = fitler_IP_SRC['state'] = 'normal'

    filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = \
    filter_button5['state'] = 'normal'
    filter_label['text'] = "IP_Src:"

    # 数据包列表区列标题
    packet_list_tree["columns"] = ("No.", "Time", "SourceMac",
                                   "DestinationMac", "SourceIp",
                                   "DestinationIp", "Protocol",
                                   "SPort", "DPort")
    packet_list_column_width = [50, 140, 125, 125, 180, 180, 65, 65, 65]
    packet_list_tree['show'] = 'headings'
    for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
        packet_list_tree.column(column_name, width=column_width, anchor='w')
        packet_list_tree.heading(column_name, text=column_name)
    global is_scan_port
    is_scan_port = 1

    clear_show_list()  # 清空已经抓到的数据包列表


def scan_port():
    stop_scanning.set()
    clear_show_list()  # 清空已经抓到的数据包列表

    scan_port_button['state'] = pause_button['state'] = stop_button['state'] = save_button['state'] = 'disabled'

    scanning_button['state'] = start_button['state'] = quit_button['state'] = fitler_IP_SRC['state'] = 'normal'

    filter_button1['state'] = filter_button2['state'] = filter_button3['state'] = filter_button4['state'] = \
    filter_button5['state'] = 'disable'

    filter_label['text'] = "ScanIP:"

    # 数据包列表区列标题
    packet_list_tree["columns"] = ("", "No.", "Time", "ScanIP", "Port", "State", "")
    packet_list_column_width = [275, 50, 140, 125, 65, 65, 275]
    packet_list_tree['show'] = 'headings'
    for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
        packet_list_tree.column(column_name, width=column_width, anchor='w')
        packet_list_tree.heading(column_name, text=column_name)

    global is_scan_port
    is_scan_port = 2

    clear_show_list()  # 清空已经抓到的数据包列表


# ---------------------以下代码绘制GUI界面---------------------
# tk是总页面，tk12是网络监控和嗅探，tk3是端口扫描
tk12 = tkinter.Tk()

tk12.title("网络监测软件")

# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk12, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 选择嗅探或者端口扫描

select_bar = Frame(tk12)
scanning_button = Button(select_bar, width=16, text="网络监控与嗅探", state='normal', command=scanning)
scan_port_button = Button(select_bar, width=16, text="网络端口扫描", state='normal', command=scan_port)

scanning_button.pack(padx=2, pady=32)
scan_port_button.pack(side=TOP, after=scanning_button, padx=2, pady=32)

select_bar.pack(side=LEFT, fill=X)

# 顶部的按钮及过滤器区
toolbar = Frame(tk12)
start_button = Button(toolbar, width=10, text="开始", command=start_btn, state='disabled')
pause_button = Button(toolbar, width=10, text="暂停", command=pause_capture, state='disabled')
stop_button = Button(toolbar, width=10, text="停止", command=stop_capture, state='disabled')
save_button = Button(toolbar, width=10, text="保存", command=save_captured_data_to_file, state='disabled')
quit_button = Button(toolbar, width=10, text="退出", command=quit_program, state='disabled')

# 复选框状态
btn1 = IntVar(toolbar)
btn2 = IntVar(toolbar)
btn3 = IntVar(toolbar)
btn4 = IntVar(toolbar)
btn5 = IntVar(toolbar)
filter_button1 = Checkbutton(toolbar, text="IP", variable=btn1, width=3, state='disabled')
filter_button2 = Checkbutton(toolbar, text="ICMP", variable=btn2, width=3, state='disabled')
filter_button3 = Checkbutton(toolbar, text="TCP", variable=btn3, width=3, state='disabled')
filter_button4 = Checkbutton(toolbar, text="UDP", variable=btn4, width=3, state='disabled')
filter_button5 = Checkbutton(toolbar, text="ARP", variable=btn5, width=3, state='disabled')

filter_label = Label(toolbar, width=6, text="IPAddr:", state='disabled')
fitler_IP_SRC = Entry(toolbar, width=20, state='disabled')
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=8, pady=8)
stop_button.pack(side=LEFT, after=pause_button, padx=8, pady=8)
save_button.pack(side=LEFT, after=stop_button, padx=8, pady=8)
quit_button.pack(side=LEFT, after=save_button, padx=8, pady=8)
filter_button1.pack(side=LEFT, after=quit_button, padx=8, pady=8)
filter_button2.pack(side=LEFT, after=filter_button1, padx=8, pady=8)
filter_button3.pack(side=LEFT, after=filter_button2, padx=8, pady=8)
filter_button4.pack(side=LEFT, after=filter_button3, padx=8, pady=8)
filter_button5.pack(side=LEFT, after=filter_button4, padx=8, pady=8)

filter_label.pack(side=LEFT, after=filter_button5, padx=0, pady=8)
fitler_IP_SRC.pack(side=LEFT, after=filter_label, padx=8, pady=8)
toolbar.pack(side=TOP, fill=X)



# 数据包列表区
packet_list_frame = Frame(tk12)
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')

# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("网络监测软件")
packet_list_column_width = [995]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)

packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

main_panedwindow.pack(fill=BOTH, expand=1)

tk12.mainloop()
