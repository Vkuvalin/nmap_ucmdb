# coding=utf-8
import sys
import subprocess
import threading
import time

start = time.time()
end = None

list_ip = list()
names_files = list()
flag = False
numberOfThreads = None
command = None
location = __file__.replace(__file__.split('\\')[-1], '')


file = open(location + 'configuration_nmap.txt', "r")
count = 1

for line in file:
    if count == 1:
        numberOfThreads = int(line.replace('\n', ''))
    elif count == 2:
        command = line.replace('\n', '')
    else:
        list_ip.append(line.replace('\n', '').strip())
    count += 1

file.close()


def mainFunc():
    def read_list_ip():
        for ip in list_ip:
            yield ip

    ip = read_list_ip()

    def performNmapDiscover(received_ip):
        global flag
        global end
        while not flag:
            try:
                next_ip = next(received_ip)
                tmp_file_name = location + next_ip.replace('.', '') + 'nmap.xml'
                names_files.append(tmp_file_name)
                process = subprocess.Popen(["powershell.exe", "cd 'C:\Program Files (x86)\Nmap\' | {} {} -oX {}".format(command, next_ip, tmp_file_name)], stdout=sys.stdout)
                process.communicate()
            except:
                flag = True

        if flag and end is None:
            end = time.time()
            timetaken = end - start

            fin = open(location + "names_files.txt", "a")
            # fin.write("The program is working out for: {}".format(timetaken) + '\n')
            for name in names_files:
                if name != names_files[-1]:
                    fin.write(name + '\n')
                else:
                    fin.write(name)
            fin.close()

    for i in range(numberOfThreads):
        additional_stream = threading.Thread(target=performNmapDiscover, args=(ip,))
        additional_stream.start()


the_main_stream = threading.Thread(target=mainFunc)
the_main_stream.start()
