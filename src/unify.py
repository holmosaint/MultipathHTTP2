import argparse

range_file_path_list = ['range_CDN0.txt', 'range_CDN1.txt', 'range_CDN2.txt']

class sub_file:

    def __init__(self, CDN_id, st, st_time_s, st_time_us, en_time_s, en_time_us):
        self.CDN_id = CDN_id
        self.st = st
        self.en = -1
        self.file_size = -1
        self.st_time_s = st_time_s
        self.st_time_us = st_time_us
        self.en_time_s = en_time_s
        self.en_time_us = en_time_us

    def print_info(self):
        print("Start point: {}, End point: {}, File size: {}".format(self.st, self.en, self.file_size))
        print("CDN ID: {}".format(self.CDN_id))
        print("Start time: {}s {}us".format(self.st_time_s, self.st_time_us))
        print("End time: {}s {}us".format(self.en_time_s, self.en_time_us))
        print()

def sub_file_cmp(sf1, sf2):
    return sf1.st - sf2.st

def sub_file_key(sf):
    return sf.st

CDN_NUM = 3

sub_file_list = list()

for CDN_id in range(CDN_NUM):
    with open(range_file_path_list[CDN_id], 'r') as range_file:
        for line in range_file.readlines():
            line = line.split('-')
            st = int(line[0])
            st_line = line[1].split(' ')
            st_time_s = float(st_line[0])
            st_time_us = float(st_line[1])
            en_line = line[2].split(' ')
            en_time_s = float(en_line[0])
            en_time_us = float(en_line[1])

            sf = sub_file(CDN_id, st, st_time_s, st_time_us, en_time_s, en_time_us)
            sub_file_list.append(sf)

sub_file_list.sort(key=sub_file_key)
chunk_size = int(1e4)

with open('unified_file.txt', 'w+') as uni_file:
    for sf in sub_file_list:
        sf.file_size = 0
        with open(str(sf.st) + '.txt', 'r') as f: 
            while(1):
                content = f.read(chunk_size)
                uni_file.write(content)
                L = len(content)
                sf.file_size += L
                if L < chunk_size:
                    break
        sf.en = sf.st + sf.file_size
        sf.print_info()
