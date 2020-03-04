#!/usr/bin/python
import csv
import re
import os

src_file = input('Enter CSV filename from FinCERT:')
while not os.path.exists(src_file):
    print('File not found!')
    src_file = input('Enter CSV filename from FinCERT:')
dst_file = input('Enter CSV filename for Check Point:')
observ_num = 0
malware_list = []
dict_for_comments = {}

regex_md5 = re.compile(r'^[a-f0-9]{32}$', re.UNICODE)
regex_ip = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', re.UNICODE)
regex_url = re.compile(r'http', re.UNICODE)
regex_domain = re.compile(r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$', re.UNICODE)
regex_mail = re.compile(r'^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})*$', re.UNICODE)

with open(src_file) as csv_original_file: 
     csv_reader = csv.DictReader(csv_original_file, delimiter=',')
     for row in csv_reader:
        if row['MD5']:
            malware_list.append(row['MD5'].lower())
            dict_for_comments[row['MD5'].lower()] = ','.join([row['ReportDate'],row['MalwareClass'],row['Filename']])
        if row['MalwareDownloadResources']:
            if ';' in row['MalwareDownloadResources']:
                malware_list.extend(row['MalwareDownloadResources'].split(';'))
                for item in row['MalwareDownloadResources'].split(';'):
                    dict_for_comments[item] = ','.join([row['ReportDate'],row['MalwareClass'],row['Filename']])
            else:
                malware_list.append(row['MalwareDownloadResources'])
                dict_for_comments[row['MalwareDownloadResources']] = ','.join([row['ReportDate'],row['MalwareClass'],row['Filename']])
        if row['MalwareConnectionResources']:
            if ';' in row['MalwareConnectionResources']:
                malware_list.extend(row['MalwareConnectionResources'].split(';'))
                for item in row['MalwareConnectionResources'].split(';'):
                    dict_for_comments[item] = ','.join([row['ReportDate'],row['MalwareClass'],row['Filename']])
            else:
                malware_list.append(row['MalwareConnectionResources'])
                dict_for_comments[row['MalwareConnectionResources']] = ','.join([row['ReportDate'],row['MalwareClass'],row['Filename']])
        if row['EmailResources']:
            if ';' in row['EmailResources']:
                malware_list.extend(row['EmailResources'].split(';'))
                for item in row['EmailResources'].split(';'):
                    dict_for_comments[item] = ','.join([row['ReportDate'],row['MalwareClass'],row['Filename']])
            else:
                malware_list.append(row['EmailResources'])
                dict_for_comments[row['EmailResources']] = ','.join([row['ReportDate'],row['MalwareClass'],row['Filename']])

malware_set = set(malware_list)

with open(dst_file, 'w') as csv_cp_file:
    csv_writer = csv.writer(csv_cp_file, dialect='excel')
    for item in malware_set:
        observ_num += 1
        if regex_md5.search(item):
            cp_list_md5 = ['observ'+str(observ_num), item, 'MD5', 'high', 'high', 'AV', dict_for_comments[item]]
            csv_writer.writerow(cp_list_md5)
        elif regex_ip.search(item):
            cp_list_ip = ['observ'+str(observ_num), item, 'IP', 'high', 'high', 'AV', dict_for_comments[item]]
            csv_writer.writerow(cp_list_ip)
        elif regex_url.search(item):
            cp_list_url = ['observ'+str(observ_num), item, 'URL', 'high', 'high', 'AV', dict_for_comments[item]]
            csv_writer.writerow(cp_list_url)
        elif regex_domain.search(item):
            cp_list_domain = ['observ'+str(observ_num), item, 'Domain', 'high', 'high', 'AV', dict_for_comments[item]]
            csv_writer.writerow(cp_list_domain)
        elif regex_mail.search(item):
            cp_list_mail = ['observ'+str(observ_num), item, 'Mail-from', 'high', 'high', 'AV', dict_for_comments[item]]
            csv_writer.writerow(cp_list_mail)
        else:
            print('Can\'t parse:', item)
    
    print('File {} was successfully created!'.format(dst_file))


