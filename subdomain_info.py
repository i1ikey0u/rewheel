#!/usr/bin/env python
#coding:utf-8
#environ: python3 64bit
#code by shuichon

'''
V1.0，
'''

import argparse, sys, re, os
from bs4 import BeautifulSoup
from urllib import request, parse
import json


# ip138接口查询IP
def get_ips(domain, *path):
	url = "http://site.ip138.com/" + str(domain) + '/'
	print(url)
	page = request.urlopen(url).read().decode('utf-8')
	# print(page)
	soup = BeautifulSoup(page, "html.parser")
	# div = soup.find_all('div', class_="panel")
	div = soup.find('div', class_="panel")
	print("发现%i个IP地址：" % len(div))
	hisaddr = div.find_all('a', target="_blank")
	for ha in hisaddr:
		print(ha.string)

# ip138接口 查询子域名
def subd_fm_ip138(target):
	url = "http://site.ip138.com/" + str(target) + '/domain.htm'
	print(url)
	page = request.urlopen(url).read().decode('utf-8')
	# print(page)
	soup = BeautifulSoup(page, "html.parser")
	# div = soup.find_all('div', class_="panel")
	div = soup.find('div', class_="panel")
	# print(div)
	ps = div.find_all('a', target="_blank")
	print("存在%i个子域名" % len(ps))
	for sd in ps:
		print(sd.string)


# 站长之家接口
def subd_fm_chinaz(target):
	url = "http://tool.chinaz.com/subdomain?domain=" + str(target)
	page = request.urlopen(url).read().decode('utf-8')
	soup = BeautifulSoup(page, "html.parser")
	ul = soup.find("ul", class_="ResultListWrap")
	us = ul.find_all("a")
	for a in us:
		print(a.string)


# virustotal接口
def subd_fm_vt(target):
	url = "https://www.virustotal.com/ui/domains/" + str(target) + "/subdomains"
	url2 = "https://www.virustotal.com/ui/domains/" + str(target) + "/subdomains?cursor=STEwCi4%3D"
	print(url)
	page = request.urlopen(url).read().decode('utf-8')
	# print(page)
	pg = json.loads(page, encoding='utf-8')
	# print(pg)
	for i in range(len(pg["data"])):
		print("打印前10个子域名：")
		print(pg["data"][i]['id'])
	page2 = request.urlopen(url2).read().decode('utf-8')
	pg2 = json.loads(page2, encoding='utf-8')
	for i in range(len(pg["data"])):
		print("打印剩余子域名：")
		print(pg2["data"][i]['id'])


#TODO 谷歌透明度查询 需要翻墙，暂时没做。
def subd_fm_gtr(target):
	url = "https://transparencyreport.google.com/"


# threatcrowd威胁情报接口,
#TODO 需要解决CloudFlare DDOS防护
def subd_fm_tc(target):
	headers = {
		'User-Agent': r'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
		              r'Chrome/44.0.2454.85 Safari/537.36 115Browser/6.0.3',
		'Connection': 'keep-alive',
		# "Accept-Encoding": "gzip, deflate, br",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
	}
	url = "https://disqus.com/api/3.0/discovery/listTopPost.json?thread=6100104160&thread=6101359458&thread=6176664485&thread=6178793347&thread=6198134280&thread=6203325891&thread=6273540066&thread=6427423066&api_key=E8Uh5l5fHZ6gD8U3KycjAIAk46f68Zw7C6eW8WSjZvCLXebZ7p0r1yrYDrLilk2F"
	url2 = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + str(target)
	# req = request.Request(url2, headers=headers)
	# respn = request.urlopen(req)
	# page = respn.read().decode("utf-8")
	page = request.urlopen(url2).read().decode("utf-8")
	print(page)
	pg = json.loads(page, encoding='utf-8')
	print(pg["subdomains"])


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument("-ip", help="查询域名解析IP历史")
	parser.add_argument("-subd", help="查询子域名")
	args = parser.parse_args()
	# print(args)
	if args.ip:
		get_ips(args.ip)
	elif args.subd:
		subd_fm_ip138(args.subd)
		subd_fm_chinaz(args.subd)
		subd_fm_vt(args.subd)
		# subd_fm_tc(args.subd)

