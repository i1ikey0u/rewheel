#!/usr/bin/env python
#coding:utf-8
#environ: python3
#code by shuichon

'''
查询一个域名的IP解析记录，并且查询其解析的IP的域名绑定历史
使用点线图展示
'''

'''
V1.0，
'''

import argparse, sys, re, os
from bs4 import BeautifulSoup
from urllib import request, parse
import networkx as nx
import matplotlib.pyplot as plt



hd = {
		'User-Agent': r'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
		              r'Chrome/44.0.2454.85 Safari/537.36 115Browser/6.0.3',
		'Connection': 'keep-alive',
		# "Accept-Encoding": "gzip, deflate, br",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
	}


# 写入文件
def wf(fn, txt):
	f = open(fn, "a+")
	f.writelines(txt)
	f.close()

# OK ip138接口查询域名当前和历史解析IP地址信息
def get_ips_fd(domain):
	car = []
	har = []
	print("当前要查询的域名为："+domain)
	url = "http://site.ip138.com/" + str(domain) + '/'
	page = request.urlopen(url).read().decode('utf-8')
	soup = BeautifulSoup(page, "html.parser")
	div = soup.find('div', class_="panel")
	curaddr = div.find_all('a', target="+_blank")
	hisaddr = div.find_all('a', target='_blank')
	print("要检查的域名共发现 %i 个IP地址：" % (len(hisaddr)+len(curaddr)))
	print('当前解析IP：')
	for ca in curaddr:
		print(ca.string)
		car.append(ca.string)
		print('该IP域名绑定过的域名如下：')
		get_d_fip(ca.string)
	print('历史解析IP：')
	for ha in hisaddr:
		print(ha.string)
		har.append(ha.string)
		print('该IP绑定过的域名如下：')
		get_d_fip(ha.string)
	return list(car+har)
	print('Done!')


# 查询IP当前及历史绑定的域名
def get_d_fip(ip):
	dm = []
	url = "http://site.ip138.com/" + str(ip) + '/'
	req = request.urlopen(url)
	if req.code != 200:
		return (req.code)
	page = req.read().decode('utf-8')
	soup = BeautifulSoup(page, "html.parser")
	# 部分情况下，div的class会变化名字
	div = soup.find('div', class_=['result result2', 'result result3'])
	dms = div.find_all('a', target="_blank")
	if len(dms) == 0:
		dm.append('暂无绑定域名')
	else:
		for d in dms:
			dm.append(d.string)
	print(dm)
	return dm


# 数据分析展示
def rst_show(d):
	G = nx.Graph()
	# 创建有向图
	DG = nx.DiGraph()
	iplist = get_ips_fd(d)
	for i in iplist:
		G.add_edge(d, i)
		DG.add_edge(d, i)
		dlit = get_d_fip(i)[1:]
		for dm in dlit:
			G.add_edge(i, dm)
			DG.add_edge(i, dm)
	# nx.draw(G, with_lables=True, node_size=20)
	# nx.draw(DG, with_lables=True, node_size=20)
	# nx.draw_spectral(G, with_labels=True)
	# nx.draw_spectral(DG, with_labels=True)

	# 为G计算spring布局时每个节点的位置，返回的是一个字典，Key是节点的标识符，
	# Value是一个元组，元素是X轴和Y轴对应的坐标。
	pos = nx.spring_layout(G)
	nx.draw_networkx_nodes(G, pos, node_size=20)
	nx.draw_networkx_edges(G, pos)
	nx.draw_networkx_labels(G, pos)
	plt.show()

def parser_error(errmsg):
	print("Usage: py -3" + sys.argv[0] + " [Options] use -h for help")
	print("Error: " + errmsg)
	sys.exit()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.error = parser_error
	parser._optionals.title = "OPTIONS"
	parser.add_argument("-d", help="查询域名解析IP历史")
	parser.add_argument("-ips", help="从cansvr.txt中遍历获取域名，进行IP查询，写入文件domain_ips.txt")
	parser.add_argument("-dms", help="查询某个IP当前及历史绑定的域名")
	parser.add_argument("-shw", help="综合查询并展示")
	args = parser.parse_args()
	if args.d:
		get_ips_fd(args.d)
	elif args.dms:
		get_d_fip(args.dms)
	elif args.shw:
		rst_show(args.shw)
	else:
		parser_error()
		print('None!')
