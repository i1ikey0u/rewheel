#!/usr/bin/env python
#coding:utf-8
#environ: python3 64bit
#code by shuichon

'''
V2.0，
'''

import argparse, sys, re, os
from bs4 import BeautifulSoup
from urllib import request, parse
import json
from http import cookiejar
import dns.resolver


hd = {
		'User-Agent': r'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
		              r'Chrome/44.0.2454.85 Safari/537.36 115Browser/6.0.3',
		'Connection': 'keep-alive',
		# "Accept-Encoding": "gzip, deflate, br",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
	}

nameservers = ['119.29.29.29', '182.254.116.116', '223.6.6.6', '8.8.8.8',
'8.8.4.4', '180.76.76.76',  '1.2.4.8', '210.2.4.8', '101.226.4.6',
'218.30.118.6', '8.26.56.26', '8.20.247.20']

canrsvr = set()
cantrsvr = set()


# 写入文件，分别将可解析域名和不可解析写入txt
def wf(fn, txt):
	f = open(fn, "a+")
	f.writelines(txt)
	f.close()

# OK ip138接口查询IP,便于查找真实IP地址
def get_ips(domain):
	url = "http://site.ip138.com/" + str(domain) + '/'
	# print(url)
	page = request.urlopen(url).read().decode('utf-8')
	# print(page)
	soup = BeautifulSoup(page, "html.parser")
	# div = soup.find_all('div', class_="panel")
	div = soup.find('div', class_="panel")
	print("发现%i个IP地址：" % len(div))
	hisaddr = div.find_all('a', target="_blank")
	for ha in hisaddr:
		print(ha.string)

# OK ip138接口 查询子域名
def subd_fm_ip138(target):
	url = "http://site.ip138.com/" + str(target) + '/domain.htm'
	# print(url)
	req = request.urlopen(url)
	if req.code != 200:
		return (req.code)
	page = req.read().decode('utf-8')
	# print(page)
	soup = BeautifulSoup(page, "html.parser")
	# div = soup.find_all('div', class_="panel")
	div = soup.find('div', class_="panel")
	# print(div)
	ps = div.find_all('a', target="_blank")
	print("存在%i个子域名" % len(ps))
	for sd in ps:
		print(sd.string)
		if chk_alive(sd.string):
			canrsvr.add(sd.string)
		else:
			cantrsvr.add(sd.string)
			# print(sd.string)
	wf("canrsvr.txt", canrsvr)
	wf("cantrsvr.txt", cantrsvr)

# OK 站长之家接口
def subd_fm_chinaz(target):
	url = "http://tool.chinaz.com/subdomain?domain=" + str(target)
	page = request.urlopen(url).read().decode('utf-8')
	soup = BeautifulSoup(page, "html.parser")
	ul = soup.find("ul", class_="ResultListWrap")
	us = ul.find_all("a")
	for a in us:
		print(a.string)
		if chk_alive(a.string):
			canrsvr.add(a.string)
		else:
			cantrsvr.add(a.string)
	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))


# OK virustotal接口
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
		sb = pg["data"][i]['id']
		# print(sb)
		if chk_alive(sb):
			canrsvr.add(sb)
		else:
			cantrsvr.add(sb)

	page2 = request.urlopen(url2).read().decode('utf-8')
	pg2 = json.loads(page2, encoding='utf-8')
	for i in range(len(pg["data"])):
		print("打印剩余子域名：")
		print(pg2["data"][i]['id'])
		sb = pg2["data"][i]['id']
		if chk_alive(sb):
			canrsvr.add(sb)
		else:
			cantrsvr.add(sb)

	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))



# #谷歌透明度查询 需要翻墙，暂时没做。
def subd_fm_gtr(target):
	url = "https://transparencyreport.google.com/"


# #threatcrowd威胁情报接口,
# 需要解决CloudFlare DDOS防护
def subd_fm_tc(target):
	url = "https://disqus.com/api/3.0/discovery/listTopPost.json?thread=6100104160&thread=6101359458&thread=6176664485&thread=6178793347&thread=6198134280&thread=6203325891&thread=6273540066&thread=6427423066&api_key=E8Uh5l5fHZ6gD8U3KycjAIAk46f68Zw7C6eW8WSjZvCLXebZ7p0r1yrYDrLilk2F"
	url2 = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + str(target)
	# req = request.Request(url2, headers=hd)
	# respn = request.urlopen(req)
	# page = respn.read().decode("utf-8")
	page = request.urlopen(url2).read().decode("utf-8")
	print(page)
	pg = json.loads(page, encoding='utf-8')
	print(pg["subdomains"])


# OK 使用dnsdb.org接口进行查询，只能获取10个内的子域名
#TODO 使用遍历的方法进行收集。
def subd_fm_dnsdb(target):
	url = "https://www.robtex.com/dns-lookup/" + str(target)
	req = request.Request(url, headers=hd)
	respn = request.urlopen(req)
	print(respn.code)
	page = respn.read().decode("utf-8")
	# print(page)
	soup = BeautifulSoup(page, "html.parser")
	h3 = soup.find('h3', text="Subdomains/Hostnames")
	cite = h3.parent.next_sibling
	# print(cite)
	for c in cite.find_all("cite"):
		# print(c.text)
		sb = c.text
		if chk_alive(sb):
			canrsvr.add(sb)
		else:
			cantrsvr.add(sb)

	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))



# censys接口
# TODO： 很难连接成功，无法获取返回页面，并且有访问限制
# TODO WARNING: Censys only allows 25 queries per day
# Tips：censys接口内的证书信息内，有IP地址信息，可以用于探测真实IP地址
def subd_fm_censys(target):
	url = 'https://censys.io/certificates?q=' + str(target)
	url2 = 'https://censys.io/certificates?q=tags%3A%20trusted%20and%20parsed.names%3A%20' + str(target)
	page = request.urlopen(url2).read().decode('utf-8')
	print(page)
	soup = BeautifulSoup(page, 'html.parser')
	# div = soup.find_all('div', id="resultset", class_="results")
	sdiv = soup.find_all('div', class_="results-metadata")
	print(len(sdiv))
	for d in sdiv:
		sbi = d.find_all('span')
		print(sbi[3])
		sb = sbi[3]
		if chk_alive(sb):
			canrsvr.add(sb)
		else:
			cantrsvr.add(sb)

	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))



# OK netcraft接口，最多返回500个
def subd_fm_netcraft(target):
	rs = []
	url = 'https://searchdns.netcraft.com/?restriction=site+contains&host=' + str(target)
	req = request.Request(url, headers=hd)
	page = request.urlopen(req).read().decode('utf-8')
	# print(page)
	soup = BeautifulSoup(page, 'html.parser')
	num = soup.find('em')
	# print(num.string)
	l = re.compile('\d{1,9}').findall(num.string)
	# print(l)

	tbl = soup.find('table', class_="TBtable")
	# print(len(tb))
	td = tbl.find_all('a', rel='nofollow')
	for sb in td:
		# print(sb.text)
		rs.append(sb.text)

	while len(rs) < int(l[0]):
		print(rs[len(rs)-1])
		url2 = 'https://searchdns.netcraft.com/?restriction=site+contains&host=' + str(target) + '&last=' + rs[len(rs)-1] +'&from=' + str(len(rs) + 1)
		req = request.Request(url2, headers=hd)
		page2 = request.urlopen(req).read().decode('utf-8')
		soup = BeautifulSoup(page2, 'html.parser')
		tbl = soup.find('table', class_="TBtable")
		td = tbl.find_all('a', rel='nofollow')
		for sb in td:
			# print(sb.text)
			rs.append(sb.text)
	# print(rs)
	# 将数组转为res set集合
	res = set(rs)
	# print(res)
	for r in res:
		if chk_alive(r):
			canrsvr.add(r)
		else:
			cantrsvr.add(r)

	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))



'''
利用域名证书信息进行收集，首先实现子域名信息收集，后续实现真实IP地址发现
'''
# OK crt.sh接口
# 查询qq.com这种有类似泛域名解析的一级域名，结果超大
def subd_fm_crtsh(target):
	url = "https://crt.sh/?q=%25." + str(target)
	page = request.urlopen(url).read().decode('utf-8')
	soup = BeautifulSoup(page, 'html.parser')
	# case1
	# to = soup.find_all('td', class_="outer")
	# print(len(to))
	# td = to[1].find_all('td', attrs={'style': False}, text=re.compile(target+'$'))
	# for sb in td:
	# 	print(sb.string)
	# case2
	pat = re.compile('<TD>' + '(.*?' + target + ')</TD>')
	sbs = pat.findall(page)
	for sb in sbs:
		# res.add(sb)
		if chk_alive(sb):
			canrsvr.add(sb)
		else:
			cantrsvr.add(sb)
	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))



# OK dnsdumpster接口
def subd_fm_dnsdumpster(target):
	url = 'https://dnsdumpster.com/'
	req = request.Request(url, headers=hd)
	p = request.urlopen(req)
	cj = cookiejar.CookieJar()
	opr = request.build_opener(request.HTTPCookieProcessor(cj))
	opr.open(req)
	# print(rsp.info, rsp.read)
	# print(cj)
	for i in cj:
		if i.name == 'csrftoken':
			csrft = i.value
			# print(csrft)
	dt = {
		'csrfmiddlewaretoken': csrft,
		'targetip': target
	}
	dat = parse.urlencode(dt).encode('utf-8')

	hd2 = {
		'User-Agent': r'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
		              r'Chrome/44.0.2454.85 Safari/537.36 115Browser/6.0.3',
		'Host': 'dnsdumpster.com',
		'Content-Type': 'application/x-www-form-urlencoded',
		"Referer": "https://dnsdumpster.com/",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
	}

	req2 = request.Request(url, data=dat, headers=hd2, method='POST')
	rsp = opr.open(req2)
	# print(rsp.info())
	page2 = rsp.read().decode('utf-8')
	# print(page2)

	soup = BeautifulSoup(page2, 'html.parser')
	# div = soup.find('div', class_="table-responsive", style="text-align: left;")
	# print(len(div))
	sbd = soup.find_all('td', class_="col-md-4")
	# print(len(sbd))
	for s in sbd:
		# print(s.text)
		# res.add(s.text)
		sb = s.text
		if chk_alive(sb):
			canrsvr.add(sb)
		else:
			cantrsvr.add(sb)

	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))


	# print(res)
	# IP信息
	# ips = sbd = soup.find_all('td', class_="col-md-3")
	# print(len(ips))



# #5118接口,需要登录，暂时不做
def subd_fm_(target):
	url = 'http://account.5118.com/signin?r=http://www.5118.com/seo/subdomains/' + str(target)
	page = request.urlopen(url).read().decode('utf-8')
	print(page)
	soup = BeautifulSoup(page, 'html.parser')


# #模板
def subd_fm_(target):
	url = '' + str(target)
	page = request.urlopen(url).read().decode('utf-8')
	print(page)
	soup = BeautifulSoup(page, 'html.parser')


def brp_fm_dnsdb(target):
	url = "http://www.dnsdb.org/f/" + str(target) + ".dnsdb.org/"
	for i in range(0, 10):
		url2 = url + str(i)
		print(url2)
		req = request.Request(url2, headers=hd)
		respn = request.urlopen(req)
		print(respn.code)
		page = respn.read().decode("utf-8")
		# print(page)
		soup = BeautifulSoup(page, "html.parser")
		sbs = soup.find_all('a')
		for sb in sbs:
			# print(sb.string)
			# res.add(sb)
			if chk_alive(sb):
				canrsvr.add(sb)
			else:
				cantrsvr.add(sb)
	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))

	for i in range(97, 123):
		url2 = url + chr(i)
		req = request.Request(url2, headers=hd)
		respn = request.urlopen(req)
		page = respn.read().decode("utf-8")
		# print(page)
		soup = BeautifulSoup(page, "html.parser")
		sbs = soup.find_all('a')
		for sb in sbs:
			# print(sb.string)
			# res.add(sb)
			if chk_alive(sb):
				canrsvr.add(sb)
			else:
				cantrsvr.add(sb)
	wf("canrsvr.txt", '\n'.join(canrsvr))
	wf("cantrsvr.txt", '\n'.join(cantrsvr))

	# print(res)


def chk_alive(target):
	# print('查看是否可以解析为IP及IP是否存活')
	# case1
	# req = dns.resolver.query(target)
	# # rsp = req.response.answer
	# for s in req.response.answer:
	# 	for j in s.items:
	# 		print(j)
			# if isinstance(j, dns.rdtypes.IN.A.A):
			# 	print('\t %s' % (j.address))
			# if isinstance(j, dns.rdtypes.ANY.CNAME.CNAME):
			# 	print('CNAME: %s' % (j))

	# case2
	rsvr = dns.resolver.Resolver()
	rsvr.nameservers = nameservers
	rsp = rsvr.query(target).response
	if rsp == dns.resolver.NoAnswer:
		print(dns.resolver.NoAnswer)
		return False
	else:
		# print(rsp)
		return True



def parser_error(errmsg):
	print("Usage: py -3" + sys.argv[0] + " [Options] use -h for help")
	print("Error: " + errmsg)
	sys.exit()


if __name__ == '__main__':
	# TODO 可以每个接口返回一个set集合，使用 a | b 求其并集。较小集合大小。
	res = set()
	parser = argparse.ArgumentParser()
	parser.error = parser_error
	parser._optionals.title = "OPTIONS"
	parser.add_argument("-ip", help="查询域名解析IP历史")
	parser.add_argument("-subd", help="查询子域名")
	parser.add_argument("-brpd", help="使用dnsdb接口暴力猜解子域名")
	args = parser.parse_args()
	# print(args)
	if args.ip:
		get_ips(args.ip)
	elif args.subd:
		try:
			print('try')
			subd_fm_ip138(args.subd)
			subd_fm_chinaz(args.subd)
			subd_fm_vt(args.subd)
			subd_fm_tc(args.subd)
			subd_fm_dnsdb(args.subd)
			subd_fm_censys(args.subd)
			subd_fm_crtsh(args.subd)
			subd_fm_netcraft(args.subd)
			subd_fm_dnsdumpster(args.subd)
			# chk_alive(args.subd)
		except Exception as e:
			print(e)
	elif args.brpd:
		try:
			brp_fm_dnsdb(args.brpd)
		except Exception as e:
			print(e)
	else:
		parser_error()
		print('None!')

