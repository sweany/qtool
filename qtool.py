#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
general qualys api tool. Should be able to create scan jobs, reports, download reports
2015-04-08 Lucas Sweany ; initial version using pycurl
2016-01-05 converted to requests instead of pycurl
2016-05-11 now using argparse for command line processing
"""
import argparse
import os
import sys
import time
import requests, requests.utils, pickle
import cStringIO
import datetime
import re
from collections import defaultdict

try:
    import xml.etree.cElementTree as et
except ImportError:
    import xml.etree.ElementTree as et

#from sys import version_info
#py3 = version_info[0] > 2 #creates boolean value for test that Python major version > 2


headers = {}
def header_function(header_line):
    # HTTP standard specifies that headers are encoded in iso-8859-1.
    # On Python 2, decoding step can be skipped. On Python 3, decoding step is required.
    header_line = header_line.decode('iso-8859-1')

    # Header lines include the first status line (HTTP/1.x ...). We are going to ignore all lines that don't have a colon in them.
    # This will botch headers that are split on multiple lines...
    if ':' not in header_line:
        return

    name, value = header_line.split(':', 1)

    # Remove whitespace that may be present.
    name = name.strip()
    value = value.strip()
    name = name.lower()
    headers[name] = value
    #print "(header) " + name + "=" + value

# ==============================================================================

def list_report_templates():
	# v1 API...uses basic auth instead of cookie
	url = api_baseurl + '/msp/report_template_list.php'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'list'}

	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))

	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, auth=(api_user,api_pass), verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		print 'An error occurred: ', errno, errstr

	print r.status_code
	#print r.text

	root = et.fromstring(r.text)
	for i in root.findall('.//'):
		title = ''
		templateid = ''
		type = ''
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			if j.tag == "TITLE":
				title = j.text
				if templateid != '':
					print templateid, type, title
			if j.tag == "ID":
				templateid = j.text
			if j.tag == "TEMPLATE_TYPE":
				type = j.text


# ==============================================================================
def find_report_by_title(name):
	# get the list of reports, find the one being asked for
	reportid = 0
	url = api_baseurl + '/api/2.0/fo/report/'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'list'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
	
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, auth=(api_user,api_pass), verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print "*** Looking for report titled '" + name + "'"

	try:
		root = et.fromstring(r.text)
	except error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	for i in root.findall('.//REPORT_LIST/REPORT'):
		tmpid = 0
		reportformat = ""
		title = ""
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			if j.tag == "OUTPUT_FORMAT":
				reportformat = j.text
			if j.tag == "ID":
				tmpid = j.text
			if j.tag == "TITLE":
				title = j.text
			if title == name:
				reportid = tmpid
				print "*** reportid is " + reportid
				return reportid

	return reportid

# ==============================================================================
def fetch_report(id):
	url = api_baseurl + '/api/2.0/fo/report/'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'fetch', 'id': str(id)}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))

	print "*** fetching report " + str(id) + '... ',
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code
	#print r.text

	if 'content-disposition' in r.headers:
		print r.headers['content-disposition'].lower()
		if "attachment" in r.headers['content-disposition']:
			filename = str(r.headers['content-disposition'].split('=')[1])

	return (r.content,filename)

# ==============================================================================
def report_download():
	qualys_login()
	reportid = 0

	if args.id == 0:
		reportid = find_report_by_title(args.name)

	if reportid == 0:
		print "No report found."
		sys.exit();

	# assuming we've got the report id, fetch it
	(content,filename) = fetch_report(reportid)

	fp = open(filename, "wb")
	fp.write(content)
	fp.close()
	print
	
	#os.rename("report.out", filename)
	print "*** Wrote report to " + filename
	
	qualys_logout()

# ==============================================================================	
def report_summary():
	qualys_login()
	reportid = 0

	if args.id == 0:
		reportid = find_report_by_title(args.name)

	if reportid == 0:
		print "No report found."
		sys.exit();

	# assuming we've got the report id, fetch it
	(content,filename) = fetch_report(reportid)

	# parse the report and add up stats
	root = et.fromstring(content)

	byhost = {}
	byvuln = {}
	kb = {}
	stats = {}
	stats['severity'] = defaultdict(int)
	stats['status'] = defaultdict(int)
	stats['uniq'] = defaultdict(int)

	# get details of QIDs for later reference
	for i in root.findall('.//VULN_DETAILS_LIST/VULN_DETAILS'):
		record = {}
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			record[j.tag] = j.text
		if record['QID'] != "":
			kb[record['QID']] = record
			byvuln[record['QID']] = {}
			byvuln[record['QID']]['hosts'] = {}
			byvuln[record['QID']]['hostcount'] = 0
			#print "gathering details about QID",record['QID']
			print 'QID', record['QID'], 'has severity', kb[record['QID']]['SEVERITY']
			stats['uniq'][kb[record['QID']]['SEVERITY']] += 1
			
	# parse through each host record
	for i in root.findall('.//HOST'):
			hostrecord = {}
			hostrecord['DNS'] = ''
			hostrecord['vulns'] = {}
			hostrecord['vulncount'] = 0
			hostrecord['OPERATING_SYSTEM'] = ''
			for j in i.getiterator():
				#print j.tag,j.attrib,j.text
				hostrecord[j.tag] = j.text

				if j.tag == "VULN_INFO":
					vulnrecord = {}
					vulnrecord['TICKET_NUMBER'] = ''
					vulnrecord['TICKET_STATE'] = ''
					for k in j.findall('.//'):
						#print k.tag,k.attrib,k.text
						vulnrecord[k.tag] = k.text

					hostrecord['vulns'][vulnrecord['QID']] = vulnrecord
					hostrecord['vulncount'] += 1
					byvuln[vulnrecord['QID']]['vuln'] = vulnrecord
					byvuln[vulnrecord['QID']]['hostcount'] += 1
					byvuln[vulnrecord['QID']]['hosts'][hostrecord['IP']] = hostrecord


			byhost[hostrecord['IP']] = hostrecord


	# report title, count by severity, count by CVSS, count by status
	for qid in sorted(byvuln):
		#print qid, kb[qid]['SEVERITY'], kb[qid]['TITLE'], '[', byvuln[qid]['hostcount'], 'hosts]'
		stats['severity'][kb[qid]['SEVERITY']] += 1
		for ipaddr in sorted(byvuln[qid]['hosts']):
			h = byvuln[qid]['hosts'][ipaddr]
			stats['status'][h['VULN_STATUS']] += 1
			#print "\t" + h['CVSS_FINAL'], h['VULN_STATUS'], '(' + h['LAST_FOUND'] + ')', ipaddr, '(' + h['DNS'] + ')', h['OPERATING_SYSTEM']
	

	print 'title="' + args.name + '"',
	print 'sev5=' + str(stats['severity']['5']), 'sev4=' + str(stats['severity']['4']), 'sev3=' + str(stats['severity']['3']), 'sev2=' + str(stats['severity']['2']), 'sev1=' + str(stats['severity']['1']),
	print 'uniq5=' + str(stats['uniq']['5']), 'uniq4=' + str(stats['uniq']['4']), 'uniq3=' + str(stats['uniq']['3']), 'uniq2=' + str(stats['uniq']['2']), 'uniq1=' + str(stats['uniq']['1']),
	print 'active=' + str(stats['status']['Active']), 'fixed=' + str(stats['status']['Fixed']), 'reopened=' + str(stats['status']['Re-Opened']), 
	print
	#for key in sorted(stats['status']):
	#	print stats['status'][key], key

	qualys_logout()



# ==============================================================================	
def list_reports():
	qualys_login()
	url = api_baseurl + '/api/2.0/fo/report/'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'list'}

	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))

	print '*** gathering report list... ',
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		print 'An error occurred: ', errno, errstr

	print r.status_code
	#print r.text

	try:
		root = et.fromstring(r.text)
	except error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	num = 0
	for i in root.findall('.//REPORT_LIST/REPORT'):
		num += 1
		reports = {}
		reports['TITLE'] = ''
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			reports[j.tag] = j.text

		print reports['LAUNCH_DATETIME'], reports['STATE'], reports['SIZE'], '(' + reports['OUTPUT_FORMAT'] + ')', reports['ID'], '"' + reports['TITLE'] + '"'
		if num >= args.limit:
			break

	qualys_logout()

# ==============================================================================
def list_assets():
	qualys_login()
	url = api_baseurl + '/api/2.0/fo/asset/host/vm/detection'
	# /api/2.0/fo/asset/host/ or /api/2.0/fo/asset/host/vm/detection/ ?
	headers = {'X-Requested-With': 'Curl'}
	params = {}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
	assets = {}

	if str(args.tags) != '':
		print "using tags " + str(args.tags)
		params = {'action': 'list', 'use_tags': '1', 'tag_set_by': 'name', 'tag_include_selector': 'all', 'tag_set_include': args.tags}

	if args.assetgroup != '':
		params['ag_titles'] = args.assetgroup

	if args.ipaddr != '':
		params['ips'] = args.ipaddr

	if args.qid != '':
		print "looking for assets with qid " + args.qid
		kb_title(args.qid)
		params['qids'] = args.qid

	params['action'] = 'list'

	print '*** gathering asset list... ',
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		print 'An error occurred: ', errno, errstr
	print r.status_code
	#print r.text

	root = et.fromstring(r.text)
	for i in root.findall('.//HOST'):
		record = {}
		record['DNS'] = ''
		record['OS'] = ''
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			record[j.tag] = j.text
			if j.tag == "IP":
				ipaddr = j.text
		if record['IP'] != '':
			#print record['IP'] + " (" + record['DNS']  + ")", record['OS']
			assets[record['IP']] = record

	for ipaddr in sorted(assets):
			print ipaddr + " (" + assets[ipaddr]['DNS']  + ")", 'TrackingMethod=' + assets[ipaddr]['TRACKING_METHOD'], 'LastScan=' + assets[ipaddr]['LAST_SCAN_DATETIME'], 'OS="' + assets[ipaddr]['OS'] + '"'
	print str(len(assets)) + " assets found matching the criteria."

	qualys_logout()

# ==============================================================================


def list_asset_groups():
	qualys_login()
	url = api_baseurl + '/api/2.0/fo/asset/group/'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'list'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))

	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		print 'An error occurred: ', errno, errstr
	print r.status_code
	#print r.text

	groups = {}
	root = et.fromstring(r.text)
	for i in root.findall('.//ASSET_GROUP'):
		record = {}
		record['IP_RANGE'] = ''
		record['RANGES'] = ''
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			if j.tag == "IP_SET":
				for k in j.getiterator():
					#print k.tag,k.attrib,k.text
					if k.tag == "IP":
						record['RANGES'] += k.text + ','
					if k.tag == "IP_RANGE":
						record['RANGES'] += k.text + ','

			record[j.tag] = j.text
			#print j.tag,j.attrib,j.text
		groups[record['TITLE']] = record

	for title in groups:
		print groups[title]['ID'], title, '[' + groups[title]['RANGES'] + ']'

	qualys_logout()

# ==============================================================================


def list_auth_records():
	qualys_login()
	url = api_baseurl + '/api/2.0/fo/auth/unix'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'list'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))

	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		print 'An error occurred: ', errno, errstr
	print r.status_code
	print r.text

	root = et.fromstring(r.text)
	for i in root.findall('.//'):
		record = {}
		#record['IP_RANGE'] = ''
		for j in i.getiterator():
			print j.tag,j.attrib,j.text
			for k in j.getiterator():
				print k.tag,k.attrib,k.text

	qualys_logout()

# ==============================================================================

def list_tickets():
	kb_read()

	#https://qualysapi.qualys.com/msp/ticket_list.php
	url = api_baseurl + '/msp/ticket_list.php'
	headers = {'X-Requested-With': 'Curl'}

	totaltickets = 0
	totalage = datetime.timedelta()
	stats = {}
	stats['OPEN/'] = 0
	stats['OPEN/REOPENED'] = 0
	stats['CLOSED/FIXED'] = 0
	stat_patchable = 0

	# if TRUNCATION/LAST exists in the output, load another page
	last = 1
	while last > 0:
		# since_ticket_number for pagination
		params = {'show_vuln_details': '0', 'modified_since_datetime': args.since, 'since_ticket_number': last}

		if args.assetgroup != '':
			params['asset_groups'] = args.assetgroup
		if args.ipaddr != '':
			params['ips'] = args.ipaddr
		if args.state != '':
			params['states'] = args.state
		if args.qid != '':
			params['qids'] = args.qid
		if args.severity != '':
			params['vuln_severities'] = args.severity

		try:
			r = requests.post(url, headers=headers, params=params, auth=(api_user,api_pass), verify=arg_sslverify)
		except requests.exceptions.RequestException, error:
			errno, errstr = error
			print 'An error occurred: ', errstr

		print r.status_code
		#print r.text

		root = et.fromstring(r.text)
		last = 0
		for i in root.findall('.//'):
			for j in i.getiterator():
				if j.tag == "ERROR":
					print j.tag, j.attrib['number'], j.text
				if j.tag == "TRUNCATION":
					#print j.tag,j.attrib,j.text
					last = j.attrib['last']


		for i in root.findall('.//TICKET'):
			d = {}
			d['CURRENT_STATUS'] = ''
			for j in i.getiterator():
				d[j.tag] = j.text
				#print j.tag,j.attrib,j.text
				if j.tag == "DETECTION":
					d['IP'] = j.text
				if j.tag == "STATS":
					d['STATS'] = {}
					d['STATS']['LAST_CLOSED_DATETIME'] = ''
					for k in j.getiterator():
						#print k.tag,k.attrib,k.text
						d['STATS'][k.tag] = k.text
				if j.tag == "VULNINFO":
					d['VULN'] = {}
					for k in j.getiterator():
						#print k.tag,k.attrib,k.text
						d['VULN'][k.tag] = k.text

			s = d['STATS']
			v = d['VULN']
			diff = ''
			# 2013-09-10T19:57:15Z
			if s['LAST_CLOSED_DATETIME'] != '':
				firstfound = datetime.datetime.strptime(s['LAST_OPEN_DATETIME'], '%Y-%m-%dT%H:%M:%SZ')
				closed = datetime.datetime.strptime(s['LAST_CLOSED_DATETIME'], '%Y-%m-%dT%H:%M:%SZ')
				if closed > firstfound:
					diff = closed - firstfound
					totalage += diff
			totaltickets += 1
			if d['DNSNAME'] is None:
				d['DNSNAME'] = str('')
			if 'PATCHABLE' in kb[v['QID']]:
				if kb[v['QID']]['PATCHABLE'] == '1':
					if d['CURRENT_STATE'] == 'OPEN':
						stat_patchable += 1
			print d['NUMBER'], d['CURRENT_STATE'] + '/' + d['CURRENT_STATUS'], s['LAST_OPEN_DATETIME'], s['LAST_CLOSED_DATETIME'], '[' + str(diff) + ']', d['IP'], '(' + d['DNSNAME'] + ')', v['QID'], kb[v['QID']]['CVSS_TEMPORAL'], v['SEVERITY'], v['TITLE']
			key = d['CURRENT_STATE'] + '/' + d['CURRENT_STATUS']
			stats[key] += 1

	print '========================================'
	print 'Total tickets: ', totaltickets
	print 'Patchable open: ', stat_patchable
	if totaltickets > 0:
		print 'Average time to close: ', totalage/totaltickets
		for key in stats:
			print key + ':', stats[key]
	


# ==============================================================================

def kb_update():
	url = api_baseurl + '/msp/knowledgebase_download.php'
	headers = {'X-Requested-With': 'Curl'}
	params = {'show_cvss_submetrics': '1'}
	try:
		#stream=True
		r = requests.post(url, headers=headers, params=params, auth=(api_user,api_pass), verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code

	print "Writing to", kbfile
	fp = open(kbfile, "wb")
	for chunk in r.iter_content(chunk_size=1024): 
		if chunk: # filter out keep-alive new chunks
			fp.write(chunk)

	fp.close()


# ==============================================================================

def kb_read():
	#print "reading in kb...",
	fp = open(kbfile, "rb")

	root = et.fromstring(fp.read())
	fp.close()
	for i in root.findall('.//VULN'):
		record = {}
		record['VENDOR_REFERENCE_LIST'] = {}
		record['CVE_ID_LIST'] = {}
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			if j.tag == "VENDOR_REFERENCE_LIST":
				ref = {}
				for k in j.getiterator():
					#print k.tag,k.attrib,k.text
					ref[k.tag] = k.text
				record['VENDOR_REFERENCE_LIST'][ref['ID']] = ref['URL']
				continue
			if j.tag == "CVE_ID_LIST":
				ref = {}
				for k in j.getiterator():
					#print k.tag,k.attrib,k.text
					ref[k.tag] = k.text
				record['CVE_ID_LIST'][ref['ID']] = ref['URL']
				#print record['QID'], ref['ID'] + ' = ' + ref['URL']
				continue
			record[j.tag] = j.text

		kb[record['QID']] = record

	#print "done"

# ==============================================================================

def kb_lookup():
	kb_read()

	d = kb[args.qid]

	print 'QID', args.qid, d['TITLE']
	print 'CVSS Base/Temporal:', d['CVSS_BASE'], d['CVSS_TEMPORAL']
	print 'Severity:', d['SEVERITY_LEVEL']
	print 'Type:', d['VULN_TYPE']
	print 'Category:', d['CATEGORY']
	print 'Last Update:', d['LAST_UPDATE']
	print 'Patchable:', d['PATCHABLE']
	print
	for key in d['CVE_ID_LIST']:
		ref = d['CVE_ID_LIST'][key]
		print key, ref
	for key in d['VENDOR_REFERENCE_LIST']:
		ref = d['VENDOR_REFERENCE_LIST'][key]
		print key, ref
	print
	print 'DIAGNOSIS'
	print html2text(d['DIAGNOSIS'])
	print
	print 'CONSEQUENCE'
	print html2text(d['CONSEQUENCE'])
	print
	print 'SOLUTION'
	print html2text(d['SOLUTION'])
	print

# ==============================================================================

def kb_title(qid):
	kb_read()
	d = kb[qid]
	print 'QID', qid, d['TITLE']


# ==============================================================================

def kb_stats():
	kb_read()

	techs = ['apache','openssh','openssl','tomcat','php','java','tls']
	stats = {}
	stats['types'] = {}
	stats['categories'] = {}
	stats['technologies'] = {}
	for key in kb:
		try:
			stats['types'][kb[key]['VULN_TYPE']] += 1
		except:
			stats['types'][kb[key]['VULN_TYPE']] = 0
		try:
			stats['categories'][kb[key]['CATEGORY']] += 1
		except:
			stats['categories'][kb[key]['CATEGORY']] = 0

		for tech in techs:
			if re.search(tech, kb[key]['TITLE'], re.IGNORECASE):
				try:
					stats['technologies'][tech] += 1
				except:
					stats['technologies'][tech] = 0
		
	print "=== Types"
	for key in sorted(stats['types']):
		print stats['types'][key], key

	print
	print "=== Categories"
	for key in sorted(stats['categories']):
		print stats['categories'][key], key

	print
	print "=== Technologies"
	for key in sorted(stats['technologies']):
		print stats['technologies'][key], key

	print

# ==============================================================================

def launch_scan():
	qualys_login()
	#/api/2.0/fo/scan/?action=launch
	url = api_baseurl + '/api/2.0/fo/scan/'
	headers = {'X-Requested-With': 'Curl'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
	params = {'action': 'launch', 'option_title': args.profile, 'scan_title': args.name}
	#scan_title
	#option_id OR option_title
	#iscanner_id or iscanner_name
	#ip, asset_group_ids, asset_groups, exclude_ip_per_scan,default_scanner, scanners_in_ag
	#target_from=tags, use_ip_nt_range_tags, tag_include_selector,tag_exclude_selector, tag_set_by, tag_set_exclude,tag_set_include
	if args.assetgroup != '':
		params['asset_groups'] = args.assetgroup
	if args.ipaddr != '':
		params['ip'] = args.ipaddr
	if args.tags != '':
		params['tag_set_by'] = 'name'
		params['tag_include_selector'] = 'all'
		params['tag_set_include'] = args.tags
	if args.scanner != '':
		params['iscanner_name'] = args.scanner

	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code
	#print r.text
	root = et.fromstring(r.text)
	for i in root.findall('.//RESPONSE'):
		for j in i.getiterator():
			if j.tag == "TEXT":
				print j.text
			if j.tag == "CODE":
				print j.text
			if j.tag == "VALUE":
				print j.text

	qualys_logout()

# ==============================================================================

def list_pcscans():
	qualys_login()
	url = api_baseurl + '/api/2.0/fo/scan/compliance/'
	headers = {'X-Requested-With': 'Curl'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
	params = {'action': 'list'}
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code
	#print r.text
	root = et.fromstring(r.text)
	for i in root.findall('.//SCAN'):
		record = {}
		for j in i.getiterator():
			#print j.tag, j.attrib, j.text
			record[j.tag] = j.text
		print record['REF'], record['TYPE'], record['LAUNCH_DATETIME'], record['USER_LOGIN'], record['DURATION'], record['PROCESSED'], record['TITLE']
		# record['STATUS'], (STATE)
		# record['TARGET']

	qualys_logout()


#https://<baseurl>/qps/rest/3.0/<operation>/<module>/<object>/<object_id>
#https://<baseurl>/qps/xsd/3.0/was/scan.xsd
#https://qualysapi.qualys.com/qps/rest/3.0/search/was/wasscan
# ==============================================================================

def scan_summary():
	# grab report by id if we have it, otherwise search by title
	if args.id != '':
		params = {'ref': args.id}

	if args.name != '':
		qualys_login()
		print 'Searching for scan with title "' + args.name + '"'
		url = api_baseurl + '/api/2.0/fo/scan/'
		headers = {'X-Requested-With': 'Curl'}
		with open('qtool_cookie.txt') as f:
			cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
		params = {'action': 'list'}
		try:
			r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
		except requests.exceptions.RequestException, error:
			errno, errstr = error
			print 'An error occurred: ', errstr

		print r.status_code
		#print r.text
		root = et.fromstring(r.text)
		for i in root.findall('.//SCAN'):
			record = {}
			for j in i.getiterator():
				#print j.tag, j.attrib, j.text
				record[j.tag] = j.text

			if record['TITLE'] == args.name:
				print 'Scan ref is ' + record['REF']
				params = {'ref': record['REF']}
				break
		qualys_logout()

	url = api_baseurl + '/msp/scan_report.php'
	headers = {'X-Requested-With': 'Curl'}
	try:
		r = requests.post(url, headers=headers, params=params, auth=(api_user,api_pass), verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code
	#print r.text
	root = et.fromstring(r.text)

	for i in root.findall('.'):
		for j in i.getiterator():
			#print j.tag, j.attrib['value'], j.text
			if j.tag == "ERROR":
				print j.tag, j.attrib['number'], j.text

	key = {}
	for i in root.findall('.//KEY'):
		for j in i.getiterator():
			#print j.tag, j.attrib['value'], j.text
			if j.tag == "ERROR":
				print j.tag, j.attrib['number'], j.text
			key[j.attrib['value']] = j.text

	# go through each vulnerability found, tally up severities
	# INFO {'number': '6', 'severity': '1'} 
	# CVSS_BASE {} 6.4
	# CVSS_TEMPORAL {} 5.2
	stats = {}
	stats['severity'] = {}
	stats['severity']['1'] = 0
	stats['severity']['2'] = 0
	stats['severity']['3'] = 0
	stats['severity']['4'] = 0
	stats['severity']['5'] = 0
	stats['status'] = {}
	stats['status']['New'] = 0
	stats['status']['Active'] = 0
	stats['status']['Fixed'] = 0
	stats['status']['Re-Opened'] = 0
	stats['unixauth'] = 0
	stats['unixauthfail'] = 0
	for i in root.findall('.//IP'):
		record = {}
		record['CVSS_BASE'] = ''
		record['CVSS_TEMPORAL'] = ''
		record['hostname'] = ''
		record['ipaddr'] = ''
		for j in i.getiterator():
			#print j.tag, j.attrib, j.text
			record[j.tag] = j.text
			if j.tag == 'IP':
				record['hostname'] = j.attrib['name']
				record['ipaddr'] = j.attrib['value']
			if j.tag == 'VULN':
				#print j.tag, j.attrib, j.text
				record['severity'] = j.attrib['severity']
				stats['severity'][j.attrib['severity']] += 1;
			if j.tag == 'VULN_STATUS':
				stats['status'] = j.text
			if j.tag == 'TITLE':
				if re.search('Unix Authentication Method', j.text, re.IGNORECASE):
					stats['unixauth'] += 1
				if re.search('Unix Authentication Failed', j.text, re.IGNORECASE):
					stats['unixauthfail'] += 1
					print 'type=authfail ip=' + record['ipaddr'] + ' hostname="' + record['hostname'] + '" date="' + key['DATE'] + '"'
		#print record['severity'], record['CVSS_BASE'], record['CVSS_TEMPORAL']

	#for key in sorted(stats['severity']):
	#	print stats['severity'][key], key

	# 2016-02-24T16:49:39+00:00 sim01.soc.sfo01.qualys.com vulns: summary date="2016-02-24T12:44:09Z" duration="02:11:57" nbhost_alive="311" nbhost_total="2816" network_title="Global Default Network" report_type="Scheduled (default option profile)" sev1=198 sev2=438 sev3=1475 sev4=1526 sev5=41 status="FINISHED" title="VM-weekly-prod-sjc01-p01-not-db07" unixauth="195" unixauthfail="0"  ref=scan/1456317850.99334
	# 2016-02-24T15:49:07+00:00 sim01.soc.sfo01.qualys.com vulns: summary date="2016-02-24T12:04:14Z" duration="03:28:52" nbhost_alive="341" nbhost_total="2560" network_title="Global Default Network" report_type="Scheduled (default option profile)" sev1=130 sev2=658 sev3=1341 sev4=908 sev5=253 status="FINISHED" title="VM-weekly-prod-gva01" unixauth="119" unixauthfail="31"  ref=scan/1456315455.99102
	# 2016-02-24T13:05:51+00:00 sim01.soc.sfo01.qualys.com vulns: summary date="2016-02-24T12:02:10Z" duration="00:54:28" nbhost_alive="221" nbhost_total="1792" network_title="Global Default Network" report_type="Scheduled (default option profile)" sev1=205 sev2=271 sev3=788 sev4=701 sev5=107 status="FINISHED" title="VM-weekly-prod-sjc01-p02" unixauth="180" unixauthfail="5"  ref=scan/1456315330.99062
	print 'type=summary ref="' + str(args.id) + '"',
	print 'date="' + key['DATE'] + '"', 'title="' + key['TITLE'] + '"', 'duration="' + key['DURATION'] + '"', 'nbhost_alive=' + key['NBHOST_ALIVE'], 'nbhost_total=' + key['NBHOST_TOTAL'], 'report_type="' + key['REPORT_TYPE'] + '"',
	print 'unixauth=' + str(stats['unixauth']), 'unixauthfail=' + str(stats['unixauthfail']), 'sev1=' + str(stats['severity']['1']), 'sev2=' + str(stats['severity']['2']), 'sev3=' + str(stats['severity']['3']), 'sev4=' + str(stats['severity']['4']), 'sev5=' + str(stats['severity']['5'])
	#print 'new=' + str(stats['status']['New']), 'fixed=' + str(stats['status']['Fixed']), 'active=' + str(stats['status']['Active']), 'reopened=' + str(stats['status']['Re-Opened'])





# ==============================================================================

def list_scans():
	qualys_login()
	url = api_baseurl + '/api/2.0/fo/scan/'
	headers = {'X-Requested-With': 'Curl'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
	params = {'action': 'list'}
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code
	#print r.text
	num = 0
	root = et.fromstring(r.text)
	for i in root.findall('.//SCAN'):
		record = {}
		num += 1
		for j in i.getiterator():
			#print j.tag, j.attrib, j.text
			record[j.tag] = j.text
		print record['REF'], record['TYPE'], record['LAUNCH_DATETIME'], record['USER_LOGIN'], record['DURATION'], record['PROCESSED'], record['TITLE']
		# record['STATUS'], (STATE)
		# record['TARGET']
		if num >= args.limit:
			break

	qualys_logout()


# ==============================================================================

def launch_report():
	url = api_baseurl + '/msp/report_template_list.php'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'list'}

	# get scan template ID
	templateid = 0
	
	print "*** listing report templates... ",
	try:
		r = requests.post(url, headers=headers, params=params, auth=(api_user,api_pass), verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code

	xmldata=r.text
	#start = xmldata.index("</SIMPLE_RETURN>")+17
	#xmldata=xmldata[start:]
	root = et.fromstring(xmldata)
	#for i in root.findall('.//REPORT_TEMPLATE_LIST/REPORT_TEMPLATE'):
	for i in root.findall('.//'):
		tmpid = 0
		title = ""
		for j in i.getiterator():
			#print j.tag,j.attrib,j.text
			if j.tag == "ID":
				tmpid = j.text
			if j.tag == "TITLE":
				title = j.text
			if title == reporttemplate:
				templateid = tmpid
				print "*** template ID is " + str(templateid)
				break
		if templateid > 0:
			break
	if templateid == 0:
		print "Unable to find template ID"
		sys.exit()

	#
	# get asset group IDs
	assetgroupid = 0
	if args.assetgroup != '':
		url = api_baseurl + '/msp/asset_group_list.php'
		params = {}

		print "*** listing asset groups... ",
		try:
			r = requests.post(url, headers=headers, params=params, auth=(api_user,api_pass), verify=arg_sslverify)
		except requests.exceptions.RequestException, error:
			errno, errstr = error
			print 'An error occurred: ', errstr
		print r.status_code

		xmldata=r.text
		root = et.fromstring(xmldata)
		#for i in root.findall('.//REPORT_TEMPLATE_LIST/REPORT_TEMPLATE'):
		for i in root.findall('.//'):
			record = {}
			record['TITLE'] = ''
			for j in i.getiterator():
				record[j.tag] = j.text
				#print j.tag,j.attrib,j.text
			if record['TITLE'] == args.assetgroup:
				assetgroupid = record['ID']
				print "*** asset group ID is " + str(assetgroupid)
				break


	
	#
	# launch the report
	qualys_login()
	url = api_baseurl + '/api/2.0/fo/report/'
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))

	# report by tags or by asset group list?
	params = {'action': 'launch', 'report_type': 'Scan', 'report_title': args.name, 'output_format': args.format, 'template_id': templateid}
	if args.assetgroup != '':
		params['asset_group_ids'] = assetgroupid
	if args.tags != '':
		params['use_tags'] = '1'
		params['tag_set_by'] = 'name'
		params['tag_include_selector'] = 'all'
		params['tag_set_include'] = args.tags

	print "*** launching report... ",
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr
	print r.status_code
	#print r.text

	root = et.fromstring(r.text)
	datetime = ''
	reportid = ''
	text = ''
	for i in root.findall('.//'):
		for j in i.getiterator():
			if j.tag == "VALUE":
				reportid = j.text
			if j.tag == "DATETIME":
				datetime = j.text
			if j.tag == "TEXT":
				text = j.text
	print datetime, reportid, text
	qualys_logout()

# ==============================================================================

def list_users():
	#https://qualysapi.qualys.com/msp/user_list.php
	qualys_login()
	url = api_baseurl + '/msp/user_list.php'
	headers = {'X-Requested-With': 'Curl'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
	params = {}
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, auth=(api_user,api_pass), verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code
	#print r.text

	root = et.fromstring(r.text)
	for i in root.findall('.//USER'):
		record = {}
		for j in i.getiterator():
			#print j.tag, j.attrib, j.text
			record[j.tag] = j.text
		print record['USER_STATUS'], record['USER_LOGIN'], '"' + record['FIRSTNAME'], record['LASTNAME'] + '"', 'Created', record['CREATION_DATE'], 'Last Login', record['LAST_LOGIN_DATE']

	qualys_logout()

# ==============================================================================
def add_user():
	#https://qualysapi.qualys.com/msp/user.php
	qualys_login()
	url = api_baseurl + '/msp/user.php'
	headers = {'X-Requested-With': 'Curl'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
	params = {'action': 'add', 'send_email': '0', 'user_role': 'reader', 'business_unit': 'Unassigned', 'first_name': 'Operations', 'last_name': 'Monitoring', 'title': 'Operations', 'phone': '650-801-6330', 'email': 'ops-sec@qualys.com', 'address1': '1600 Bridge Parkway', 'address2': '', 'city': 'Redwood City', 'country': 'United States of America', 'state': 'California', 'zip_code': '94065'}
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, auth=(api_user,api_pass), verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		errno, errstr = error
		print 'An error occurred: ', errstr

	print r.status_code
	print r.text


	qualys_logout()


# ==============================================================================
def list_accounts():
	print
	print 'qtool has cached credentials for the following:'
	print
	for key in credentials:
		print "\t" + key + ' (' + credentials[key]['QTOOL_USER'] + ')'

	print


# ==============================================================================
def qualys_login():
	url = api_baseurl + '/api/2.0/fo/session/'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'login', 'username': api_user, 'password': api_pass}

	print "*** logging in as " + api_user + ' ...',
	try:
		r = requests.post(url, headers=headers, params=params, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		print 'An error occurred: ', error
		sys.exit()

	print r.status_code
	#print r.text

	with open('qtool_cookie.txt', 'w') as f:
		pickle.dump(requests.utils.dict_from_cookiejar(r.cookies), f)	

	#print r.cookies['QualysSession']
	

# ==============================================================================
def qualys_logout():
	url = api_baseurl + '/api/2.0/fo/session/'
	headers = {'X-Requested-With': 'Curl'}
	params = {'action': 'logout'}
	with open('qtool_cookie.txt') as f:
		cookies = requests.utils.cookiejar_from_dict(pickle.load(f))

	print "*** logging out ",
	try:
		r = requests.post(url, headers=headers, params=params, cookies=cookies, verify=arg_sslverify)
	except requests.exceptions.RequestException, error:
		print 'An error occurred: ', errno, errstr

	print r.status_code
	#print r.text

# ==============================================================================

def html2text(text):
	text = re.sub('<P>',"\n", text)
	text = re.sub('<BR>',"\n", text)
	text = re.sub('</A>',"\n", text)
	text = re.sub('<A HREF="','[', text)
	text = re.sub('" TARGET="_blank">',"]", text)
	return text

# ==============================================================================

def examples():
	print "\nSyntax:\n";
	print "\t" + str(sys.argv[0]) + ' kb <-q qid>'
	print "\t" + str(sys.argv[0]) + ' kbstats'
	print "\t" + str(sys.argv[0]) + ' kbupdate'
	print
	print "\t" + str(sys.argv[0]) + ' listassetgroups'
	print "\t" + str(sys.argv[0]) + ' listassets <-a assetgroups|-t tags|-h iplist|-q qids>'
	print "\t" + str(sys.argv[0]) + ' listtickets <-a assetgroups|-h iplist> [-s YYYY-MM-DD] [--state OPEN|CLOSED|RESOLVED|IGNORED] [-q qid1,qid2,...,qid10] [--sev 1|2|3|4|5|1,2,..]'
	print
	print "\t" + str(sys.argv[0]) + ' listreports'
	print "\t" + str(sys.argv[0]) + ' listtemplates'
	print "\t" + str(sys.argv[0]) + ' getreport <-n "Report title"|-i reportid>'
	print "\t" + str(sys.argv[0]) + ' createreport -n "Report title" -o reporttemplate <-a assetgroups|-t tags> [-f <csv|html|pdf|xml>]'
	print
	print "\t" + str(sys.argv[0]) + ' listscans'
	print "\t" + str(sys.argv[0]) + ' scansummary -i <report reference>'
	print "\t" + str(sys.argv[0]) + ' launchscan <-n "Scan title"> <-a assetgroups|-t tags|-h iplist> [--scanner "iscanner appliance name"] [-p "option profile name"]'
	#listoptionprofiles
	print
	print "\t" + 'accounts'

	print "\nExamples:\n";
	print "\t" + str(sys.argv[0]) + ' createreport -n "sfo01-eng-p03 by vuln snapshot 20150407" -o "All vulns sorted by vuln snapshot" -a SFO01-ENG-P03'
	print "\t" + str(sys.argv[0]) + ' createreport -n "sfo01-eng-p03 by host snapshot 20150407" -o "All vulns sorted by host snapshot" -t eng,p03'
	print "\n"

# ==============================================================================
# ==============================================================================

parser = argparse.ArgumentParser(description='Qualys API tool. Repicate many common tasks which are cumbersome in the UI, and provde a way to dump data to syslog for easy reporting in splunk.')
# positional argument
parser.add_argument('mode', action='store', choices=['accounts', 'kb', 'kbstats', 'kbupdate', 'listassetgroups', 'listassets', 'listtickets', 'listreports', 'listtemplates', 'listscans', 'getreport', 'createreport', 'reportsummary', 'scansummary', 'launchscan'], help='operating mode')
# optional argument
parser.add_argument('-u', action='store', dest='url', default='https://qualysapi.qualys.com', help='API url')
# optional argument, true/false, no parameters
parser.add_argument('--noverify', action='store_true', default=False, help='Do no verify SSL certficates')
parser.add_argument('--prompt', action='store_true', default=False, help='Prompt for credentials (to change stored creds)')
parser.add_argument('-v', action='store_true', dest='verbose', default=False, help='Verbose output')
parser.add_argument('-a', action='store', dest='assetgroup', default='', help='assetgroup list (comma separated)')
parser.add_argument('-t', action='store', dest='tags', default='', help='tag list (comma separated)')
parser.add_argument('-i', action='store', dest='ipaddr', default='', help='IP list (comma separated)')
parser.add_argument('-q', action='store', dest='qid', default='', help='QID list (comma separated)')
parser.add_argument('-s', action='store', dest='since', default='2013-01-01', help='since date')
parser.add_argument('--id', action='store', dest='id', default=0, help='report ID')
parser.add_argument('-l', action='store', dest='limit', type=int, default=20, help='list size limit')
parser.add_argument('-n', action='store', dest='name', default='', help='title or name')
parser.add_argument('-o', action='store', dest='template', default='All vulns sorted by vuln snapshot', help='report template')
parser.add_argument('-p', action='store', dest='profile', default='ops-sec-01', help='option profile')
parser.add_argument('--state', action='store', dest='state', choices=['OPEN', 'CLOSED', 'RESOLVED', 'IGNORED'], help='ticket state')
parser.add_argument('--sev', action='store', dest='severity', help='severity')
parser.add_argument('-f', action='store', dest='format', default='html', choices=['csv', 'html', 'pdf', 'xml'], help='output format')
parser.add_argument('--scanner', action='store', dest='scanner', default='', help='scanner appliance name')

args = parser.parse_args()


# globals
api_baseurl = 'https://qualysapi.qualys.com'
api_user=''
api_pass=''

kbfile = 'kb.xml'
kb = {}

mode=args.mode
api_baseurl = args.url
arg_sslverify = not args.noverify



# initialize cred store
credentials = {}
try:
	with open('.qtool') as f:
		credentials = pickle.load(f)
except:
	credentials = {}

# are user & password already present?
if not args.prompt:
	try:
		if 'QTOOL_USER' in credentials[api_baseurl]:
			api_user = credentials[api_baseurl]['QTOOL_USER']
		if 'QTOOL_PASS' in credentials[api_baseurl]:
			api_pass = credentials[api_baseurl]['QTOOL_PASS']
	except:
		credentials[api_baseurl] = {}

# prompt for user & password if they aren't already present
if api_user == '':
	api_user = raw_input("Enter your qualysguard username: ")
	credentials[api_baseurl]['QTOOL_USER'] = api_user
if api_pass == '':
	api_pass = raw_input("Enter your qualysguard password: ")
	credentials[api_baseurl]['QTOOL_PASS'] = api_pass

with open('.qtool', 'w') as f:
	pickle.dump(credentials, f)	


# ==============================================================================
# main program routine

modes = {'getreport': report_download,
	'createreport': launch_report,
	'reportsummary': report_summary,
	# patch report?
	'listreports': list_reports,
	'listassets': list_assets,
	'listtemplates': list_report_templates,
	'listassetgroups': list_asset_groups,
	#'listtags': list_tags,
	'listauth': list_auth_records,
	'listtickets': list_tickets,
	'kbupdate': kb_update,
	'kb': kb_lookup,
	'kbstats': kb_stats,
	'launchscan': launch_scan,
	'listscans': list_scans,
	'listpcscans': list_pcscans,
	'listusers': list_users,
	'adduser': add_user,
	'scansummary': scan_summary,
	'accounts': list_accounts,
}

try:
	modes[mode]()
except:
	print "Invalid command line arguments specified."
	raise
	examples()

sys.exit()

