#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

""" Detect machine LAN """

import sys
import re
import os
import smtplib
import time
import datetime
from optparse import OptionGroup
from optparse import OptionParser

import nmap

__author__ = "GoldraK"
__credits__ = "Eduardo7c2"
__license__ = "GPL"
__version__ = "0.2"
__maintainer__ = "Eduardo7c2"
__email__ = "Eduardo7c2@gmail.com"
__status__ = "Prototype"


class DetectMachineLan:
	def __init__(self):
		self.version = "0.2"
		self.whitelist_file = ""
		self.log_file = ""
		self.verbose = False

	def detect_machine_lan(self):
		(opts, args) = self.__handle_arguments()
		if opts.macsearch and opts.ip:
			self.__detect_machines_network(opts.ip)
		if opts.macadd:
			macs = opts.macadd.split(",")
			for x in macs:
				self.__write_whitelist(x)
		if opts.macremove:
			macs = opts.macremove.split(",")
			for x in macs:
				self.__remove_whitelist(x)
		if opts.ip and not opts.macsearch:
			self.__detect_machines_whitelist(opts)

	def __scan_network(self, ip):
		nm = nmap.PortScanner()
		machines = nm.scan(hosts=ip, arguments='-sP')
		return machines

	def __detect_machines_network(self, ip):
		machines = self.__scan_network(ip)
		for k, v in machines['scan'].items():
			if str(v['status']['state']) == 'up':
				print("-------")
				try:
					print(str(v['addresses']['ipv4']) + " --> " + str(v['addresses']['mac']))
				except Exception:
					print(str(v['addresses']['ipv4']) + " --> MAC not detected")

	def __detect_machines_whitelist(self, opts):
		whitelist = self.__read_file()

		alert_mac = ""
		mac_list = []

		machines = self.__scan_network(opts.ip)

		for k, v in machines['scan'].items():
			if str(v['status']['state']) == 'up':
				try:
					for i in mac_list:
						if str(v['addresses']['mac']) in i:
							alert_mac = 'Duplicate MAC detected: ' + str(v['addresses']['mac']) + '\n'
							msg = 'Duplicate MAC detected: ' + str(v['addresses']['mac'])
							if self.verbose:
								self.__console_message(msg)
							if self.log_file:
								self.__write_log_file(msg)
					mac_list.append(str(v['addresses']['mac']))
					if str(v['addresses']['mac']) in whitelist:
						msg = 'Mac find ' + str(v['addresses']['mac']) + ' Ip: ' + str(v['addresses']['ipv4'])
						if self.verbose:
							self.__console_message(msg)
						if self.log_file:
							self.__write_log_file(msg)
					else:
						alert_mac = alert_mac + 'New MAC detected ' + str(v['addresses']['mac']) + ' IP: ' + \
									str(v['addresses']['ipv4']) + '\n'
						msg = 'New MAC detected ' + str(v['addresses']['mac']) + ' IP: ' + \
							  str(v['addresses']['ipv4'])
						if self.verbose:
							self.__console_message(msg)
						if self.log_file:
							self.__write_log_file(msg)
				except Exception:
					msg = 'MAC not detected ' + str(v['addresses']['ipv4'])
					if self.verbose:
						self.__console_message(msg)
					if self.log_file:
						self.__write_log_file(msg)
		if opts.emailto:
			self.__send_email(alert_mac, opts)

	def __handle_arguments(self, argv: object = None) -> object:
		"""
		This function parses the command line parameters and arguments
		"""

		parser = OptionParser()
		if not argv:
			argv = sys.argv

		mac = OptionGroup(parser, "MAC", "At least one of these "
						  "options has to be provided to define the machines")

		mac.add_option('--ms', '--macsearch', action='store_true', default=False, dest='macsearch',
					   help='Search machine Network')
		mac.add_option('--ma', '--macadd', action='store', dest='macadd', help='Add MAC to whitelist')
		mac.add_option('--mr', '--macremove', action='store', dest='macremove', help='Remove MAC from whitelist')

		email = OptionGroup(parser, "Email", "You need user, password, server and destination "
							"options has to be provided to define the server send mail")

		email.add_option('-u', '--user', action='store', dest='user', help='User mail server')
		email.add_option('--pwd', '--password', action='store', dest='password', help='Password mail server')
		email.add_option('-s', '--server', action='store', dest='server', help='mail server')
		email.add_option('-p', '--port', action='store', default='25', dest='port', help='Port mail server')
		email.add_option('--et', '--emailto', action='store', dest='emailto', help='Destination E-mail')

		parser.add_option('-r', '--range', action='store', dest='ip', help='Secure network range ')
		parser.add_option('-w', '--whitelist', action='store', default='whitelist.txt', dest='whitelist_file',
						  help='File have MAC whitelist ')
		parser.add_option('-l', '--log_file', action='store', default='log_file.txt', dest='log_file',
						  help='log_file actions script')
		parser.add_option('-v', '--verbose', action='store_true', default=False, dest='verbose',
						  help='Verbose actions script')

		parser.add_option_group(mac)
		parser.add_option_group(email)

		(opts, args) = parser.parse_args()

		self.log_file = opts.log_file
		self.verbose = opts.verbose
		self.whitelist_file = opts.whitelist_file

		if opts.user or opts.password or opts.server or opts.emailto:
			if not all([opts.user, opts.password, opts.server, opts.emailto]):
				err_msg = "missing some email option (-u, --pwd, -s, --et), use -h for help"
				parser.error(err_msg)
				self.__write_log_file(err_msg)
				sys.exit(-1)
		if opts.macsearch and not opts.ip:
			err_msg = "missing some range scan option (-r), use -h for help"
			parser.error(err_msg)
			self.__write_log_file(err_msg)
			sys.exit(-1)
		return opts, args

	def __send_email(self, alert_mac, opts):
		"""
		This function send mail with the report
		"""
		header = 'From: %s\n' % opts.user
		header += 'To: %s\n' % opts.emailto
		if alert_mac:
			header += 'Subject: New machines connected\n\n'
			message = header + 'List macs: \n ' + str(alert_mac)
		else:
			header += 'Subject: No intruders - All machines known \n\n'
			message = header + 'No intruders'

		server = smtplib.SMTP(opts.server + ":" + opts.port)
		server.starttls()
		server.login(opts.user, opts.password)
		if self.verbose or self.log_file:
			debug_email = server.set_debuglevel(1)
			if self.verbose:
				self.__console_message(debug_email)
		problems = server.sendmail(opts.user, opts.emailto, message)
		print(problems)
		server.quit()

	def __console_message(self, message):
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		print('[' + st + '] ' + str(message))

	def __write_log_file(self, log_file):
		"""
		This function write log_file
		"""
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		if os.path.isfile(self.log_file):
			try:
				file_read = open(self.log_file, 'a')
				file_read.write('[' + st + '] ' + log_file + "\n")
				file_read.close()
			except IOError:
				msg = 'ERROR: Cannot open' + self.log_file
				if self.verbose:
					self.__console_message(msg)
				sys.exit(-1)
		else:
			msg = "ERROR: The log_file file ", self.log_file, " doesn't exist!"
			if self.verbose:
				self.__console_message(msg)
			sys.exit(-1)

	def __write_whitelist(self, mac):
		"""
		This function add newmac to whitelist
		"""
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
			if os.path.isfile(self.whitelist_file):
				try:
					file_read = open(self.whitelist_file, 'a')
					file_read.write(mac + "\n")
					file_read.close()
					msg = "MAC: " + mac + " added correctly"
					if self.verbose:
						self.__console_message(msg)
					if self.log_file:
						self.__write_log_file(msg)
				except IOError:
					print()
					msg = 'ERROR: Cannot open' + self.whitelist_file
					if self.verbose:
						self.__console_message(msg)
					if self.log_file:
						self.__write_log_file(msg)
					sys.exit(-1)
			else:
				msg = "ERROR: The Whitelist file " + self.whitelist_file + " doesn't exist!"
				if self.verbose:
					self.__console_message(msg)
				if self.log_file:
					self.__write_log_file(msg)
				sys.exit(-1)
		else:
			msg = "ERROR: The MAC " + mac + " not valid!"
			if self.verbose:
				self.__console_message(msg)
			if self.log_file:
				self.__write_log_file(msg)

	def __remove_whitelist(self, mac):
		"""
		This function remove new mac from whitelist
		"""
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
			if os.path.isfile(self.whitelist_file):
				try:
					file_read = open(self.whitelist_file, 'r')
					lines = file_read.readlines()
					file_read.close()
					file_read = open(self.whitelist_file, 'w')
					for line in lines:
						if line.strip() != mac:
							file_read.write(line)
					file_read.close()
					msg = "MAC " + mac + " remove correctly"
					if self.verbose:
						self.__console_message(msg)
					if self.log_file:
						self.__write_log_file(msg)
				except IOError:
					msg = 'ERROR: Cannot open ' + self.whitelist_file
					if self.verbose:
						self.__console_message(msg)
					if self.log_file:
						self.__write_log_file(msg)
					sys.exit(-1)
			else:
				msg = "ERROR: The Whitelist file " + self.whitelist_file + " doesn't exist!"
				if self.verbose:
					self.__console_message(msg)
				if self.log_file:
					self.__write_log_file(msg)
				sys.exit(-1)
		else:
			msg = "ERROR: The MAC " + mac + " doesn't exist!"
			if self.verbose:
				self.__console_message(msg)
			if self.log_file:
				self.__write_log_file(msg)

	def __read_file(self):
		"""
		This function read the whitelist
		"""
		whitelist = []
		if os.path.isfile(self.whitelist_file):
			try:
				file_read = open(self.whitelist_file, 'r')
				for line in file_read:
					if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", line.strip().lower()):
						whitelist.append(line.strip())
				return whitelist
			except IOError:
				msg = 'ERROR: Cannot open ' + self.whitelist_file
				if self.verbose:
					self.__console_message(msg)
				if self.log_file:
					self.__write_log_file(msg)
				sys.exit(-1)
		else:
			msg = "ERROR: The Whitelist file " + self.whitelist_file + " doesn't exist!"
			if self.verbose:
				self.__console_message(msg)
			if self.log_file:
				self.__write_log_file(msg)
			sys.exit(-1)


if __name__ == "__main__":
	p = DetectMachineLan()
	p.detect_machine_lan()
