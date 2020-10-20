#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import subprocess
from OpenSSL.crypto import load_certificate, dump_publickey, dump_privatekey, dump_certificate, X509, X509Name, PKey
from OpenSSL.crypto import TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1, load_pkcs7_data
from Crypto.Util.asn1 import (DerSequence, DerObject)
from datetime import datetime
import textwrap
from OpenSSL.crypto import _lib, _ffi, X509
from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config
import apkutils
import hashlib
import pyaxmlparser
import glob
import json
import avclass_labeler
from argparse import Namespace
from dateutil.parser import parse
import re
from const import *

cert_id = 'cert_id'
vt_report_dir = os.path.expanduser("~/Projects/file_data/vt_reports")
# os.path.expanduser("~/Projects/apk_extractor/vt_reports")

build_prop_dir = os.path.expanduser("~/Projects/file_data/build_props")
# os.path.expanduser("~/Documents/Myworkspace/build_props")

apk_pos_file = "firmware_apk_position.txt"  # "play_apk_position.txt"
apk_crawler_log = "log.txt"
apk_hash_path_items = [apk_md5, apk_sha1, apk_sha256, pem_md5, pem_sha1,
                       pem_sha256, apk_original_path]

firm_sys_hash_file = os.path.expanduser("~/Projects/apk_extractor/batch2_firm_sys_hash.txt")
log = "log starts here.\n"
start = None
apk_dict = {}
firm_cert_dict = {}
apk_cert_dict = {}


def format_subject_issuer(x509name, cert_dict, actor):
    items = []
    # actor_dict = {"C": "", "ST": "", "L": "", "O": "", "OU": "", "CN": "", "emailAddress": ""}
    try:
        for item in x509name.get_components():
            tag = item[0].decode("utf-8")
            value = item[1].decode("utf-8")
            # actor_dict[tag] = value
            cert_dict[actor][tag] = value
            items.append('%s=%s' % (tag, value))
    except UnicodeDecodeError as error:
        global log
        exception = "UnicodeDecodeError for: " + cert_dict['cert_file_path'] + "\n" + str(error)
        print(exception)
        log += exception
    # finally:
    #     cert_dict[actor] = actor_dict

    return ", ".join(items)


def format_split_bytes(aa):
    bb = aa[1:] if len(aa) % 2 == 1 else aa  # force even num bytes, remove leading 0 if necessary
    return bb
    # return ':'.join(bb[i:i + 2] for i in range(0, len(bb), 2))
    # out = format(':'.join(s.encode('hex').lower() for s in bb.decode('hex')))
    # return out
    # return str(aa)


def format_split_int(serial_number):
    # print(serial_number)
    aa = "0%x" % serial_number  # add leading 0
    # print("val " + aa)
    return format_split_bytes(aa)


def format_asn1_date(d):
    return datetime.strptime(d.decode('utf-8'), '%Y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S GMT")


def get_signature_bytes(x509):
    der = DerSequence()
    der.decode(dump_certificate(FILETYPE_ASN1, x509))
    der_tbs = der[0]
    der_algo = der[1]
    der_sig = der[2]
    der_sig_in = DerObject()
    der_sig_in.decode(der_sig)
    sig = der_sig_in.payload[1:]  # skip leading zeros
    # return ''.join(format(x, '02x') for x in sig)
    return sig


def get_modulus_and_exponent(x509):
    if x509.get_pubkey().type() == TYPE_RSA:
        pub_der = DerSequence()
        pub_der.decode(dump_publickey(FILETYPE_ASN1, x509.get_pubkey()))
        public_key = ''.join(['%02x' % c for c in pub_der[1]])
        pub_key_der = DerObject()
        pub_key_der.decode(pub_der[1])
        pub_mod_exp = DerSequence()
        pub_mod_exp.decode(pub_key_der.payload[1:])
        modulus = "%x" % pub_mod_exp[0]
        if modulus[0] > '7':
            modulus = '00' + modulus
        exponent = pub_mod_exp[1]
        # print(public_key + "\n" + modulus + "\n" + str(exponent))
        return [modulus, exponent, public_key]
    return ''


def get_certificates(pkcs7):
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """
    certs = _ffi.NULL
    if pkcs7.type_is_signed():
        certs = pkcs7._pkcs7.d.sign.cert
    elif pkcs7.type_is_signedAndEnveloped():
        certs = pkcs7._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return pycerts


def parse_cert(cert_file, cert_dict):
    cert_dict['cert_file_path'] = os.path.abspath(cert_file)
    try:
        with open(cert_file, 'rb+') as f:
            cert_pem = f.read()

        pkcs7 = load_pkcs7_data(FILETYPE_ASN1, cert_pem)
        x509 = get_certificates(pkcs7)[0]
        # x509 = load_certificate(FILETYPE_PEM, cert_pem)

        # print("Certificate:")
        # print("    Data:")

        cert_dict[cert_version] = int(x509.get_version() + 1)
        # print("        Version: %s (0x%x)" % (cert_dict['version'], x509.get_version()))

        # print("        Serial Number:")
        cert_dict[serial_number] = format_split_int(x509.get_serial_number())
        # print("            %s" % cert_dict['serial_number'])

        cert_dict[sig_alg] = x509.get_signature_algorithm().decode("utf-8")
        # print("    Signature Algorithm: %s" % cert_dict['signature_algorithm'])

        cert_dict[issuer][dn] = format_subject_issuer(x509.get_issuer(), cert_dict, "issuer")
        # print("    Issuer: %s" % issuer)

        # print("    Validity")
        cert_dict[not_valid_before] = format_asn1_date(x509.get_notBefore())
        # print("        Not Before: %s" % cert_dict['not_before'])
        cert_dict[not_valid_after] = format_asn1_date(x509.get_notAfter())
        # print("        Not After : %s" % cert_dict['not_after'])

        cert_dict[subject][dn] = format_subject_issuer(x509.get_subject(), cert_dict, "subject")
        # print("    Subject: %s" % subject)
        # print("    Subject Public Key Info:")

        if cert_dict[issuer][dn] == cert_dict[subject][dn]:
            cert_dict[dn_type] = "both"
        else:
            cert_dict[dn_type] = "subject"

        # pkey_lines = []
        # keytype = x509.get_pubkey().type()
        # keytype_list = {TYPE_RSA: 'rsaEncryption', TYPE_DSA: 'dsaEncryption', 408: 'id-ecPublicKey'}
        # key_type_str = keytype_list[keytype] if keytype in keytype_list else 'other'

        # cert_dict['pub_key_algorithm'] = key_type_str
        # pkey_lines.append("        Public Key Algorithm: %s" % key_type_str)

        cert_dict[key_size] = x509.get_pubkey().bits()
        # pkey_lines.append("            Public-Key: (%s bit)" % cert_dict['key_size'])
        if x509.get_pubkey().type() == TYPE_RSA:
            cert_dict[key_modulus], cert_dict[key_exponent], cert_dict[public_key] = get_modulus_and_exponent(x509)
            # formatted_modulus = "\n                ".join(textwrap.wrap(modulus, 45))
            # pkey_lines.append("            Modulus:")
            # pkey_lines.append("                %s" % formatted_modulus)
            # pkey_lines.append("            Exponent %d (0x%x)" % (exponent, exponent))
        # print("\n".join(pkey_lines))

        # print("        X509v3 extensions:")
        # for i in range(x509.get_extension_count()):
        #     critical = 'critical' if x509.get_extension(i).get_critical() else ''
        #     item = x509.get_extension(i).get_short_name().decode("utf-8")
        #     val = x509.get_extension(i).__str__()
        #     if item == 'subjectKeyIdentifier':
        #         cert_dict['subjectKeyIdentifier'] = val
            # elif item == 'authorityKeyIdentifier':
            #     cert_dict['authorityKeyIdentifier'] = val
            # print("             x509v3 %s: %s" % (item, critical))
            # print("                 %s" % val)

        # print("    Signature Algorithm: %s" % x509.get_signature_algorithm().decode("utf-8"))
        cert_dict[signature] = ''.join(format(x, '02x') for x in get_signature_bytes(x509))
        # sig_formatted = "\n         ".join(textwrap.wrap(cert_dict[signature], 54))
        # print("         %s" % sig_formatted)

        cert_dict[pem_md5] = x509.digest('md5').decode("utf-8").replace(':', '').lower()
        # print("    Thumbprint MD5:    %s" % cert_dict['md5_fingerprint'])
        cert_dict[pem_sha1] = x509.digest('sha1').decode("utf-8").replace(':', '').lower()
        # print("    Thumbprint SHA1:   %s" % cert_dict['sha1_fingerprint'])
        cert_dict[pem_sha256] = x509.digest('sha256').decode("utf-8").replace(':', '').lower()
        # print("    Thumbprint SHA256: %s" % cert_dict['sha256_fingerprint'])

    except Exception as e:
        global log
        exception = "Error in parse cert: " + cert_file + "\n" + str(e)
        print(exception)
        log += exception


def initialize_dicts():
    for item in nullable_apk_items:
        apk_dict[item] = None

    for item in nullable_cert_items:
        apk_cert_dict[item] = None
        firm_cert_dict[item] = None

    apk_cert_dict[issuer] = {}
    apk_cert_dict[subject] = {}
    firm_cert_dict[issuer] = {}
    firm_cert_dict[subject] = {}
    for item in nullable_dn_items:
        apk_cert_dict[issuer][item] = None
        apk_cert_dict[subject][item] = None
        firm_cert_dict[issuer][item] = None
        firm_cert_dict[subject][item] = None


def insert_cert_info_into_db(cursor, cert_dict):
    cursor.execute(cert_check_query, (cert_dict[pem_md5],))
    if cursor.rowcount == 0:
        # print("new cert")
        if cert_dict[issuer][dn] is not None:
            cursor.execute(dn_check_query, (cert_dict[issuer][dn],))
            if cursor.rowcount == 0:
                dn_insert_args = tuple([cert_dict[issuer][item] for item in dn_table])
                cursor.execute(dn_insert_query, dn_insert_args)
                cert_dict[issuer_id] = cursor.lastrowid
            else:
                cert_dict[issuer_id] = cursor.fetchone()[0]

            if cert_dict[dn_type] == subject:
                cursor.execute(dn_check_query, (cert_dict[subject][dn],))
                if cursor.rowcount == 0:
                    dn_insert_args = tuple([cert_dict[subject][item] for item in dn_table])
                    cursor.execute(dn_insert_query, dn_insert_args)
                    cert_dict[subject_id] = cursor.lastrowid
                else:
                    cert_dict[subject_id] = cursor.fetchone()[0]
            else:
                cert_dict[subject_id] = cert_dict[issuer_id]

        cert_insert_args = tuple([cert_dict[item] for item in cert_table])
        cursor.execute(cert_insert_query, cert_insert_args)
        return cursor.lastrowid
    else:
        cert_row = cursor.fetchone()
        return cert_row[0]


def insert_apk_info_into_db(db_connection, apk_path, cert_destination, apk_source):
    cursor = None
    try:
        cursor = db_connection.cursor(buffered=True)
        get_hash(apk_path)
        get_apk_info(apk_path, cert_destination, apk_source)
        cursor.execute(apk_check_query, (apk_dict[apk_md5],))
        if cursor.rowcount == 0:
            if apk_cert_dict[pem_md5] is not None:
                apk_dict[apk_cert_id] = insert_cert_info_into_db(cursor, apk_cert_dict)

            apk_insert_args = tuple([apk_dict[item] for item in apk_table])
            cursor.execute(apk_insert_query, apk_insert_args)
            apk_dict[apk_id] = cursor.lastrowid
        else:
            apk_row = cursor.fetchone()
            apk_dict[apk_id] = apk_row[0]

        if apk_dict[source] == 'firmware':
            cursor.execute(firmware_check_query, (apk_dict[firm_md5],))
            if cursor.rowcount == 0:
                firm_cert_file = os.path.join(apk_dict[extract_dir], "CERT.RSA")
                if os.path.exists(firm_cert_file):
                    parse_cert(firm_cert_file, firm_cert_dict)
                    apk_dict[firm_cert_id] = insert_cert_info_into_db(cursor, firm_cert_dict)

                # if get_build_prop():
                #     build_prop_insert_args = tuple([apk_dict[item] for item in build_prop_table])
                #     cursor.execute(build_prop_insert_query, build_prop_insert_args)
                #     apk_dict[build_prop_id] = cursor.lastrowid
                get_build_prop()
                firmware_insert_args = tuple([apk_dict[item] for item in firmware_table])
                cursor.execute(firmware_insert_query, firmware_insert_args)
                apk_dict[firmware_id] = cursor.lastrowid

                apk_dict[source_url] = "https://androidmtk.com/"
                firmware_source_insert_args = tuple([apk_dict[item] for item in firmware_source_table])
                cursor.execute(firmware_source_insert_query, firmware_source_insert_args)
            else:
                firmware_row = cursor.fetchone()
                apk_dict[firmware_id] = firmware_row[0]

            firmware_info_insert_args = tuple([apk_dict[item] for item in firmware_info_table])
            cursor.execute(firmware_info_insert_query, firmware_info_insert_args)
        else:
            appstore_info_insert_args = tuple([apk_dict[item] for item in appstore_info_table])
            cursor.execute(appstore_info_insert_query, appstore_info_insert_args)
        db_connection.commit()

    except Error as error:
        print(error)

    finally:
        if cursor is not None:
            cursor.close()


def extract_cert_from_apk(apk_path, destination, apk_source):
    if apk_source == "firmware":
        rsa_file = apk_path.replace("/apps/", "/certs/").replace(".apk", ".RSA")
        if os.path.exists(rsa_file) and (os.path.getsize(rsa_file) > 0):
            return rsa_file
        rsa_file = os.path.dirname(apk_path.replace("/apps/", "/certs/")) + os.path.basename(apk_path).split('.')[0] + ".RSA"
        if os.path.exists(rsa_file) and (os.path.getsize(rsa_file) > 0):
            return rsa_file
        else:
            print("RSA not found")
            return None

    else:
        rsa_file = os.path.join(destination, os.path.splitext(os.path.basename(apk_path))[0] + ".RSA")
        if not os.path.exists(rsa_file):
            os.makedirs(os.path.dirname(rsa_file), exist_ok=True)
            val = -1
            try:
                print("Unzipping: " + os.path.basename(apk_path))
                val = subprocess.call("unzip -p " + apk_path + " *.RSA > " + rsa_file, shell=True)
                if val != 0:
                    subprocess.call("rm " + rsa_file, shell=True)
                    raise FileNotFoundError

            except FileNotFoundError:
                print(" Error Code: " + str(val) + "\n")

    if os.path.exists(rsa_file) and (os.path.getsize(rsa_file) > 0):
        return rsa_file
    else:
        global log
        exception = "Cert extraction Problem in file: " + apk_path + "\n"
        print(exception)
        log += exception
        return None


def get_manifest_info(apk_path):
    global log
    try:
        apk = apkutils.APK(apk_path)
        manifest_dict = apk.get_manifest()
        apk_dict[package] = manifest_dict["@package"]
        apk_dict[versionCode] = manifest_dict["@android:versionCode"]
        apk_dict[versionName] = manifest_dict["@android:versionName"]
        apk_dict[minSdkVersion] = manifest_dict['uses-sdk']['@android:minSdkVersion']
        apk_dict[targetSdkVersion] = manifest_dict['uses-sdk']['@android:targetSdkVersion']
        if "@android:sharedUserId" in manifest_dict:
            apk_dict[sharedUserId] = manifest_dict["@android:sharedUserId"]

    except Exception as e:
        exception1 = "Error getting manifest info: " + apk_path + "\n" + str(e)
        print(exception1)
        log += exception1
        try:
            apk = pyaxmlparser.APK(apk_path)
            apk_dict[package] = apk.package
            apk_dict[versionCode] = apk.version_code
            apk_dict[versionName] = apk.version_name
            apk_dict[minSdkVersion] = apk.get_min_sdk_version
            apk_dict[targetSdkVersion] = apk.get_target_sdk_version
        except Exception as ex:
            exception2 = "Error getting package info: " + apk_path + "\n" + str(ex)
            print(exception2)
            log += exception2
            with open(apk_crawler_log, "a+") as login:
                login.write(log + '\n')
                log = "--------********Dumped********----------\n"


def get_hash(apk_path):
    try:
        # Open,close, read file and calculate MD5 on its contents
        with open(apk_path, "rb") as apk_to_hash:
            # read contents of the file
            data = apk_to_hash.read()
            # pipe contents of the file through
            apk_dict[apk_md5] = hashlib.md5(data).hexdigest()
            apk_dict[apk_sha1] = hashlib.sha1(data).hexdigest()
            apk_dict[apk_sha256] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        global log
        exception = "Hash Error for: " + apk_path + "\n" + str(e)
        print(exception)
        log += exception


def get_vt_avclass(apk_path, md5_hash):
    try:
        if md5_hash != "":
            vt_report_file = os.path.join(vt_report_dir, md5_hash + ".json")
            if os.path.exists(vt_report_file):
                with open(vt_report_file) as vt_json:
                    vt_data = json.load(vt_json)
                    apk_dict[vt_count] = vt_data["positives"]
                if apk_dict[vt_count] > 0:
                    args = Namespace(
                        alias='./data/default.aliases',
                        aliasdetect=False, av=None, eval=False, fam=False,
                        gen='./data/default.generics',
                        gendetect=False, gt=None, hash=None, lb=None, lbdir=None, pup=False, verbose=False,
                        vt=[vt_report_file], vtdir=None)
                    apk_dict[avclass] = avclass_labeler.main(args)
                else:
                    apk_dict[avclass] = "NoAVClass"
    except Exception as e:
        global log
        exception = "VT_avclass Error for: " + apk_path + "\n" + str(e)
        print(exception)
        log += exception


def get_build_prop():
    item_count = len(build_prop_table)
    file_name = os.path.join(build_prop_dir, apk_dict[firm_name])
    if not os.path.exists(file_name):
        file_name = os.path.join(build_prop_dir, apk_dict[firm_name].split('.')[0])
        if not os.path.exists(file_name):
            return False
    try:
        with open(file_name, "r") as fin:
            for line in fin:
                line = line.rstrip()
                if "ro.build.id" in line:
                    apk_dict[build_id] = line.split("=")[1]
                    item_count -= 1
                elif "ro.build.version.release" in line:
                    apk_dict[build_version] = line.split("=")[1]
                    item_count -= 1
                elif "ro.build.date=" in line:
                    try:
                        dt_str = line.split("=")[1]
                        # Tue Oct 18 16:45:14 CST 2016
                        # 'September 18, 2017, 22:19:55'
                        # new_dt_str = dt_str[1] + " " + dt_str[2] + ", " + dt_str[5] + ", " + dt_str[3]
                        apk_dict[build_date] = parse(dt_str)  # .strftime("%Y-%m-%d %H:%M:%S")
                    except Exception as e1:
                        print("Error in date format: " + str(e1))
                        try:
                            dt_str = line.split("=")[1].split()
                            # 2018年 04月 24日 星期二 18:07:30 CST
                            # 'September 18, 2017, 22:19:55'
                            new_dt_str = dt_str[0][0:4] + "-" + dt_str[1][0:2] + "-" + dt_str[2][0:2] + " " + dt_str[4]
                            apk_dict[build_date] = parse(new_dt_str)  # .strftime("%Y-%m-%d %H:%M:%S")
                        except Exception as e2:
                            print("Error again in date format: " + str(e2))
                            year = re.search(r'\d{4}', line).group()
                            date_str = year + "-01-01 00:00:00"
                            apk_dict[build_date] = parse(date_str)  # .strftime("%Y-%m-%d %H:%M:%S")
                    finally:
                        item_count -= 1
                elif "ro.product.model" in line:
                    apk_dict[build_model] = line.split("=")[1]
                    item_count -= 1
                elif "ro.product.brand" in line:
                    apk_dict[build_brand] = line.split("=")[1]
                    item_count -= 1
                elif "ro.product.manufacturer" in line:
                    apk_dict[build_manufacturer] = line.split("=")[1]
                    item_count -= 1
                elif "ro.build.display.id" in line:
                    apk_dict[build_display_id] = line.split("=")[1]
                    item_count -= 1
                elif "ro.build.fingerprint" in line:
                    apk_dict[build_fingerprint] = line.split("=")[1]
                elif item_count == 0:
                    break
    except Exception as ex:
        print("Exception: " + str(ex))
    finally:
        return True


def get_apk_info(apk_path, cert_destination, apk_source):
    cert_path = extract_cert_from_apk(apk_path, cert_destination, apk_source)
    global log
    if cert_path is not None:
        parse_cert(cert_path, apk_cert_dict)

    get_manifest_info(apk_path)
    get_vt_avclass(apk_path, apk_dict[apk_md5])
    apk_dict[timestamp] = os.path.getmtime(apk_path)
    apk_dict[size] = os.path.getsize(apk_path)
    apk_dict[source] = apk_source
    apk_dict[apk_filename] = os.path.basename(apk_path)
    if apk_source == "firmware":
        apk_path_list = apk_path.split(os.sep)
        index = 9
        pds = ["/others/"]
        if any(pd in apk_path for pd in pds):
            index += 1
        apk_dict[extract_dir] = "/" + "/".join(apk_path_list[1:index+1])
        # print(apk_dict[extract_dir])
        apk_dict[firm_name] = apk_path_list[index]
        apk_dict[apk_filepath] = "/system/" + "/".join(apk_path_list[index+1:])
        with open(firm_sys_hash_file, 'r') as fin:
            for line in fin:
                if apk_dict[firm_name] in line:
                    items = line.rstrip().split(',')
                    apk_dict[firm_md5] = items[0]
                    apk_dict[system_md5] = items[1]


def get_apk_names(position_file, file_path):
    global start
    with open(position_file, "r") as fpos:
        start, count = (int(val) for val in fpos.read().splitlines())
        end = int(start) + int(count)

    with open(file_path) as fin:
        apk_names = [line.rstrip() for line in fin.readlines()[start:end]]
        if len(apk_names) == 0:
            print("******************completed*******************")

    return apk_names


def collect_play_cert_info(apk_names_path, apk_dir, cert_destination):
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    count = 0
    global start
    # Loop through each apk file in the apk_dir and collect certificate info
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            apk_names = get_apk_names(apk_pos_file, apk_names_path)

            for apk_file in apk_names:
                if apk_file.endswith(".apk"):
                    apk_path = os.path.join(apk_dir, apk_file)
                    print(str(start) + " : " + str(count) + " -> " + apk_path)
                    if not os.path.exists(apk_path):
                        print("Apk path doesn't exist")
                        break
                    initialize_dicts()
                    # get_apk_info(apk_path, cert_destination, "play-store")
                    insert_apk_info_into_db(db_connection, apk_path, cert_destination, "play-store")
                count = count + 1
                start = start + 1

        else:
            print('db_connection failed.')

    except Error as error:
        print(error)

    finally:
        if db_connection is not None:
            db_connection.close()
            print('db_connection closed.')
            with open(apk_pos_file, "w") as fpos:
                fpos.write("%d\n%d" % (start, count))
            global log
            with open(apk_crawler_log, "a+") as login:
                login.write(log + '\n')


def collect_firmware_cert_info(apk_names_path, cert_destination):
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    count = 0
    global start
    # Loop through each apk file in the apk_dir and collect certificate info
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            apk_hash_paths = get_apk_names(apk_pos_file, apk_names_path)
            for apk_hash_path in apk_hash_paths:
                initialize_dicts()
                path = apk_hash_path.split('  ')[-1]
                print(str(start) + " : " + str(count) + " -> " + path)
                if not os.path.exists(path):
                    print("Apk path doesn't exist")
                    break
                # get_apk_info(apk_path, cert_destination, "firmware")
                insert_apk_info_into_db(db_connection, path, cert_destination, "firmware")
                count = count + 1
                start = start + 1

        else:
            print('db_connection failed.')

    except Error as error:
        print(error)

    finally:
        if db_connection is not None:
            db_connection.close()
            print('db_connection closed.')
            with open(apk_pos_file, "w") as fpos:
                fpos.write("%d\n%d" % (start, count))
            global log
            with open(apk_crawler_log, "a+") as login:
                login.write(log + '\n')


if __name__ == "__main__":
    app_source = "firmware"

    if app_source == "play-store":
        apk_names_file = os.path.expanduser('~/Documents/Myworkspace/apksfilenames.txt')
        apk_directory = os.path.expanduser('~/Documents/apks/')
        # dest_cert_dir = os.path.expanduser('~/Documents/firmwares/play_apk_certs/')
        dest_cert_dir = os.path.expanduser('~/Documents/TestDir/certs/')
        collect_play_cert_info(apk_names_file, apk_directory, dest_cert_dir)

    elif app_source == "firmware":
        # apk_names_file = os.path.expanduser('firmware/samsung_apk_hash_path.txt')
        # dest_cert_dir = os.path.expanduser('~/Documents/bal/certs/')
        apk_names_file = os.path.expanduser('~/Projects/apk_extractor/batch2_apk_hashes.txt')
        dest_cert_dir = os.path.expanduser('~/Documents/firmwares/firmwareNAS/bip/certextract/')
        collect_firmware_cert_info(apk_names_file, dest_cert_dir)
    sys.exit(0)
