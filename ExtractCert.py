#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OpenSSL.crypto import load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey
from OpenSSL.crypto import TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1, load_pkcs7_data
from Crypto.Util.asn1 import (DerSequence, DerObject)
from datetime import datetime
import textwrap
from OpenSSL.crypto import _lib, _ffi, X509
from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config
from zipfile import ZipFile, BadZipFile
from apkutils import APK
import hashlib
import sys
import os

cert_info_query = "insert into apk_info (`pkg_name`,`version_code`,`category`,`rating`,`downloads`,`signature_algorithm`," \
                  "`pub_key_size`,`pub_modulus`,`pub_exponent`,`hash`,`source`, `md5_fingerprint`, `sha1_fingerprint`, " \
                  "`sha256_fingerprint`) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"

cert_dn_info_query = "insert into cert_dn (`pkg_name`,`dn_type`,`country`,`state`,`locality`," \
                     "`organization`,`organizational_unit`,`common_name`,`apk_info_id`) values (%s,%s,%s,%s,%s,%s,%s,%s,%s)"

firmware_info_query = "insert into firmware_info (`pkg_name`,`manufacturer`,`firmware_name`,`type`, `apk_info_id`)" \
                      " values (%s,%s,%s,%s,%s)"

log = "log starts here.\n"
start = None


def format_subject_issuer(x509name, cert_dict, actor):
    items = []
    actor_dict = {"C":"","ST":"","L":"","O":"","OU":"","CN":""}
    try:
        for item in x509name.get_components():
            tag = item[0].decode("utf-8")
            value = item[1].decode("utf-8")
            actor_dict[tag] = value
            items.append('%s=%s' % (tag, value))
    except UnicodeDecodeError as error:
        global log
        exception = "UnicodeDecodeError for: " + cert_dict['cert_file_path'] + "\n" + str(error)
        print(exception)
        log += exception
    finally:
        cert_dict[actor] = actor_dict

    return ", ".join(items)


def format_split_bytes(aa):
    bb = aa[1:] if len(aa) % 2 == 1 else aa  # force even num bytes, remove leading 0 if necessary
    return ':'.join(bb[i:i + 2] for i in range(0, len(bb), 2))
    # out = format(':'.join(s.encode('hex').lower() for s in bb.decode('hex')))
    # return out
    # return str(aa)


def format_split_int(serial_number):
    aa = "0%x" % serial_number  # add leading 0
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


def get_modulus_and_exponent(x509, cert_dict):
    if x509.get_pubkey().type() == TYPE_RSA:
        pub_der = DerSequence()
        pub_der.decode(dump_privatekey(FILETYPE_ASN1, x509.get_pubkey()))
        modulus = "%s:%s" % (format_split_int(pub_der._seq[0]), format_split_int(pub_der._seq[1]))
        cert_dict['pub_modulus'] = modulus
        exponent = pub_der._seq[2]
        cert_dict['pub_exponent'] = exponent
        return [modulus, exponent]
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


def parse_cert(cert_file):
    cert_dict = {'cert_file_path': os.path.abspath(cert_file)}
    with open(cert_file, 'rb+') as f:
        cert_pem = f.read()
        f.close()

        pkcs7 = load_pkcs7_data(FILETYPE_ASN1, cert_pem)
        x509 = get_certificates(pkcs7)[0]
        # x509 = load_certificate(FILETYPE_PEM, cert_pem)

        # print("Certificate:")
        # print("    Data:")

        cert_dict['version'] = int(x509.get_version() + 1)
        # print("        Version: %s (0x%x)" % (cert_dict['version'], x509.get_version()))

        # print("        Serial Number:")
        cert_dict['serial_number'] = format_split_int(x509.get_serial_number())
        # print("            %s" % cert_dict['serial_number'])

        cert_dict['signature_algorithm'] = x509.get_signature_algorithm().decode("utf-8")
        # print("    Signature Algorithm: %s" % cert_dict['signature_algorithm'])

        issuer = format_subject_issuer(x509.get_issuer(), cert_dict, "issuer")
        # print("    Issuer: %s" % issuer)

        # print("    Validity")
        cert_dict['not_before'] = format_asn1_date(x509.get_notBefore())
        # print("        Not Before: %s" % cert_dict['not_before'])
        cert_dict['not_after'] = format_asn1_date(x509.get_notAfter())
        # print("        Not After : %s" % cert_dict['not_after'])

        subject = format_subject_issuer(x509.get_subject(), cert_dict, "subject")
        # print("    Subject: %s" % subject)
        # print("    Subject Public Key Info:")

        if issuer == subject:
            cert_dict["dn_type"] = "both"
        else:
            cert_dict["dn_type"] = "issuer"

        pkey_lines = []
        keytype = x509.get_pubkey().type()
        keytype_list = {TYPE_RSA: 'rsaEncryption', TYPE_DSA: 'dsaEncryption', 408: 'id-ecPublicKey'}
        key_type_str = keytype_list[keytype] if keytype in keytype_list else 'other'

        cert_dict['pub_key_algorithm'] = key_type_str
        pkey_lines.append("        Public Key Algorithm: %s" % key_type_str)

        cert_dict['pub_key_size'] = x509.get_pubkey().bits()
        pkey_lines.append("            Public-Key: (%s bit)" % cert_dict['pub_key_size'])
        if x509.get_pubkey().type() == TYPE_RSA:
            modulus, exponent = get_modulus_and_exponent(x509, cert_dict)
            formatted_modulus = "\n                ".join(textwrap.wrap(modulus, 45))
            pkey_lines.append("            Modulus:")
            pkey_lines.append("                %s" % formatted_modulus)
            pkey_lines.append("            Exponent %d (0x%x)" % (exponent, exponent))
        # print("\n".join(pkey_lines))

        # print("        X509v3 extensions:")
        for i in range(x509.get_extension_count()):
            critical = 'critical' if x509.get_extension(i).get_critical() else ''
            item = x509.get_extension(i).get_short_name().decode("utf-8")
            val = x509.get_extension(i).__str__()
            if item == 'subjectKeyIdentifier':
                cert_dict['subjectKeyIdentifier'] = val
            # elif item == 'authorityKeyIdentifier':
            #     cert_dict['authorityKeyIdentifier'] = val
            # print("             x509v3 %s: %s" % (item, critical))
            # print("                 %s" % val)

        # print("    Signature Algorithm: %s" % x509.get_signature_algorithm().decode("utf-8"))
        cert_dict['signature'] = ':'.join(format(x, '02x') for x in get_signature_bytes(x509))
        sig_formatted = "\n         ".join(textwrap.wrap(cert_dict['signature'], 54))
        # print("         %s" % sig_formatted)

        cert_dict['md5_fingerprint'] = x509.digest('md5').decode("utf-8")
        # print("    Thumbprint MD5:    %s" % cert_dict['md5_fingerprint'])
        cert_dict['sha1_fingerprint'] = x509.digest('sha1').decode("utf-8")
        # print("    Thumbprint SHA1:   %s" % cert_dict['sha1_fingerprint'])
        cert_dict['sha256_fingerprint'] = x509.digest('sha256').decode("utf-8")
        # print("    Thumbprint SHA256: %s" % cert_dict['sha256_fingerprint'])

    return cert_dict


def insert_cert_info_into_db(db_connection, apk_dict):
    cursor = None

    try:
        cursor = db_connection.cursor()
        cert_info_args = (apk_dict["pkg_name"], apk_dict["version_code"], "", "", "",
                          apk_dict['signature_algorithm'],
                          apk_dict['pub_key_size'], apk_dict['pub_modulus'], apk_dict['pub_exponent'], apk_dict["md5_hash"],
                          apk_dict["source"], apk_dict['md5_fingerprint'], apk_dict['sha1_fingerprint'], apk_dict['sha256_fingerprint'])
        cursor.execute(cert_info_query, cert_info_args)

        cert_info_id = cursor.lastrowid
        cert_dn_info_args = (apk_dict["pkg_name"], apk_dict["dn_type"], apk_dict["issuer"]["C"], apk_dict["issuer"]["ST"],
                             apk_dict["issuer"]["L"],
                             apk_dict["issuer"]["O"], apk_dict["issuer"]["OU"], apk_dict["issuer"]["CN"],
                             cert_info_id)
        cursor.execute(cert_dn_info_query, cert_dn_info_args)

        if apk_dict["dn_type"] == "issuer":
            cert_dn_info_args = (apk_dict["pkg_name"], "subject", apk_dict["subject"]["C"], apk_dict["subject"]["ST"],
                                 apk_dict["subject"]["L"],
                                 apk_dict["subject"]["O"], apk_dict["subject"]["OU"], apk_dict["subject"]["CN"], cert_info_id)
            cursor.execute(cert_dn_info_query, cert_dn_info_args)

        if apk_dict["source"] == 'firmware':
            firmware_info_args = (apk_dict["pkg_name"], apk_dict["manufacturer"], apk_dict["firmware_name"],
                                  apk_dict["type"], cert_info_id)
            cursor.execute(firmware_info_query, firmware_info_args)

        db_connection.commit()

    except Error as error:
        print(error)

    finally:
        if cursor is not None:
            cursor.close()


# def insert_all_certificate(db_connection, dir_name, manifest_dict):
#     cursor = None
#
#     try:
#         cursor = db_connection.cursor()
#         directory = os.fsencode(dir_name)
#         for file in os.listdir(directory):
#             file_name = os.fsdecode(file)
#             if file_name.endswith(".RSA"):
#                 apk_path = os.path.join(dir_name, file_name)
#                 apk_dict = parse_cert(apk_path)
#                 # print(apk_dict)
#                 cert_info_args = (manifest_dict["@package"], manifest_dict['@android:versionCode'], "unknown", "3.78",
#                                   "10008", apk_dict['signature_algorithm'],
#                         apk_dict['pub_key_size'], apk_dict['pub_modulus'], apk_dict['pub_exponent'], "dfgdtgdfb",
#                         "play-store")
#                 cursor.execute(cert_info_query, cert_info_args)
#
#                 cert_info_id = cursor.lastrowid
#                 cert_dn_info_args = (manifest_dict["@package"], "both", apk_dict["issuer"]["C"], apk_dict["issuer"]["ST"],
#                                      apk_dict["issuer"]["L"], apk_dict["issuer"]["O"], apk_dict["issuer"]["OU"],
#                                      apk_dict["issuer"]["CN"], cert_info_id)
#                 cursor.execute(cert_dn_info_query, cert_dn_info_args)
#
#                 firmware_info_args = (manifest_dict["@package"], "Huwaei", "some firmware name", "some mode", "1", cert_info_id)
#                 cursor.execute(firmware_info_query, firmware_info_args)
#         db_connection.commit()
#
#     except Error as error:
#         print(error)
#
#     finally:
#         if cursor is not None:
#             cursor.close()
#         db_connection.close()
#         print('db_connection closed.')


def extract_cert_from_apk(apk_path, destination, apk_source):
    if apk_source == "firmware":
        apk_path_list = apk_path.split(os.sep)
        if len(apk_path_list) >= 4:
            destination = os.path.join(destination, apk_path_list[-3], apk_path_list[-2])

    rsa_file = os.path.join(destination, os.path.splitext(os.path.basename(apk_path))[0] + ".RSA")
    os.makedirs(os.path.dirname(rsa_file), exist_ok=True)
    try:
        apk_zip = ZipFile(apk_path)
        for file in apk_zip.namelist():
            if file.endswith(".RSA"):
                file_data = apk_zip.read(file)
                with open(rsa_file, "wb") as fout:
                    fout.write(file_data)
                return rsa_file
    except BadZipFile:
        global log
        exception = "File is not a zip file: " + os.path.basename(apk_path) + "\n"
        print(exception)
        log += exception

    return None


def get_apk_info(apk_path, cert_destination, apk_source):
    cert_path = extract_cert_from_apk(apk_path, cert_destination, apk_source)
    global log
    if cert_path is None:
        exception = "RSA doesn't exist in: " + os.path.basename(apk_path) + "\n"
        print(exception)
        log += exception
        return None

    apk_dict = parse_cert(cert_path)
    apk_dict["pkg_name"] = ""
    apk_dict["version_code"] = ""
    try:
        apk = APK(apk_path)
        manifest_dict = apk.get_manifest()
        apk_dict["pkg_name"] = manifest_dict["@package"]
        apk_dict["version_code"] = manifest_dict["@android:versionCode"]
    except KeyError as error:
        exception = "KeyError for: " + apk_path + "\n" + str(error)
        print(exception)
        log += exception

    # Open,close, read file and calculate MD5 on its contents
    with open(apk_path, "rb") as apk_to_hash:
        # read contents of the file
        data = apk_to_hash.read()
        # pipe contents of the file through
        apk_dict["md5_hash"] = hashlib.md5(data).hexdigest()

    apk_dict["source"] = apk_source
    if apk_source == "firmware":
        apk_path_list = apk_path.split(os.sep)
        if len(apk_path_list) >= 4:
            apk_dict["manufacturer"] = apk_path_list[-4]
            apk_dict["firmware_name"] = apk_path_list[-3]
            apk_dict["type"] = apk_path_list[-2]

    return apk_dict


def get_apk_names(file_path):
    global start
    with open("play_apk_position.txt", "r") as fpos:
        start, count = (int(val) for val in fpos.read().splitlines())
        end = int(start) + int(count)
        # fpos.seek(0)
        # fpos.write("%d\n%d" % (end, count))

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
    # Loop through each apk file in the apk_dir and collect certificate info
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            apk_names = get_apk_names(apk_names_path)

            for apk_file in apk_names:
                if apk_file.endswith(".apk"):
                    apk_path = os.path.join(apk_dir, apk_file)
                    print("Current: %s..." % apk_path)
                    apk_dict = get_apk_info(apk_path, cert_destination, "play-store")
                    if apk_dict is not None:
                        insert_cert_info_into_db(db_connection, apk_dict)
                count = count+1

        else:
            print('db_connection failed.')

    except Error as error:
        print(error)

    finally:
        if db_connection is not None:
            db_connection.close()
            print('db_connection closed.')
            global start
            start = start+count
            with open("play_apk_position.txt", "w") as fpos:
                fpos.write("%d\n%d" % (start, count))
            global log
            with open("log.txt", "a+") as login:
                login.write(log + '\n')


def load_firmware_apk_names(firmware_dir):
    apk_paths = []
    for path, dirs, files in os.walk(firmware_dir):
        for apk_file in files:
            if apk_file.endswith(".apk"):
                apk_paths.append(os.path.join(path, apk_file))

    return apk_paths


def get_apk_paths_to_parse(firmware_dir, manufacturer_name):
    file_name = manufacturer_name + ".txt"
    with open(file_name, "r") as firm_in:
        done_apk_paths = [line.rstrip() for line in firm_in.readlines()]
    all_apk_paths = load_firmware_apk_names(firmware_dir)
    remaining = set(all_apk_paths).difference(set(done_apk_paths))
    return list(remaining)


def collect_firmware_cert_info(apk_dir, manufacturer, cert_destination):
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    done_apk_paths = []
    # Loop through each apk file in the apk_dir and collect certificate info
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            apk_paths = get_apk_paths_to_parse(apk_dir, manufacturer)

            for apk_path in apk_paths:
                apk_dict = get_apk_info(apk_path, cert_destination, "firmware")
                if apk_dict is not None:
                    # insert_cert_info_into_db(db_connection, apk_dict)
                    done_apk_paths.append(apk_path)

        else:
            print('db_connection failed.')

    except Error as error:
        print(error)

    finally:
        if db_connection is not None:
            db_connection.close()
            print('db_connection closed.')
            if len(done_apk_paths) != 0:
                file_name = manufacturer + ".txt"
                with open(file_name, "a+") as firm_in:
                    firm_in.write('\n'.join(done_apk_paths) + '\n')
            global log
            with open("log.txt", "a+") as login:
                login.write(log + '\n')


if __name__ == "__main__":
    # os.chdir(sys.path[0])
    # parse_cert(sys.argv[1])
    # parse_cert("/home/biplob/Academic/Research/APK_certificate_workspace/apk_cert_extractor/apks/META-INF/CERT.RSA")

    app_source = "play-store"

    # print(get_apk_info("/home/biplob/Documents/apks/com.djxp.troid.apk", "/home/biplob/Documents/TestDir/", "test"))
    if app_source == "play-store":
        apk_names_file = os.path.expanduser('~/Documents/Myworkspace/apksfilenames.txt')
        # '/home/biplob/Documents/TestDir/apk_names.txt'
        # apk_directory = '/home/biplob/Academic/Research/APK_certificate_workspace/apks/'
        apk_directory = os.path.expanduser('~/Documents/apks/')
        dest_cert_dir = os.path.expanduser('~/Documents/firmwares/play_apk_certs/')
        collect_play_cert_info(apk_names_file, apk_directory, dest_cert_dir)
    else:
        manufacturer = "Advan"
        apk_directory = os.path.expanduser('~/Documents/firmwares/apps/Advan/')
        dest_cert_dir = os.path.expanduser('~/Documents/firmwares/certs/Advan/')
        collect_firmware_cert_info(apk_directory, manufacturer, dest_cert_dir)

    #print("Hello ,it works!")
    sys.exit(0)
