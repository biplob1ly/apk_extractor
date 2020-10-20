#!/usr/bin/env python
# -*- coding: utf-8 -*-
import zipfile
import glob
import os
import shutil
import subprocess
import re
import hashlib
import sdat2img

build_prop_dir = os.path.expanduser("~/Projects/file_data/build_props")


def extract_system_image(firmware_path, dest_dir):
    unzipped_dir = "unzipped_firm"
    firmware_path_list = os.path.splitext(firmware_path)[0].split(os.sep)
    firmware_name = firmware_path_list[-1]
    manufacturer_name = firmware_path_list[-2]
    batch_num = firmware_path_list[-3]
    app_dest_dir = os.path.join(dest_dir, "apps", batch_num, manufacturer_name, firmware_name)  # os.path.basename(firmware_path)
    cert_dest_dir = os.path.join(dest_dir, "certs", batch_num, manufacturer_name, firmware_name)

    with zipfile.ZipFile(firmware_path, 'r') as firm_zip:
        firm_zip.extractall(unzipped_dir)

    for filename in glob.iglob("unzipped_firm/**/*.zip", recursive='true'):
        update_path = filename
        print(update_path)
        with zipfile.ZipFile(update_path, 'r') as update_zip:
            update_zip.extractall(unzipped_dir)
        break

    mount_error_code = -1

    if not os.path.exists("unzipped_firm/system"):
        try:
            sdat2img.main("unzipped_firm/system.transfer.list", "unzipped_firm/system.new.dat", "system.img")
            os.makedirs("unzipped_firm/system")
            mount_error_code = subprocess.call("echo 'Autumn_2018!' | sudo -S mount -t ext4 -o loop system.img unzipped_firm/system",  shell=True)
        except Exception as ex:
            print("Error in sdat2img: " + str(ex))
    else:
        mount_error_code = 0

    if mount_error_code == 0:
        if not os.path.exists(app_dest_dir):
            os.makedirs(app_dest_dir)
        if not os.path.exists(cert_dest_dir):
            os.makedirs(cert_dest_dir)
        try:
            if os.path.exists("unzipped_firm/META-INF/CERT.RSA"):
                shutil.move("unzipped_firm/META-INF/CERT.RSA", os.path.join(app_dest_dir, "CERT.RSA"))
            if os.path.exists("unzipped_firm/system/build.prop"):
                shutil.copy("unzipped_firm/system/build.prop", os.path.join(build_prop_dir, firmware_name))
        except Exception as ex:
            print(str(ex))

        for src_apk_path in glob.glob("unzipped_firm/system/**/*.apk", recursive=True):
            tail_apk_path = re.sub(r'.*system/', '', src_apk_path)
            dest_apk_path = os.path.join(app_dest_dir, tail_apk_path)
            os.makedirs(os.path.dirname(dest_apk_path), exist_ok=True)
            # print(src_apk_path + " -> " + dest_apk_path)
            shutil.copy(src_apk_path, dest_apk_path)
            try:
                dest_rsa_path = os.path.join(cert_dest_dir, tail_apk_path)
                dest_rsa_path = re.sub(r'.apk', '.RSA', dest_rsa_path)
                os.makedirs(os.path.dirname(dest_rsa_path), exist_ok=True)
                subprocess.call("unzip -p " + src_apk_path + " *.RSA > " + dest_rsa_path, shell=True)
            except Exception as e:
                print("Couldn't find RSA: " + str(e))
        try:
            with open(firmware_path, "rb") as firm_to_hash, open("batch3_hash.txt", "a+") as hash_in:
                # read contents of the file
                data = firm_to_hash.read()
                # pipe contents of the file through
                md5_hash = hashlib.md5(data).hexdigest()
                hash_in.write(md5_hash + " " + firmware_path + "\n")
            subprocess.call("rm system.img ; sudo umount unzipped_firm/system; rm -r unzipped_firm", shell=True)
        except Exception as er:
            print(str(er))


if __name__ == "__main__":
    source_dir = os.path.expanduser("~/Documents/firmwareNAS/AndroidFirmware/batch3/oppo") # "~/Documents/bal/firms/zte"
    dest_dir = os.path.expanduser("~/Documents/firmwareNAS/bip/certextract")

    for firmware_file in os.listdir(source_dir):
        try:
            print(firmware_file)
            source_firm_path = os.path.join(source_dir, firmware_file)
            extract_system_image(source_firm_path, dest_dir)
        except Exception as e:
            print(str(e))
