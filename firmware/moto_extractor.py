#!/usr/bin/env python
# -*- coding: utf-8 -*-
import zipfile
import glob
import os
import shutil
import subprocess
import re
import hashlib
import rarfile

build_prop_dir = os.path.expanduser("~/Projects/file_data/build_props")


def extract_system_image(firmware_path, dest_dir):
    unzipped_dir = "unzipped_firm"
    firmware_path_list = os.path.splitext(firmware_path)[0].split(os.sep)
    firmware_name = firmware_path_list[-1]
    manufacturer_name = firmware_path_list[-2]
    batch_num = firmware_path_list[-3]
    app_dest_dir = os.path.join(dest_dir, "apps", batch_num, manufacturer_name, firmware_name)  # os.path.basename(firmware_path)
    cert_dest_dir = os.path.join(dest_dir, "certs", batch_num, manufacturer_name, firmware_name)

    if zipfile.is_zipfile(firmware_path):
        with zipfile.ZipFile(firmware_path, 'r') as firm_zip:
            firm_zip.extractall(unzipped_dir)
    elif rarfile.is_rarfile(firmware_path):
        with rarfile.RarFile(firmware_path, 'r') as firm_rar:
            firm_rar.extractall(unzipped_dir)
        for filename in glob.iglob("unzipped_firm/**/*.zip", recursive='true'):
            with zipfile.ZipFile(filename, 'r') as firm_zip:
                firm_zip.extractall(unzipped_dir)
                break
    else:
        return

    # search for system.img_sparsechunk.5
    sparse_chunks = []
    for filename in glob.iglob("unzipped_firm/**/system.img_sparsechunk*", recursive='true'):
        sparse_chunks.append(filename)

    mount_error_code = -1
    try:
        if len(sparse_chunks) != 0:
            chunk_str = ' '.join(sparse_chunks)
            sparse_error_code = subprocess.call("./simg2img " + chunk_str + " system.raw", shell=True)
            if sparse_error_code == 0:
                os.makedirs("unzipped_firm/mount_point", exist_ok=True)
                mount_error_code = subprocess.call("echo 'Autumn_2018!' | sudo -S mount -t ext4 -o loop system.raw "
                                                   "unzipped_firm/mount_point", shell=True)
        else:
            sys_path = None
            for filename in glob.iglob("unzipped_firm/**/system*.img", recursive='true'):
                sys_path = filename
                break
            if sys_path:
                print(sys_path)
                sparse_error_code = subprocess.call("./simg2img " + sys_path + " system.raw", shell=True)
                if sparse_error_code == 0:
                    os.makedirs("unzipped_firm/mount_point", exist_ok=True)
                    mount_error_code = subprocess.call(
                        "echo 'Autumn_2018!' | sudo -S mount -t ext4 -o loop system.raw "
                        "unzipped_firm/mount_point", shell=True)
                else:
                    os.makedirs("unzipped_firm/mount_point", exist_ok=True)
                    mount_error_code = subprocess.call(
                        "echo 'Autumn_2018!' | sudo -S mount -t ext4 -o loop " + sys_path +
                        " unzipped_firm/mount_point", shell=True)

    except Exception as e:
        print("Something went wrong: " + str(e))

    if mount_error_code == 0:
        if not os.path.exists(app_dest_dir):
            os.makedirs(app_dest_dir)
        if not os.path.exists(cert_dest_dir):
            os.makedirs(cert_dest_dir)
        try:
            if os.path.exists("unzipped_firm/META-INF/CERT.RSA"):
                shutil.move("unzipped_firm/META-INF/CERT.RSA", os.path.join(app_dest_dir, "CERT.RSA"))
            # if os.path.exists("unzipped_firm/mount_point/system/build.prop"):
            #     shutil.copy("unzipped_firm/mount_point/system/build.prop", os.path.join(build_prop_dir, firmware_name))
            subprocess.call("sudo cat unzipped_firm/mount_point/system/build.prop > " + os.path.join(build_prop_dir, firmware_name), shell=True)
        except Exception as ex:
            print(str(ex))

        for src_apk_path in glob.glob("unzipped_firm/mount_point/system/**/*.apk", recursive=True):
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
            subprocess.call("rm system.raw; sudo umount unzipped_firm/mount_point; rm -r unzipped_firm", shell=True)
        except Exception as er:
            print(str(er))


if __name__ == "__main__":
    source_dir = os.path.expanduser("~/Documents/firmwareNAS/AndroidFirmware/batch3/RIM")
    dest_dir = os.path.expanduser("~/Documents/firmwareNAS/bip/certextract")

    # source_dir = os.path.expanduser("~/Documents/bal/firms/motorola/firmware")
    # dest_dir = os.path.expanduser("~/Documents/firmwares")
    if not os.path.exists(build_prop_dir):
        os.makedirs(build_prop_dir)
    for firmware_file in os.listdir(source_dir):
        try:
            print(firmware_file)
            source_firm_path = os.path.join(source_dir, firmware_file)
            extract_system_image(source_firm_path, dest_dir)
        except Exception as e:
            print(str(e))
