#!/usr/bin/env python
# -*- coding: utf-8 -*-
import zipfile
import rarfile
import glob
import os
import shutil
import subprocess
import re
import hashlib
import sdat2img

destination_dir = os.path.expanduser("~/Documents/firmwareNAS/bip/certextract")
# destination_dir = os.path.expanduser("~/Documents/firmwares")
firm_apk_hash_path = "huawei_apk_hash_path.txt"
firm_hash_file = "huawei_sys_hash.txt"
source_path_file = "huawei_firm_paths.txt"
logger_file = "huawei_extraction_log.txt"
firm_pos = "huawei_firm_pos.txt"
start = None

unknown = -1
success = 0
unpack_error = 1
image_absent_error = 2
mount_error = 3
prop_absent_error = 4
already_unpacked = 5
message = {success: "Success",
           unpack_error: "Could not unpack initial file",
           image_absent_error: "Could not find system image file",
           mount_error: "Could not mount",
           prop_absent_error: "Did not find build.prop",
           already_unpacked: "Already unpacked"}

system_image = "system*.img*"
system_new_dat = "system.new.dat"
system_transfer_list = "system.transfer.list"
system_sparse_chunk = "system.img_sparsechunk*"
source = "Firmwirefile_premium"
manufacturer = "Huawei"
password = "Autumn_2018!"
wd = manufacturer
wd_path = wd + "/**/"


def get_path(root_dir, basename):
    path_to_search = os.path.join(root_dir, basename)
    for path in glob.iglob(path_to_search, recursive=True):
        return path
    return None


def unpack_zip_file():
    sys_dir = get_path(wd_path, "system")
    if sys_dir is not None:
        return True

    home_path = get_path(wd_path, "*HOME.tar.md5")
    if home_path is not None:
        subprocess.call("tar -xf " + home_path.replace(' ', '\\ ') + " -C ./" + wd + "/", shell=True)
        os.remove(home_path)
        return True

    meta_path = get_path(wd_path, "*meta.tar.md5")
    if meta_path is not None:
        subprocess.call("tar -xf " + meta_path.replace(' ', '\\ ') + " -C ./" + wd + "/", shell=True)
        os.remove(meta_path)
        return True

    uapp_path = get_path(wd_path, "*.APP")
    if uapp_path is not None:
        os.chdir(wd)
        uapp_path = uapp_path.replace(wd + "/", "")
        subprocess.call("../splituapp -f " + uapp_path.replace(' ', '\\ ') + " -l system", shell=True)
        os.remove(uapp_path)
        os.chdir("..")
        return True

    kdz_path = get_path(wd_path, "*.kdz")
    if kdz_path is not None:
        os.chdir(wd)
        kdz_path = kdz_path.replace(wd + "/", "")
        subprocess.call("python ../unkdz.py -f " + kdz_path.replace(' ', '\\ ') + " -x;"
                        + "python ../undz.py -f kdzextracted/*.dz -x;"
                        + "python ../mergersystem.py", shell=True)
        os.remove(kdz_path)
        os.chdir("..")
        return True

    rar_path = get_path(wd_path, "*.rar")
    if rar_path is not None:
        with rarfile.RarFile(rar_path, 'r') as rar_file:
            rar_file.extractall(wd)
        os.remove(rar_path)
        return True

    zip_path = get_path(wd_path, "*.zip")
    if zip_path is not None:
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            zip_file.extractall(wd)
        os.remove(zip_path)
        return True

    return False


def unsparse_and_mount(image_type, image_path):
    sparse_code = subprocess.call("./simg2img " + image_path + " " + wd + "/system.raw", shell=True)
    os.makedirs(wd + "/system", exist_ok=True)
    if image_type == system_sparse_chunk:
        dd_code = subprocess.call("mv " + wd + "/system.raw " + wd + "/system.img.raw; "
                        "offset=$(LANG=C grep -aobP -m1 '\\x53\\xEF' " + wd + "/system.img.raw | head -1 | gawk '{print $1 - 1080}'); "
                        "dd if=" + wd + "/system.img.raw of=" + wd + "/system.raw ibs=$offset skip=1 2>&1", shell=True)
        if dd_code != 0:
            subprocess.call("mv " + wd + "/system.img.raw " + wd + "/system.raw", shell=True)

    if sparse_code == 0:
        mount_code = subprocess.call(
            "echo '" + password + "' | sudo -S mount -t ext4 -o loop " + wd + "/system.raw "
            + wd + "/system", shell=True)
    else:
        mount_code = subprocess.call(
            "echo '" + password + "' | sudo -S mount -t ext4 -o loop " + image_path +
            " " + wd + "/system", shell=True)

    if mount_code == 0:
        return success
    else:
        return mount_error


def check_for_new_dat():
    try:
        transfer_list_path = get_path(wd_path, system_transfer_list)
        new_dat_path = get_path(wd_path, system_new_dat)
        if transfer_list_path is not None and new_dat_path is not None:
            system_image_path = wd + "/system.img"
            sdat2img.main(wd + "/" + system_transfer_list, wd + "/" + system_new_dat, system_image_path)
            return system_new_dat, system_image_path
    except Exception as err:
        print("Error in sdat2img: " + str(err))

    return None, None


def check_for_sparse_chunk():
    sparse_chunks = []
    for filename in glob.iglob(wd_path + system_sparse_chunk, recursive='true'):
        sparse_chunks.append(filename)
    if len(sparse_chunks) != 0:
        system_image_path = ' '.join(sparse_chunks)
        return system_sparse_chunk, system_image_path
    else:
        return None, None


def get_hash(file_path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as fin:
        for chunk in iter(lambda: fin.read(4096), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    hash_val = {'md5': md5.hexdigest(), 'sha1': sha1.hexdigest(), 'sha256': sha256.hexdigest()}
    return hash_val


def extract_system_image(firmware_path, dest_dir):
    firm_hash = get_hash(firmware_path)
    with open(firm_hash_file, "r") as firm_in:
        for line in firm_in:
            if firm_hash['md5'] in line:
                return already_unpacked

    if not os.path.exists(wd):
        os.makedirs(wd)
    firmware_name = os.path.basename(firmware_path)
    app_dest_dir = os.path.join(dest_dir, "apps", source, manufacturer, firmware_name)
    cert_dest_dir = os.path.join(dest_dir, "certs", source, manufacturer, firmware_name)

    if zipfile.is_zipfile(firmware_path):
        with zipfile.ZipFile(firmware_path, 'r') as firm_zip:
            firm_zip.extractall(wd)
        unpack_zip_file()
    elif rarfile.is_rarfile(firmware_path):
        with rarfile.RarFile(firmware_path, 'r') as firm_rar:
            firm_rar.extractall(wd)
        unpack_zip_file()
    elif firmware_path.endswith(".kdz"):
        os.chdir(wd)
        subprocess.call("python ../unkdz.py -f " + firmware_path.replace(' ', '\\ ') + " -x;"
                        + "python ../undz.py -f kdzextracted/*.dz -x;"
                        + "python ../mergersystem.py", shell=True)
        os.chdir("..")
    else:
        return unpack_error

    sys_hash = {'md5': '', 'sha1': '', 'sha256': ''}
    mount_status = unknown
    image_type = None
    image_path = None
    while True:
        sys_dir = get_path(wd_path, "system")
        if sys_dir is not None:
            mount_status = success
            break
        else:
            image_type, image_path = check_for_new_dat()
            if image_path is None:
                image_type, image_path = check_for_sparse_chunk()
            if image_path is None:
                image_type = system_image
                image_path = get_path(wd_path, system_image)
            if image_path is not None:
                break
            if not unpack_zip_file():
                return image_absent_error

    try:
        if mount_status != success and image_type != system_sparse_chunk and os.path.exists(image_path):
            sys_hash = get_hash(image_path)
        mount_status = unsparse_and_mount(image_type, image_path)
    except Exception as ex:
        print("Error while Mounting: " + str(ex))
        return mount_error

    sys_dir = get_path(wd_path, "system")
    if mount_status == success and sys_dir is not None:
        if not os.path.exists(app_dest_dir):
            os.makedirs(app_dest_dir)
        if not os.path.exists(cert_dest_dir):
            os.makedirs(cert_dest_dir)
        try:
            if os.path.exists(wd + "/META-INF/CERT.RSA"):
                shutil.move(wd + "/META-INF/CERT.RSA", os.path.join(app_dest_dir, "CERT.RSA"))
            build_prop_path = get_path(sys_dir, "build.prop")
            if build_prop_path is not None:
                print(build_prop_path)
                subprocess.call("echo '" + password + "' | sudo cat " + build_prop_path + " > "
                                + os.path.join(app_dest_dir.replace(' ', '\\ '), "build.prop"), shell=True)
            default_prop_path = get_path(wd_path, "default.prop")
            if default_prop_path is not None:
                subprocess.call("echo '" + password + "' | sudo cat " + default_prop_path + " > "
                                + os.path.join(app_dest_dir.replace(' ', '\\ '), "default.prop"), shell=True)
        except Exception as ex:
            print(str(ex))

        with open(firm_apk_hash_path, "a+") as apk_hash_fin:
            for src_apk_path in glob.glob(sys_dir + "/**/*.apk", recursive=True):
                tail_apk_path = re.sub(r'.*system/', 'system/', src_apk_path)
                dest_apk_path = os.path.join(app_dest_dir, tail_apk_path)
                os.makedirs(os.path.dirname(dest_apk_path), exist_ok=True)
                shutil.copy(src_apk_path, dest_apk_path)

                apk_without_ext = os.path.splitext(os.path.basename(tail_apk_path))[0]
                odex_path = get_path(os.path.dirname(src_apk_path) + "/**/", apk_without_ext + ".odex")
                odex_hash = {'md5': '', 'sha1': '', 'sha256': ''}
                if odex_path is not None:
                    shutil.copy(odex_path, os.path.join(os.path.dirname(dest_apk_path), os.path.basename(odex_path)))
                    odex_hash = get_hash(odex_path)
                vdex_path = get_path(os.path.dirname(src_apk_path) + "/**/", apk_without_ext + ".vdex")
                if vdex_path is not None:
                    shutil.copy(vdex_path, os.path.join(os.path.dirname(dest_apk_path), os.path.basename(vdex_path)))

                apk_hash = get_hash(src_apk_path)
                apk_hash_fin.write(','.join(apk_hash.values()) + "," + ','.join(odex_hash.values()) + "," + dest_apk_path + "\n")

                try:
                    dest_rsa_path = os.path.join(cert_dest_dir, tail_apk_path)
                    dest_rsa_path = re.sub(r'.apk', '.RSA', dest_rsa_path)
                    os.makedirs(os.path.dirname(dest_rsa_path), exist_ok=True)
                    subprocess.call("echo '" + password + "' | sudo -S unzip -p " + src_apk_path + " *.RSA > " + dest_rsa_path.replace(' ', '\\ '), shell=True)
                except Exception as error:
                    print("Couldn't find RSA: " + str(error))
        try:
            with open(firm_hash_file, "a+") as hash_in:
                hash_in.write(','.join(firm_hash.values()) + ','
                              + ','.join(sys_hash.values()) + ',' + firmware_path + "\n")
        except Exception as er:
            print(str(er))
    return mount_status


def get_firm_names(position_file, file_path):
    global start
    with open(position_file, "r") as fpos:
        start, count = (int(val) for val in fpos.read().splitlines())
        end = int(start) + int(count)

    with open(file_path) as fin:
        firm_names = [line.rstrip() for line in fin.readlines()[start:end]]
        if len(firm_names) == 0:
            print("******************completed*******************")

    return firm_names


if __name__ == "__main__":
    done_count = 0
    count = 0

    firm_paths = get_firm_names(firm_pos, source_path_file)

    for source_firm_path in firm_paths:
        try:
            source_firm_path = source_firm_path.rstrip()
            print(str(start) + " : " + source_firm_path)
            status = extract_system_image(source_firm_path, destination_dir)
            if status == success:
                done_count = done_count + 1
            print("Done : " + str(done_count))
            with open(logger_file, "a+") as logger:
                logger.write(source_firm_path + " : " + message[status] + "\n")
            start = start + 1
            count = count + 1
            subprocess.call("echo '" + password + "' | sudo -S umount " + wd + "/system; rm -rf " + wd,
                            shell=True)
        except Exception as exc:
            print(str(exc))
        finally:
            with open(firm_pos, "w") as fpos:
                fpos.write("%d\n%d" % (start, count))
