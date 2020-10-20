from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config
import hashlib
import mmap
import glob
import os

idpos_query = "select hash from apk_info where id>=1572483"
firmware_name_query = "select distinct name from firmware"


def collect_firmware_names():
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    cursor = None
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            cursor = db_connection.cursor()
            cursor.execute(firmware_name_query)
            rows = cursor.fetchall()

            with open("available_firmware_names.txt", "a+") as fout:
                for row in rows:
                    print(row[0])
                    fout.write(row[0] + "\n")
        else:
            print('db_connection failed.')

    except Error as error:
        print(error)

    finally:
        if cursor is not None:
            cursor.close()
        if db_connection is not None:
            db_connection.close()
            print('db_connection closed.')


def collect_firmware_hashes():
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    cursor = None
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            cursor = db_connection.cursor()
            cursor.execute(idpos_query)
            rows = cursor.fetchall()

            with open("hashes.txt", "a+") as fout:
                for row in rows:
                    print(row[0])
                    fout.write(row[0] + "\n")
        else:
            print('db_connection failed.')
         
    except Error as error:
        print(error)

    finally:
        if cursor is not None:
            cursor.close()
        if db_connection is not None:
            db_connection.close()
            print('db_connection closed.')


def collect_hashes_from_apks(apk_path_file):
    with open(apk_path_file, "r") as path_file:
        apk_paths = [line.rstrip() for line in path_file.readlines()]
    count = 1

    try:
        with open("all_hashes.txt", "a+") as fin, open("missing_path_hash.txt", "a+") as miss_fin, open("vt_missed_hashes.txt", "rb", 0) as miss_hash_file:
            s = mmap.mmap(miss_hash_file.fileno(), 0, access=mmap.ACCESS_READ)
            for apk_path in apk_paths:
                # Open,close, read file and calculate MD5 on its contents
                try:
                    with open(apk_path, "rb") as apk_to_hash:
                        # read contents of the file
                        data = apk_to_hash.read()
                        # pipe contents of the file through
                        md5_hash = hashlib.md5(data).hexdigest()
                        fin.write(md5_hash + " , " + apk_path  + "\n")
                        if s.find(bytes(md5_hash, encoding= 'utf-8')) != -1:
                            miss_fin.write(md5_hash + "," + apk_path  + "\n")
                        print(str(count))
                        count = count+1
                except Exception as e:
                    with open("no_hashes.txt", "a+") as no_hash_fin:
                        no_hash_fin.write(apk_path + "\n")
                    print("Something went wrong!: " + str(e))
    except Exception as p:
        print("Exception: " + str(p))
    finally:
        s.close()


def generate_apk_hash():
    for src_apk_path in glob.glob("/home/lin.3021/Documents/firmwareNAS/bip/certextract/apps/batch2/**/*.apk", recursive=True):
        try:
            with open(src_apk_path, "rb") as apk_path, open("/home/lin.3021/Documents/Myworkspace/batch2_hashes.txt", "a+") as fin:
                data = apk_path.read()
                md5_hash = hashlib.md5(data).hexdigest()
                fin.write(md5_hash + " " + apk_path)
        except Exception as e:
            print(str(e))


def get_only_hash(src_file,dest_file):
    with open(src_file, 'r') as fin, open(dest_file, 'a+') as fout:
        for line in fin:
            md5_hash = line.split(',')[0]
            fout.write(md5_hash + '\n')


def find_missing_firm(src_file, firm_file, dest_file):
    with open(src_file, 'r') as src_fin, open(dest_file, 'a+') as dest_in:
        for src_line in src_fin:
            apk_path = src_line.split(' , ')[1]
            apk_path_list = apk_path.split(os.sep)
            index = 9
            if "/others/" in apk_path:
                index += 1
            parent_name = apk_path_list[index-1]
            firm_name = apk_path_list[index]
            isAvailable = False
            with open(firm_file, 'r') as firm_in:
                for line in firm_in:
                    if firm_name in line:
                        # print(firm_name + " >> " + line)
                        isAvailable = True
                        break
                if not isAvailable:
                    dest_in.write(parent_name + "," + firm_name + "\n")


def find_moto_firm_hashes(src_file, path_file, output_file):
    with open(src_file, 'r') as src_fin:
        firm_names = [line.rstrip() for line in src_fin]
    with open(path_file, 'r') as path_in:
        paths = [line.rstrip() for line in path_in]
    with open(output_file, 'a+') as out:
        for firm in firm_names:
            for path in paths:
                if firm in path:
                    #md5 = hashlib.md5()
                    #with open(path, "rb") as fin:
                    #    for chunk in iter(lambda: fin.read(4096), b""):
                    #        md5.update(chunk)
                    #hsh = md5.hexdigest() + " " + path
                    #out.write(hsh + "\n")
                    #print(hsh)
                    out.write(path+"\n")
                    break


if __name__ == "__main__":
    # collect_firmware_hashes()
    # collect_hashes_from_apks("all_firmware_apks.txt")
    # collect_firmware_names()
    # generate_apk_hash()
    # get_only_hash("/home/biplob/Documents/Myworkspace/remote/huawei_apk_hash_path_partial.txt", "huawei_apk_md5_hashes_partial.txt")
    # find_missing_firm("batch1_apk_hashes.txt", "batch1_firm_sys_hash.txt", "missed_batch1_firms.txt")
    find_moto_firm_hashes("lg_extracted.txt", "lg_path.txt", "firmware/batch3_firm_paths.txt")
