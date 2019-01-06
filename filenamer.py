from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config
import hashlib
import os
import sys

idpos_query = "select id,hash from apk_info where file_name is NULL limit 1"
fname_insert_query = """update apk_info set file_name = %s where id = %s"""
start = None
count = None


def get_apk_names(position_file, file_path):
    global start, count
    with open(position_file, "r") as fpos:
        start, count = (int(val) for val in fpos.read().splitlines())
        end = int(start) + int(count)

    with open(file_path) as fin:
        apk_names = [line.rstrip() for line in fin.readlines()[start:end]]
        if len(apk_names) == 0:
            print("******************completed*******************")

    return apk_names


def collect_file_name(apk_names_path, apk_dir):
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    cursor = None
    global start, count
    # Loop through each apk file in the apk_dir and collect certificate info
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            apk_names = get_apk_names("pos.txt", apk_names_path)
            print(len(apk_names))
            cursor = db_connection.cursor()
            cursor.execute(idpos_query)
            row = cursor.fetchone()
            i = 0
            while count > 0:
                while i < len(apk_names):
                    apk_file = apk_names[i]
                    start = start+1
                    i = i+1
                    if apk_file.endswith(".apk"):
                        apk_path = os.path.join(apk_dir, apk_file)
                        # Open,close, read file and calculate MD5 on its contents
                        with open(apk_path, "rb") as apk_to_hash:
                            # read contents of the file
                            data = apk_to_hash.read()
                            # pipe contents of the file through
                            apk_hash = hashlib.md5(data).hexdigest()
                            print(row[1] + "  fdf  " + apk_hash)
                        if row[1] == apk_hash:
                            cursor.execute(fname_insert_query, (apk_file, row[0]))
                            db_connection.commit()
                            break
                count = count - 1
                cursor.execute(idpos_query)
                row = cursor.fetchone()
                if row is None:
                    print("Npne")
                    break

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
            with open("pos.txt", "w") as fpos:
                fpos.write("%d\n%d" % (start, count))


if __name__ == "__main__":
    # os.chdir(sys.path[0])
    # parse_cert(sys.argv[1])

    apk_names_file = os.path.expanduser('~/Documents/Myworkspace/apksfilenames.txt')
    apk_directory = os.path.expanduser('~/Documents/apks/')
    # dest_cert_dir = os.path.expanduser('~/Documents/firmwares/play_apk_certs/')
    collect_file_name(apk_names_file, apk_directory)

    sys.exit(0)
