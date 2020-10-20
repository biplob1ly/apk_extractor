from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config
import json
import avclass_labeler
import os
from const import *
from argparse import Namespace

vt_report_dir = os.path.expanduser("~/Projects/file_data/vt_reports")
vt_pos_file = os.path.expanduser("vt_updater_pos.txt")
initial_id = 320700
final_id = 525650


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


def update_vt_report():
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    cursor = None
    data = []
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            cursor = db_connection.cursor()
            cursor.execute(apk_hash_select_query, (initial_id, final_id))
            rows = cursor.fetchall()
            print((initial_id, final_id))
            for row in rows:
                print(row[0])
                vt_report_file = os.path.join(vt_report_dir, row[0] + ".json")
                vt_count = None
                avclass = None
                try:
                    if os.path.exists(vt_report_file):
                        with open(vt_report_file) as vt_json:
                            vt_data = json.load(vt_json)
                            vt_count = vt_data["positives"]
                        if vt_count > 0:
                            args = Namespace(
                                alias='./data/default.aliases',
                                aliasdetect=False, av=None, eval=False, fam=False,
                                gen='./data/default.generics',
                                gendetect=False, gt=None, hash=None, lb=None, lbdir=None, pup=False, verbose=False,
                                vt=[vt_report_file], vtdir=None)
                            avclass = avclass_labeler.main(args)
                        else:
                            avclass = "NoAVClass"
                        data.append((vt_count, avclass, row[0]))
                        print((vt_count, avclass, row[0]))
                except Exception as ex:
                    print("Avclass not found" + str(ex))
            if len(data) != 0:
                cursor.executemany(apk_vt_insert_query, data)
                db_connection.commit()
                print("Committed")
            else:
                print("No data to commit")

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


if __name__ == "__main__":
    update_vt_report()
