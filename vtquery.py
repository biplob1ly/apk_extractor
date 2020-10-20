import requests
from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config
import os
import json

idpos_query = "select id,hash from apk_info where id >= %s limit %s"
vt_res_dir = os.path.expanduser('~/Documents/firmwares/firmware/vt_results/')  # '~/Documents/TestDir/vtresult'
no_result_files = os.path.join(os.path.expanduser('~/Documents/firmwares/firmware/'), "no_vt_result.txt")
start = None
limit = None

url = 'https://www.virustotal.com/vtapi/v2/file/report'
proxy = {'http':'http://127.0.0.1:5566', 'https':'https://127.0.0.1:5566'}

def get_vt_response(apk_id, apk_hash, vt_key):
    params = {'apikey': vt_key, 'resource': apk_hash}
    try:
        response = requests.get(url, params=params, proxies=proxy)
        print(response.status_code)
        if response.status_code != 200:
            with open("no_response.txt","a+") as no_response:
                no_response.write(str(apk_id)+"_"+apk_hash+"\n")
        else:        
            vt_res = json.loads(response.text)
            #print(vt_res)
            if vt_res["response_code"] == 1:
                fname = os.path.join(vt_res_dir, str(apk_id)+"_"+apk_hash+".json")
                with open(fname, "w") as file:
                    json.dump(vt_res, file)
            else:
                with open(no_result_files, "a+") as no_res:
                    no_res.write(str(apk_id)+"_"+apk_hash+"\n")
    except OSError:
        print("OS error Occured")
    except ProxyError:
        print("Proxy error Occured")
    except MaxRetryError:
        print("Max Retry Error")



def collect_vt_info():
    # Establish database connection
    db_config = read_db_config()
    db_connection = None
    cursor = None
    count = 0
    global start, limit, vt_keys
    with open("vt_pos.txt", "r") as fpos:
        start, limit = (int(val) for val in fpos.read().splitlines())
    # Loop through each apk file in the apk_dir and collect certificate info
    try:
        print('Connecting to MySQL database...')
        db_connection = MySQLConnection(**db_config)
        if db_connection.is_connected():
            print('db_connection established.')
            cursor = db_connection.cursor()
            cursor.execute(idpos_query, (start, limit))
            rows = cursor.fetchall()

            with open("vtkeys.txt") as fin:
                vt_keys = [line.rstrip() for line in fin.readlines()]

            for row in rows:
                print(str(start) + " : " + str(count) + " : " + row[1])
                get_vt_response(row[0], row[1], vt_keys[count % len(vt_keys)])
                count = count+1
                start = start+1

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
            with open("vt_pos.txt", "w") as fpos:
                fpos.write("%d\n%d" % (start, limit))


if __name__ == "__main__":
    collect_vt_info()
    #get_vt_response("5454", "ad368f18f3d63d7c0979e100c5dee221", "38d697f5cc6305dafa48d5fc6a70309a3bbd0c2288a7136f07eb8368ad4acb8d")
