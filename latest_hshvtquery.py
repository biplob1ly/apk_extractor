import requests
import os
import json
import time
import sys


vt_res_dir = os.path.expanduser('~/Documents/BP/batch2_vt_reports')  # '~/Documents/TestDir/vtresult'
no_result_files = os.path.expanduser('~/Documents/BP/batch2_vt_missed.txt')
initial_id = 1572483
final_id = 1863858
start = None
count = None
max_val = 0
# proxies = {'http': 'http://127.0.0.1:5566', 'https': 'https://127.0.0.1:5566'}
report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'

def get_vt_response(apk_hash, vt_key):
    #print(vt_key)
    params = {'apikey': vt_key, 'resource': apk_hash}
    try:
        response = requests.get(report_url, params=params)
        print(response.status_code)
        while response.status_code != 200:
            print(response.status_code)
            time.sleep(5)
            response = requests.get(report_url, params=params)

        vt_res = json.loads(response.text)
        #print(vt_res)
        if vt_res["response_code"] == 1:
            fname = os.path.join(vt_res_dir, apk_hash+".json")
            with open(fname, "w") as file:
                json.dump(vt_res, file)
            return 1
    except Exception as e:
        print("Something went wrong while requesting: " + str(e))

    return 0


def get_apk_hashes(position_file, file_path):
    global start, count
    delim = ","
    with open(position_file, "r") as fpos:
        start, count = (int(val) for val in fpos.read().splitlines())
        end = int(start) + int(count)

    with open(file_path) as fin:
        apk_hashes = [line.rstrip().split(delim) for line in fin.readlines()[start:end]]
        if len(apk_hashes) == 0:
            print("******************completed*******************")

    return apk_hashes


def collect_vt_info():
    global start, count
    delim = "  "
    # Loop through each apk file in the apk_dir and collect certificate info
    if not os.path.exists(vt_res_dir):
        os.makedirs(vt_res_dir)
    try:
        hashes = get_apk_hashes("vt_pos.txt", "batch2_apk_hashes.txt")

        with open("vtkeys.txt") as fin:
            vt_keys = [line.rstrip() for line in fin.readlines()]
        with open("batch2_vt_missed.txt", "a+") as no_res, open("batch2_vt_available.txt", "a+") as vt_avl:
            for hash,path in hashes:
                print(str(start) + " : " + str(count) + " : " + hash)
                #if not os.path.exists(os.path.join(vt_res_dir, hash+".json")):
                result = get_vt_response(hash, vt_keys[count%len(vt_keys)])
                if result == 0:
                    no_res.write(hash + delim + path + "\n")
                else:
                    vt_avl.write(hash + delim + path + "\n")
                count = count-1
                start = start+1

    except:
        print("Unexpected error: ", sys.exc_info()[0])

    finally:
        with open("vt_pos.txt", "w") as fpos:
            fpos.write("%d\n%d" % (start, count))


def upload_file(file_path, api_key):
    params = {'apikey': api_key}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    try:
        response = requests.post(scan_url, files=files, params=params)
        print(response.status_code)
        if response.status_code == 200:
            vt_res = json.loads(response.text)
            print(str(vt_res["response_code"]) + " " + vt_res["verbose_msg"])
            if vt_res["response_code"] >= 1:
                return 1
            elif vt_res["response_code"] <= 0:
                return 0
        else:
            return -1
    except Exception as e:
        print("No response :" + str(e))
    return 0


def collect_vt_info_from_file():
    global start, count
    delim = ","
    # Loop through each apk file in the apk_dir and collect certificate info
    try:
        hash_paths = get_apk_hashes("vt_pos.txt", "samsung_vt_missed.txt")

        with open("vtkeys.txt") as fin:
            vt_keys = [line.rstrip() for line in fin.readlines()]

        with open("uploaded_samsung_apks.txt", "a+") as uploaded, open("failed_samsung_apks.txt", "a+") as failed:
            for hash, file_path in hash_paths:
                print(str(start) + " : " + str(count) + " : " + file_path)
                if os.path.getsize(file_path) < 33000000:
                    ret = upload_file(file_path, vt_keys[count % len(vt_keys)])
                    print(ret)
                    if ret == 1:
                        uploaded.write(hash + delim + file_path + "\n")
                    elif ret == 0:
                        failed.write(hash + delim + file_path + "\n")
                    else:
                        break
                count = count-1
                start = start+1

    except Exception as e:
        print("Unexpected error: " + str(e))

    finally:
        with open("vt_pos.txt", "w") as fpos:
            fpos.write("%d\n%d" % (start, count))


if __name__ == "__main__":
    # collect_vt_info()
    collect_vt_info_from_file()
