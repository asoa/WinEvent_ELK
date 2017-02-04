#! /usr/bin/env python
"""
Purpose: this script uses the elasticsearch query API to fetch data from a local elasticsearch instance using standard
 Lucene syntax.  Specifically, this script queries for windows event log process data with label type:"process".  The
 script writes 2 csv files to the current working directory:

    - suspect_<date>.csv: processes executed from filesystem paths not in the whitelist
    - legit_<date>.csv: legitimate processes execution count

#TODO: create function to tokenize process name only and check against white,black,mutated lists
#TODO: create function to set start|end default time to last 24 hours
#TODO: (complete) output processes not residing in white_list to csv
#TODO: (complete) output count of legitimate process execution to csv
#TODO: (complete) output hits to csv file

"""

from __future__ import print_function
from datetime import datetime
from elasticsearch import Elasticsearch
import argparse
import sys
import time
import csv
import re
import operator
import os


client = Elasticsearch()


def check_white_list(hit):
    # add additional white-list path patterns to white_list
    white_list = re.compile(r'C:\\Windows\\System32\\|C:\\Program Files\\Windows NT\\Accessories\\|<add another pattern here>')
    found = white_list.search(hit)
    if found:
        return True
    return False


def classify_bins(hit_list):  # classifies binary path as either suspect or good
    suspect_exe = []
    good_hit_dict = {}
    hits = (hit[1] for hit in hit_list)  # generator to iterate over all hits
    # for hit in hits:
    for hit in hit_list:
        good_hit_exe = check_white_list(hit[3])  # check binary path against white-list
        if good_hit_exe:  # add binary to dictionary or increment count if found
            good_bin = hit[3].split("\\")[-1]
            if good_bin in good_hit_dict.keys():
                good_hit_dict[good_bin] += 1
            else:
                good_hit_dict[good_bin] = 1
        else:
            suspect_exe.append(hit)  # add suspect binary to list

    # create dict sorted on hit count
    ordered_good_hit_dict = sorted(good_hit_dict.items(), key=operator.itemgetter(1), reverse=True)
    return suspect_exe, ordered_good_hit_dict  # return list and dict to caller


def query_elasticsearch(query, q_size, start_time, end_time):
    # json request was derived from Kibana dispayed request; click on " ^ " under histogram on Discover tab
    response = client.search(
        index="logstash*",
        body={
            "size": q_size,  # specify how many records to return that match the query

            "sort": [  # sort records in desc order based on time field
                {
                  "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "boolean"
                  }
                }
              ],

            "query": {
                "bool": {
                  "must": [
                    {
                      "query_string": {
                        "query": query,  # lucene formatted query, default is *
                      }
                    },
                    {
                      "match": {
                        "type": {
                          "query": "process",  # only return records labeled "process"
                          "type": "phrase"
                        }
                      }
                    },
                    {
                      "range": {
                        "@timestamp": {
                          "gte": start_time,  # return records within the specified time parameters
                          "lte": end_time,
                          "format": "epoch_millis"
                        }
                      }
                    }
                  ],
                  "must_not": []
                }
            }
        }

    )
    return response


def get_epoch(s_time, e_time):  # convert date format to epoch
    pattern = '%d %m %Y %H:%M:%S'
    start_time = int(time.mktime(time.strptime(s_time, pattern)))
    end_time = int(time.mktime(time.strptime(e_time, pattern)))
    return str(start_time) + "000", str(end_time) + "000"  # add padding (milliseconds) to epoch time


def parse_args():
    parser = argparse.ArgumentParser(usage=sys.argv[0] + ' -q <lucene query> -s <query_size> -s_time <start_time> -e_time <end_time>', description="enter the following cmd line arguments:")
    parser.add_argument("-q", dest="query", default="*", help="lucene formatted query, default is '*'")
    parser.add_argument("-s", dest="q_size", default=500, help="max amount of records query will return, default=500")
    parser.add_argument("-s_time", dest="s_time", help="start time of query, format: DD MM YY HH:MM")
    parser.add_argument("-e_time", dest="e_time", help="end time of query, format: DD MM YY HH:MM")
    args = parser.parse_args()
    if args.query is None or args.q_size is None or args.s_time is None or args.e_time is None:
        print(parser.usage)
        print("Example: ./ES_python_process.py -s_time '23 12 2016 04:19:00' -e_time '25 12 2016 04:34:00' -s 1000")
        exit(0)
    return args.query, args.q_size, args.s_time, args.e_time


def main():
    hits = []
    query, size, s_time, e_time = parse_args()
    start_time, end_time = get_epoch(s_time, e_time)
    response = query_elasticsearch(query, size, start_time, end_time)
    for hit in response['hits']['hits']:
        hit_tuple = (hit["_source"]["TimeCreated"], hit["_source"]["MachineName"], hit["_source"]["SubjectUserName"], hit["_source"]["NewProcessName"], hit["_source"]["CommandLine"])
        # print(hit_tuple)
        hits.append(hit_tuple)
    suspect_exe, ordered_good_hit_dict = classify_bins(hits)

    # create csv file and write binary paths that aren't in whitelist
    date_time = datetime.now().isoformat()
    with open("suspect_" + date_time + ".csv", "wt") as f:
        writer = csv.writer(f)
        writer.writerow(('TimeCreated','MachineName','UserName','ProcessName','CommandLine'))
        for suspect_path in suspect_exe:
            writer.writerow((suspect_path[0], suspect_path[1], suspect_path[2], suspect_path[3], suspect_path[4]))
    print("{} suspect binary paths written to {}".format(len(suspect_exe), os.path.abspath("suspect.csv")))
    # print(open("suspect.csv", 'rt').read())

    with open("legit_" + date_time + ".csv", "wt") as f:
        writer = csv.writer(f)
        writer.writerow(('LegitBin','Count'))
        for hit in ordered_good_hit_dict:
            legit_bin = hit[0]
            count = hit[1]
            writer.writerow((legit_bin,count))
    print("{} legit binaries and counts written to {}".format(len(ordered_good_hit_dict), os.path.abspath("legit.csv")))
    # print(open("legit.csv", 'rt').read())

    # print("********* The following binaries aren't in the whitelist path(s) *********")
    # print(*suspect_exe, sep="\n")
    # print("********* Descending count of all binaries seen in the selected time frame *********")
    # print(*ordered_good_hit_dict, sep="\n")

if __name__ == "__main__":
    main()

