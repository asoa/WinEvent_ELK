#! /usr/bin/env python3


from datetime import datetime
from elasticsearch import Elasticsearch
import argparse
import sys
import time
import csv
import re
import operator


client = Elasticsearch()


def check_sys32(hit):
    # add additional white-list path patterns to white_list
    white_list = re.compile(r'C:\\Windows\\System32\\|C:\\Program Files\\Windows NT\\Accessories\\|<add another pattern here>')
    found = white_list.search(hit)
    if found:
        return True
    return False


def get_sys32(hit_list):  # generator to iterate over all hits
    suspect_exe = []
    good_hit_dict = {}
    hits = (hit[1] for hit in hit_list)
    for hit in hits:
        good_hit_exe = check_sys32(hit)
        if good_hit_exe:
            # add binary to dictionary or increment count if found
            good_bin = hit.split("\\")[-1]
            if good_bin in good_hit_dict.keys():
                good_hit_dict[good_bin] += 1
            else:
                good_hit_dict[good_bin] = 1
        else:
            # prints path to interesting binary to screen
            # print("I might be bad, check me out: {}".format(hit))
            suspect_exe.append(hit)

    # prints the count of "good binaries"
    ordered_good_hit_dict = sorted(good_hit_dict.items(), key=operator.itemgetter(1), reverse=True)
    # print(ordered_good_hit_dict)
    return suspect_exe, ordered_good_hit_dict

def query_elasticsearch(query, q_size, start_time, end_time):  # json request was derived from Kibana dispayed request; click on " ^ " under histogram on Discover tab
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
    return str(start_time) + "000", str(end_time) + "000"


def parse_args():
    parser = argparse.ArgumentParser(usage=sys.argv[0] + ' -q <lucene query> -s <query_size> -s_time <start_time> -e_time <end_time>', description="enter the following cmd line arguments:")
    parser.add_argument("-q", dest="query", default="*", help="lucene formatted query, default is '*'")
    parser.add_argument("-s", dest="q_size", default=500, help="max amount of records query will return, default=500")
    parser.add_argument("-s_time", dest="s_time", help="start time of query, format: DD MM YY HH:MM")
    parser.add_argument("-e_time", dest="e_time", help="end time of query, format: DD MM YY HH:MM")
    args = parser.parse_args()
    if args.query is None or args.q_size is None or args.s_time is None or args.e_time is None:
        print(parser.usage)
        exit(0)
    return args.query, args.q_size, args.s_time, args.e_time


def main():
    hits = []
    query, size, s_time, e_time = parse_args()
    start_time, end_time = get_epoch(s_time, e_time)
    response = query_elasticsearch(query, size, start_time, end_time)
    for hit in response['hits']['hits']:
        hit_tuple = (hit["_source"]["TimeCreated"], hit["_source"]["NewProcessName"], hit["_source"]["CommandLine"])
        hits.append(hit_tuple)
    suspect_exe, ordered_good_hit_dict = get_sys32(hits)
    print("********* The following binaries aren't in the whitelist path(s) *********")
    print(*suspect_exe, sep="\n")
    print("********* Count of all binaries seen in the selected time frame *********")
    print(*ordered_good_hit_dict, sep="\n")

if __name__ == "__main__":
    main()


#TODO: create function to match on processess not residing in C:\Windows\System32\ and output to file
#TODO: create function tokenize process name only and check against white|black lists
#TODO: create function to check processess against mutated black-list
#TODO: create function to count occurences of process and output to file
#TODO: create function to set start|end default time to last 24 hours
#TODO: output hits to csv file

