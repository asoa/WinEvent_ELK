#! /usr/bin/env python

from __future__ import print_function
from datetime import datetime
from elasticsearch import Elasticsearch
import argparse
import sys
import time
import csv

client = Elasticsearch()


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
    query, size, s_time, e_time = parse_args()
    start_time, end_time = get_epoch(s_time, e_time)
    response = query_elasticsearch(query, size, start_time, end_time)
    for hit in response['hits']['hits']:
        hit_tuple = (hit["_source"]["TimeCreated"], hit["_source"]["NewProcessName"], hit["_source"]["CommandLine"])
        print(hit_tuple)
        #print(hit["_source"]["TimeCreated"], hit["_source"]["NewProcessName"], hit["_source"]["CommandLine"])

if __name__ == "__main__":
    main()


# Output returned to console from query " * "  to index logstash* matching on all documents tagged with "process" label

"""
(u'12/23/2016 4:52:23 PM', u'C:\\Windows\\System32\\slui.exe', u'"C:\\windows\\System32\\SLUI.exe" RuleId=eeba1977-569e-4571-b639-7623d8bfecc0;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f16059f;SkuId=b3ca044e-a358-4d68-9883-aaa2941aca99;NotificationInterval=1440;Trigger=NetworkAvailable')
(u'12/23/2016 4:52:23 PM', u'C:\\Windows\\System32\\sppsvc.exe', u'C:\\windows\\system32\\sppsvc.exe')
(u'12/23/2016 4:52:23 PM', u'C:\\Windows\\System32\\taskhost.exe', u'taskhost.exe network')
(u'12/23/2016 4:52:14 PM', u'C:\\Windows\\System32\\conhost.exe', u'\\??\\C:\\windows\\system32\\conhost.exe 0xffffffff')
(u'12/23/2016 4:52:14 PM', u'C:\\Windows\\System32\\sc.exe', u'C:\\windows\\system32\\sc.exe start wuauserv')
(u'12/23/2016 4:52:14 PM', u'C:\\Windows\\System32\\taskhost.exe', u'taskhost.exe USER')
(u'12/23/2016 4:52:14 PM', u'C:\\Windows\\System32\\taskhost.exe', u'taskhost.exe SYSTEM')
"""

#TODO: create function to match on processess not residing in C:\Windows\System32\ and output to file
#TODO: create function tokenize process name only and check against white|black lists
#TODO: create function to count occurences of process and output to file
#TODO: create function to set start|end default time to last 24 hours
#TODO: output hits to csv file

