#! /usr/bin/env python

from __future__ import print_function
from datetime import datetime
from elasticsearch import Elasticsearch

client = Elasticsearch()

# json request was derived from Kibana dispayed request; click on " ^ " under histogram on Discover tab
response = client.search(
    index="logstash*",
    body={
        "size": 500,  # specify how many records to return that match the query

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
                    "query": "*",
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
                      "gte": 1482484753418,
                      "lte": 1482658453418,
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

for hit in response['hits']['hits']:
    print(hit["_source"]["TimeCreated"],hit["_source"]["NewProcessName"],hit["_source"]["CommandLine"])

# Output returned to console from query " * "  to index logstash* matching on all documents tagged with "process" label

"""
12/24/2016 8:33:12 AM C:\Windows\System32\slui.exe "C:\windows\System32\SLUI.exe" RuleId=eeba1977-569e-4571-b639-7623d8bfecc0;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f16059f;SkuId=b3ca044e-a358-4d68-9883-aaa2941aca99;NotificationInterval=1440;Trigger=NetworkAvailable
12/24/2016 8:33:12 AM C:\Windows\System32\SppExtComObj.Exe C:\windows\system32\SppExtComObj.exe -Embedding
12/24/2016 8:33:12 AM C:\Windows\System32\sppsvc.exe C:\windows\system32\sppsvc.exe
12/24/2016 8:32:51 AM C:\Windows\System32\calc.exe C:\Windows\System32\calc.exe
12/24/2016 8:32:11 AM C:\Windows\System32\MRT.exe C:\windows\system32\MRT.exe /EHB /Q
12/24/2016 8:32:11 AM C:\Windows\System32\taskhostex.exe taskhostex.exe Regular
12/24/2016 8:31:51 AM C:\Windows\System32\calc.exe C:\Windows\System32\calc.exe
"""

#TODO: create argparse function to create cmd line argmuments: q_size, d_range
#TODO: create function to convert d_range argument to epoch time passed to range key in json query
#TODO: create function to match on processess not residing in C:\Windows\System32\ and output to file
#TODO: create function tokenize process name only and check against white|black lists
#TODO: create function to count occurences of process and output to file

