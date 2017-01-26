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

        "sort": [
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
                      "query": "process",
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

#TODO: create argparse function to create cmd line argmuments: q_size, d_range
#TODO: create function to convert d_range argument to epoch time passed to range key in json query
#TODO: create function to match on processess not residing in C:\Windows\System32\ and output to file
#TODO: create function tokenize process name only and check against white|black lists
#TODO: create function to

