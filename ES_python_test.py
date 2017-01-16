#! /usr/bin/env python

from datetime import datetime
from elasticsearch import Elasticsearch

client = Elasticsearch()

response = client.search(
    index="logstash*",
    body={
        "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "TargetDomainName:\"LAB\""
                  }
                },
                {
                  "range": {
                    "@timestamp": {
                      "gte": 1482478536785,
                      "lte": 1482652236785,
                      "format": "epoch_millis"
                    }
                  }
                }
              ],
              "must_not": []
            }
          }
    },

)

for hit in response['hits']['hits']:
    # print(hit)
    print(hit["_source"]['MachineName'],hit["_source"]['TargetDomainName'],hit["_source"]['TargetUserName'],hit["_source"]['type'],'TimeCreated')