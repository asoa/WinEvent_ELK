#! /usr/bin/env python

from __future__ import print_function
from datetime import datetime
from elasticsearch import Elasticsearch

client = Elasticsearch()

"""
The search function json
"""
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
    }

)

for hit in response['hits']['hits']:
    # print(hit)
    print(hit["_source"]['MachineName'],hit["_source"]['TargetDomainName'],hit["_source"]['TargetUserName'],hit["_source"]['type'],hit["_source"]['TimeCreated'])

# Output returned to console from query (TargetDomainName:LAB) to index logstash*

"""
bob-win7.lab.local LAB DoD_Admin logoff 12/25/2016 1:52:43 AM
bob-win7.lab.local LAB DoD_Admin logoff 12/25/2016 1:52:43 AM
bob-win7.lab.local LAB DoD_Admin logoff 12/24/2016 10:48:46 PM
bob-win7.lab.local LAB DoD_Admin logon 12/24/2016 10:48:30 PM
bob-win7.lab.local LAB DoD_Admin logoff 12/24/2016 10:46:56 PM
bob-win7.lab.local LAB DoD_Admin logoff 12/24/2016 10:46:55 PM
bob-win7.lab.local LAB DoD_Admin logon 12/24/2016 10:46:46 PM
bob-win7.lab.local LAB DoD_Admin logon 12/24/2016 10:46:45 PM
bob-win7.lab.local LAB DoD_Admin logon 12/24/2016 10:46:45 PM
bob-win7.lab.local LAB DoD_Admin logoff 12/24/2016 10:46:35 PM
bob-win7.lab.local LAB DoD_Admin logoff 12/24/2016 10:46:30 PM
"""

