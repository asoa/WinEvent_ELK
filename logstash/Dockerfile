FROM logstash:5

# Add your logstash plugins setup here
# Example: RUN logstash-plugin install logstash-filter-json

RUN logstash-plugin install logstash-filter-translate
RUN logstash-plugin install logstash-filter-date
RUN logstash-plugin install logstash-filter-grok
RUN mkdir /data
ADD testData /data