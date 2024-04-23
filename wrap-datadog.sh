#!/bin/bash

# https://github.com/edx/edx-arch-experiments/issues/580
#export DD_TRACE_PYMONGO_ENABLED=false

# # Enable Datadog's OpenTelemetry exporter
# export DD_TRACE_OTEL_ENABLED=true

# # Not sure what this does, but if we don't include it we get a startup failure when exporting via OTel:
# # TypeError: Couldn't build proto file into descriptor pool: duplicate file name opentelemetry/proto/common/v1/common.proto
# export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION="python"

#export DD_TRACE_DEBUG=true
#export DD_TRACE_DEBUG_ENABLE=false
#export DD_TRACE_LOG_FILE_LEVEL=ERROR
#export DD_TRACE_LOG_STREAM_HANDLER=no_thank_you
#export DD_TRACE_LOG_FILE=/var/log/dd.log

ddtrace-run "$@"
