#!/bin/bash

# https://github.com/edx/edx-arch-experiments/issues/580
export DD_TRACE_PYMONGO_ENABLED=false

# Enable Datadog's OpenTelemetry exporter
export DD_TRACE_OTEL_ENABLED=true

# Not sure what this does, but if we don't include it we get a startup failure:
# TypeError: Couldn't build proto file into descriptor pool: duplicate file name opentelemetry/proto/common/v1/common.proto
export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION="python"

ddtrace-run "$@"
