#!/bin/sh
rm -rf latest.zip
zip -r latest.zip ./ -
# aws lambda update-function-code --function-name odata-proxy --zip-file fileb://latest.zip --profile workuser
# To set aws config profile as default, we must export AWS_PROFILE environment variable with the profile name.
# eg. export AWS_PROFILE=<profile name>
