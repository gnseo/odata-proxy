#!/bin/sh
rm -rf latest.zip
zip -r latest.zip ./ -i "app.py" -i "lib/*"
aws lambda update-function-code --function-name odata-proxy --zip-file fileb://latest.zip --profile mfa
# To set aws config profile as default, we must export AWS_PROFILE environment variable with the profile name.
# eg. export AWS_PROFILE=<profile name>
