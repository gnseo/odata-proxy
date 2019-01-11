del latest.zip
7z\7za a -xr@7z\.ignore -x@7z\.ignorexact latest.zip .\
REM 7z\7za a latest.zip ..\..\..\..\config\pysaml2-lambda\idp_conf.py -r
call aws lambda update-function-code --function-name odata-proxy --zip-file fileb://latest.zip --profile cs_deployLambda
pause
