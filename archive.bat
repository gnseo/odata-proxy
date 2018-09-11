del latest.zip
7z\7za a -x@7z\.ignore latest.zip *.* * -r
REM 7z\7za a latest.zip ..\..\..\..\config\pysaml2-lambda\idp_conf.py -r
call aws lambda update-function-code --function-name odata-proxy --zip-file fileb://latest.zip
pause
