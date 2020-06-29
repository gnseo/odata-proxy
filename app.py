import base64
import contextlib
import gzip
import json
import os
import re
import ssl
import sys
import logging
import tempfile
import uuid
from urllib.parse import quote
import traceback

import boto3
import botocore

sys.path.insert(0, './pip')

try:
    print(OpenSSL.crypto)
except NameError:
    import OpenSSL.crypto
    import requests
except:
    print("Unexpected error:", sys.exc_info()[0])


logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.INFO)

AUTH_BASE64 = "auth_base64"
URL = "url"
CONTENT_TYPE = 'Content-Type'
APPLICATION_JSON = 'application/json'
ACCESS_CONTROL_ALLOW_ORIGIN = 'Access-Control-Allow-Origin'
ALL = '*'

version = None


def handler(event, context):
    global version

    # print(context)
    print(event)
    try:
        method = event["httpMethod"]
    except:
        method = event["context"]["http-method"]

    version = event.get("version")

    handlers = {
        "GET": handler_get,
        "POST": handler_post,
        "PUT": handler_post,
        "DELETE": handler_post,
        "PATCH": handler_post
    }

    def getQuery(method):
        if method == "GET":
            if version == "20190625":
                return event
            else:
                try:
                    return event["queryStringParameters"]
                except:
                    return event["params"]["querystring"]
        else:
            if "body" in event:
                if version == "20190625":
                    return event.get("body")
                else:
                    return json.loads(event["body"])
            else:
                return event["body-json"]

    query = getQuery(method)

    if version == "20190625":
        url = event.get(URL)
    else:
        url = query[URL]

    ret_result = handlers[method](event, context, query, url, method)
    if "connectionId" in event:
        return sendMessageToClient(event, ret_result)
    else:
        return ret_result


def get_file_from_s3(bucket_name, file_name):

    # KEY = 'Y2TSL8HJY_ManageMashupTokenIn.wsdl' # replace with your object key

    # client_s3 = boto3.client("s3")

    s3 = boto3.resource('s3')

    local_wsdl_location = '/tmp/{}'.format(file_name)

    try:
        # log.info(client_s3.list_objects_v2(Bucket=bucket_name))
        s3.meta.client.download_file(
            bucket_name, file_name, local_wsdl_location)
        # client_s3.get_object(Bucket=bucket_name, Key=KEY)#, 'wsdl/{}'.format(KEY))
    except botocore.exceptions.ClientError:
        # if e.response['Error']['Code'] == "404":
        str_msg = traceback.format_exc().splitlines()
        log.error("Error: During creation Client - {0}".format(str_msg))
        return {"error": str_msg}

    return local_wsdl_location


# ref to https://gist.github.com/erikbern/756b1d8df2d1487497d29b90e81f8068


@contextlib.contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    ''' Decrypts the .pfx file to be used with requests. '''
    with tempfile.NamedTemporaryFile(suffix='.pem') as t_pem:
        f_pem = open(t_pem.name, 'wb')
        pfx = open(pfx_path, 'rb').read()
        p12 = OpenSSL.crypto.load_pkcs12(pfx, pfx_password)
        f_pem.write(OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))
        f_pem.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))
        ca = p12.get_ca_certificates()
        if ca is not None:
            for cert in ca:
                f_pem.write(OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, cert))
        f_pem.close()
        yield t_pem.name

# HOW TO USE:
# with pfx_to_pem('foo.pem', 'bar') as cert:
#     requests.post(url, cert=cert, data=payload)


def handler_get(event, context, query, url, httpMethod):
    #auth_base64 = query[AUTH_BASE64]
    #cert_path = get_file_from_s3("cert--bsg.support","private.csr")
    #key_path = get_file_from_s3("cert--bsg.support","private.pem")
    try:
        h = json.loads(query["headers"])
    except TypeError:
        h = query["headers"]
    except KeyError:
        # h =
        print(query)
        pass 
    useSSL = False

    pkcs12 = h.get("pkcs12", None)

    if pkcs12 is not None:
        useSSL = True

    return_headers = {ACCESS_CONTROL_ALLOW_ORIGIN: ALL,
                      "Access-Control-Expose-Headers": "my-cookie,x-csrf-token,www-authenticate"}

    if useSSL == True:
        pkcs12_path = get_file_from_s3("cert-bsg.support", pkcs12["filename"])

        with pfx_to_pem(pkcs12_path, pkcs12["password"]) as cert:
            res, ret_result = sendQuery(
                url, httpMethod, cert=cert, return_headers=return_headers)
    else:
        res, ret_result = sendQuery(
            url, httpMethod, headers=h, return_headers=return_headers)

    if ret_result is not None:
        return ret_result

    # print(res.headers)
    # print(res.text)
    # print(res.cookies)
    # try:

    return_headers.update(res.headers)
    return_headers["my-cookie"] = " ".join(
        ["{0}={1};".format(k, res.cookies[k]) for k in res.cookies.keys()])
    #return_headers["my-cookie"] = "".join(re.findall('[^ .]+\; ',res.headers["set-cookie"]))

    return_body = ""
    gzipped = False
    for key, value in return_headers.items():
        if key.lower() == "content-encoding":
            if value == "gzip":
                gzipped = True
                break

    for key, value in return_headers.items():
        if key.lower() == "content-type":
            if re.search(r'json', value, flags=re.IGNORECASE):
                return_headers[key] = "application/json"
                return_body = res.text
                break
            elif re.search(r'html', value, flags=re.IGNORECASE):
                return_body = res.text
                break
            elif re.search(r'xml', value, flags=re.IGNORECASE):
                return_body = res.text
                break

    isBase64Encoded = False
    gzipped = False
    if gzipped:
        try:
            return_body = return_body.encode()
        except:
            pass

        return_body = gzip.compress(return_body)

        return_body = base64.b64encode(return_body)
        return_body = str(return_body, 'utf8')

        isBase64Encoded = True

    # print(return_body)

    #token = res.headers["x-csrf-token"]
    ## cookie = res.headers["set-cookie"].replace("path=/; secure; HttpOnly","")
    #set_cookie = res.headers["set-cookie"]
    #cookie = "".join(re.findall('[^ .]+\; ',set_cookie))
    # for c in re.finditer('[^ .]+\; ',set_cookie):
    ##  cookie += c

    return {
        'statusCode': res.status_code,
        'headers': return_headers,
        'body': return_body,
        'isBase64Encoded': isBase64Encoded
    }

    # except KeyError:
    #  try:
    #    when_login_failed = res.headers["www-authenticate"]#'Basic realm="SAP NetWeaver Application Server"'
    #  except KeyError:
    #    return {
    #          'statusCode': 200,
    #          'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
    #          'body': json.JSONEncoder().encode({
    #            "error": {
    #              "message": "Failed to get Token. Invalid URL might be one of the reasons."
    #            }
    #          })
    #    }
    #  return {
    #        'statusCode': 200,
    #        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
    #        'body': json.JSONEncoder().encode({
    #          "error": {
    #            "message": "Failed to log in, check your username or password"
    #          }
    #        })
    #  }

    # return {
    #      'statusCode': 200,
    #      'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
    #      'body': json.JSONEncoder().encode({
    #        "x-csrf-token": token,
    #        "set-cookie": cookie
    #      })
    # }


def sendQuery(url, httpMethod, headers=None, jsonBody=None, cert=None, return_headers=None):
    res = None
    try:
        if httpMethod == "GET":
            if cert is not None:
                res = requests.get(url, cert=cert)
            else:
                res = requests.get(url, headers=headers)
        elif httpMethod == "PUT":
            res = requests.put(url, headers=headers,
                               json=jsonBody, timeout=890)
        elif httpMethod == "PATCH":
            res = requests.patch(url, headers=headers,
                                 json=jsonBody, timeout=890)
        elif httpMethod == "DELETE":
            res = requests.delete(url, headers=headers, timeout=890)
        else:
            res = requests.post(url, headers=headers,
                                json=jsonBody, timeout=890)
        res.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout, requests.exceptions.HTTPError) as requestsError:
        error_status_code = 400
        error_text = ""
        if res is not None:
            print(res)
            print(res.status_code)
            print(res.text)
            error_text = res.text
            error_status_code = res.status_code
            return_headers.update(res.headers)

        ret_result = {
            'statusCode': error_status_code,
            'headers': return_headers,
            'body': {"Exception": str(requestsError), "ResponseError": error_text},
            'isBase64Encoded': False
        }
        print(requestsError)
        print("requests occurred error")
        return None, ret_result

    return res, None


def handler_post(event, context, query, url, httpMethod):
    global version
    # if "get_token" in query:
    #     token_json = handler_get(event, context, query, url, httpMethod)

        # try:
            # token = token_json["body"]["x-csrf-token"]
            # cookie = token_json["body"]["set-cookie"]
        # except KeyError:
        #     return token_json
    # else:
    #     pass
        # try:
        #  token = query["token"]
        # except KeyError:
        #  return {
        #        'statusCode': 200,
        #        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
        #        'body': json.JSONEncoder().encode({
        #          "error": {
        #            "message": "No token provided"
        #          }
        #        })
        #  }
        # try:
        #  cookie = query["cookie"]
        # except KeyError:
        #  return {
        #        'statusCode': 200,
        #        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
        #        'body': json.JSONEncoder().encode({
        #          "error": {
        #            "message": "No cookie provided"
        #          }
        #        })
        #  }
        # try:
        #  auth_base64 = query["auth_base64"]
        # except KeyError:
        #  return {
        #        'statusCode': 200,
        #        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
        #        'body': json.JSONEncoder().encode({
        #          "error": {
        #            "message": "No auth_base64 provided"
        #          }
        #        })
        #  }

    # print("cookie and token:")

    headersPost = {
        "accept": "application/json",
        "content-type": "application/json",
        # "x-csrf-token":token,
        # "cookie":cookie,
        # "authorization":"Basic "+auth_base64
    }
    if version == "20190625":
        headersPost.update(event.get("headers"))
        jsonPost = event.get("body")
    else:
        headersPost.update(query.get("headers"))
        jsonPost = query.get("body")
    # , auth=(username,password)
    return_headers = {ACCESS_CONTROL_ALLOW_ORIGIN: ALL,
                      "Access-Control-Expose-Headers": "x-csrf-token,www-authenticate"}
    return_body = ""

    res, ret_result = sendQuery(
        url, httpMethod, headersPost, jsonPost, return_headers=return_headers)
    if ret_result is not None:
        return ret_result

    return_headers.update(res.headers)

    gzipped = False
    for key, value in return_headers.items():
        if key.lower() == "content-encoding":
            if value == "gzip":
                gzipped = True
                break

    for key, value in return_headers.items():
        if key.lower() == "content-type":
            if re.search(r'json', value, flags=re.IGNORECASE):
                return_headers[key] = "application/json"
                return_body = res.text
                break
            elif re.search(r'html', value, flags=re.IGNORECASE):
                return_body = res.text
                break

    isBase64Encoded = False
    gzipped = False
    if gzipped:
        try:
            return_body = return_body.encode()
        except:
            pass

        return_body = gzip.compress(return_body)

        return_body = base64.b64encode(return_body)
        return_body = str(return_body, 'utf8')

        isBase64Encoded = True

    ret_result = {
        'statusCode': res.status_code,
        'headers': return_headers,
        'body': return_body,
        'isBase64Encoded': isBase64Encoded
    }
    print("return result successfully")
    return ret_result

    # result = res.json()
    # result = result["d"]["results"]

    # return {
    #     'statusCode': 200,
    #     'headers': {CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL},
    #     'body': json.JSONEncoder().encode({
    #         "result": result
    #     })
    # }


def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]


def sendMessageToClient(event, ret_result):
    global version

    domainName = event["domainName"]
    stage = event["stage"]
    connectionId = event["connectionId"]

    apiClient = boto3.client("apigatewaymanagementapi",
                             endpoint_url="https://{0}/{1}".format(domainName, stage))
    ret_result.update(
        {
            "action": event.get("action", None),
            "subAction": event.get("subAction", None),
            "processID": event.get("processID", None),
        })

    if version is None:
        ret_result.update({"toDo": event.get("toDo", None)})

    dataToSend = base64.b64encode(json.dumps(ret_result).encode())
    # print(sys.getsizeof(dataToSend))
    # print(len(dataToSend))
    dataSplitted = split_len(dataToSend, 1024 * 10)
    totalLine = len(dataSplitted)
    for idx, d in enumerate(dataSplitted):
        lineNumber = idx + 1
        if totalLine == 1:
            finalData = json.dumps({
                "action": event.get("action", None),
                "subAction": event.get("subAction", None),
                "processID": event.get("processID", None),
                "toDo": event.get("toDo", None),
                "body": d.decode()
            })
            if version == "20190625":
                finalData = json.dumps({
                    "isBase64Encoded": True,
                    "response": d.decode()
                })
        else:
            finalData = json.dumps({
                "action": event.get("action", None),
                "subAction": event.get("subAction", None),
                "processID": event.get("processID", None),
                "toDo": event.get("toDo", None),
                "splitted": {
                    "total": totalLine,
                    "seq": lineNumber,
                    "body": d.decode()
                }
            })
            if version == "20190625":
                finalData = json.dumps({
                    "splitted": {
                        "total": totalLine,
                        "seq": lineNumber,
                        "action": event.get("action", None),
                        "subAction": event.get("subAction", None),
                        "processID": event.get("processID", None),
                        "isBase64Encoded": True,
                        "response": d.decode()
                    }
                })

        try:
            apiClient.post_to_connection(
                ConnectionId=connectionId, Data=finalData)
        except botocore.exceptions.ClientError:  # as clientError:
            pass
            # resBody = {"statusCode": clientError.response['Error']['Code']}
