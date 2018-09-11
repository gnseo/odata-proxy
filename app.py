import sys
sys.path.insert(0, './pip')

import requests
import re
import uuid
import json
from urllib.parse import quote
import gzip
import base64

AUTH_BASE64 = "auth_base64"
URL = "url"
CONTENT_TYPE = 'Content-Type'
APPLICATION_JSON = 'application/json'
ACCESS_CONTROL_ALLOW_ORIGIN = 'Access-Control-Allow-Origin'
ALL = '*'

def handler2(event, context):
  import boto3
  import json

  client = boto3.client('lambda')

  payload = {
    "key": "texts/example.json",
    "lang": "ko"
  }

  response = client.invoke(
      FunctionName="s3select_json",
      Payload=json.dumps(payload)
  )

  records = []
  rawJson = response['Payload'].read().decode('utf-8')
  getJson = json.loads(rawJson)
  print(getJson)
  records.append(getJson)

  return records

def handler(event, context):
  print(event)
  method = event["httpMethod"]

  handlers = {
    "GET": handler_get,
    "POST": handler_post
  }

  def getQuery(method):
    if method == "GET":
      return event["queryStringParameters"]
    else:
      return json.loads(event["body"])

  query = getQuery(method)

  def getURL(query):
    return query[URL]

  return handlers[method](event, context, query, getURL(query))

def handler_get(event, context, query, url):
  #auth_base64 = query[AUTH_BASE64]

  res = requests.get(url, headers=json.loads(query["headers"]))

  print(res.headers)
  print(res.text)
  print(res.cookies)
  #try:

  return_headers = { ACCESS_CONTROL_ALLOW_ORIGIN: ALL, "Access-Control-Expose-Headers": "my-cookie,x-csrf-token,www-authenticate" }
  return_headers.update(res.headers)
  return_headers["my-cookie"] = " ".join(["{0}={1};".format(k,res.cookies[k]) for k in res.cookies.keys()])
  #return_headers["my-cookie"] = "".join(re.findall('[^ .]+\; ',res.headers["set-cookie"]))

  return_body = ""
  gzipped = False
  for key,value in return_headers.items():
    if key.lower() == "content-encoding":
      if value == "gzip":
        gzipped = True
        break

  for key,value in return_headers.items():
    if key.lower() == "content-type":
      if re.search(r'json',value,flags=re.IGNORECASE):
        return_headers[key] = "application/json"
        return_body = res.text
        break
      elif re.search(r'html',value,flags=re.IGNORECASE):
        return_body = res.text
        break

  isBase64Encoded = False
  if gzipped:
    try:
      return_body = return_body.encode()
    except:
      pass

    return_body = gzip.compress(return_body)

    return_body = base64.b64encode(return_body)
    return_body = str(return_body, 'utf8')

    isBase64Encoded = True

  print(return_body)

  #token = res.headers["x-csrf-token"]
  ## cookie = res.headers["set-cookie"].replace("path=/; secure; HttpOnly","")
  #set_cookie = res.headers["set-cookie"]
  #cookie = "".join(re.findall('[^ .]+\; ',set_cookie))
  ##for c in re.finditer('[^ .]+\; ',set_cookie):
  ##  cookie += c
  #print(cookie)

  return {
    'statusCode': 200,
    'headers': return_headers,
    'body': return_body,
    'isBase64Encoded': isBase64Encoded
  }

  #except KeyError:
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

  #return {
  #      'statusCode': 200,
  #      'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
  #      'body': json.JSONEncoder().encode({
  #        "x-csrf-token": token,
  #        "set-cookie": cookie
  #      })
  #}

def handler_post(event, context, query, url):

  if "get_token" in query:
    token_json = handler_get(event, context, query, url)

    try:
      token = token_json["body"]["x-csrf-token"]
      cookie = token_json["body"]["set-cookie"]
    except KeyError:
      return token_json
  else:
    pass
    #try:
    #  token = query["token"]
    #except KeyError:
    #  return {
    #        'statusCode': 200,
    #        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
    #        'body': json.JSONEncoder().encode({
    #          "error": {
    #            "message": "No token provided"
    #          }
    #        })
    #  }
    #try:
    #  cookie = query["cookie"]
    #except KeyError:
    #  return {
    #        'statusCode': 200,
    #        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
    #        'body': json.JSONEncoder().encode({
    #          "error": {
    #            "message": "No cookie provided"
    #          }
    #        })
    #  }
    #try:
    #  auth_base64 = query["auth_base64"]
    #except KeyError:
    #  return {
    #        'statusCode': 200,
    #        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
    #        'body': json.JSONEncoder().encode({
    #          "error": {
    #            "message": "No auth_base64 provided"
    #          }
    #        })
    #  }


  print("cookie and token:")
  #print(cookie, token)

  headersPost = {
    "accept":"application/json",
    "content-type":"application/json",
    #"x-csrf-token":token,
    #"cookie":cookie,
    #"authorization":"Basic "+auth_base64
  }
  headersPost.update(query["headers"])
  jsonPost = query["body"]
  print(headersPost)
  res = requests.post(url, headers=headersPost, json=jsonPost)#, auth=(username,password)

  return_headers = { ACCESS_CONTROL_ALLOW_ORIGIN: ALL, "Access-Control-Expose-Headers": "x-csrf-token,www-authenticate" }
  return_headers.update(res.headers)
  print(res.headers)

  return_body = ""
  gzipped = False
  for key,value in return_headers.items():
    if key.lower() == "content-encoding":
      if value == "gzip":
        gzipped = True
        break

  for key,value in return_headers.items():
    if key.lower() == "content-type":
      if re.search(r'json',value,flags=re.IGNORECASE):
        return_headers[key] = "application/json"
        return_body = res.text
        break
      elif re.search(r'html',value,flags=re.IGNORECASE):
        return_body = res.text
        break

  isBase64Encoded = False
  if gzipped:
    try:
      return_body = return_body.encode()
    except:
      pass

    return_body = gzip.compress(return_body)

    return_body = base64.b64encode(return_body)
    return_body = str(return_body, 'utf8')

    isBase64Encoded = True

  print(return_body)
  return {
    'statusCode': 200,
    'headers': return_headers,
    'body': return_body,
    'isBase64Encoded': isBase64Encoded
  }


  result = res.json()
  print(result)
  result = result["d"]["results"]

  print(result["TaskID"])
  print(result["Message"])

  return {
        'statusCode': 200,
        'headers': { CONTENT_TYPE: APPLICATION_JSON, ACCESS_CONTROL_ALLOW_ORIGIN: ALL },
        'body': json.JSONEncoder().encode({
          "result": result
        })
  }
