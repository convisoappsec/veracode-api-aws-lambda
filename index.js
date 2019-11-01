/*
---------------------------------------
Author: Daniel Arenas
Company: Conviso Application Security
Last Update: 01/11/2019 
Version: 1.0
Based on: https://gist.githubusercontent.com/mrpinghe/f44479f2270ea36bf3b7cc958cc76cc0

Sample Event:

Findings API

{
  "body": {
    "api_id": "API_ID_HERE",
    "api_key": "API_KEY_HERE",
    "request_type": "GET",
    "host": "api.veracode.com",
    "endpoint": "/appsec/v1/applications"
  }
}

XML API

{
  "body": {
    "api_id": "API_ID_HERE",
    "api_key": "API_KEY_HERE",
    "request_type": "GET",
    "host": "analysiscenter.veracode.com",
    "endpoint": "/api/5.0/getapplist.do"
  }
}

With Params:

{
  "body": {
    "api_id": "API_ID_HERE",
    "api_key": "API_KEY_HERE",
    "request_type": "GET",
    "host": "analysiscenter.veracode.com",
    "endpoint": "/api/5.0/detailedreport.do?build_id=X"
  }
}
---------------------------------------
*/

const crypto = require('crypto');
const http = require('https');

const preFix = "VERACODE-HMAC-SHA-256";
const verStr = "vcode_request_version_1";

exports.handler = async (event, context, callback) => {
    
    var requestBody = event['body'];
    
    if(checkJSON(requestBody))
        requestBody = JSON.parse(requestBody);
    
    const id = requestBody['api_id'];
    const key = requestBody['api_key'];
    const endpoint = requestBody['endpoint'];
    const http_method = requestBody['request_type'];
    const host = requestBody['host'];
    
    return new Promise((resolve, reject) => {
      generateHeader(host, endpoint, http_method, id, key)
      .then(authToken =>{
            performRequest(authToken,http_method,host, endpoint)
            .then((output) => {
                sendResponse(output,callback);
            }).catch(reject);
        }).catch(reject);  
    });
};

var hmac256 = (data, key, format) => {
	var hash = crypto.createHmac('sha256', key).update(data);
	// no format = Buffer / byte array
	return hash.digest(format);
};

var getByteArray = (hex) => {
	var bytes = [];

	for(var i = 0; i < hex.length-1; i+=2){
	    bytes.push(parseInt(hex.substr(i, 2), 16));
	}

	// signed 8-bit integer array (byte array)
	return Int8Array.from(bytes);
};

var generateHeader = (host, url, method, id, key) =>{
    
    return new Promise((resolve, reject) => {
        var data = `id=${id}&host=${host}&url=${url}&method=${method}`;
    	var timestamp = (new Date().getTime()).toString();
    	var nonce = crypto.randomBytes(16).toString("hex");
    
    	// calculate signature
    	var hashedNonce = hmac256(getByteArray(nonce), getByteArray(key));
    	var hashedTimestamp = hmac256(timestamp, hashedNonce);
    	var hashedVerStr = hmac256(verStr, hashedTimestamp);
    	var signature = hmac256(data, hashedVerStr, 'hex');
    	
    	var hmac_header = `${preFix} id=${id},ts=${timestamp},nonce=${nonce},sig=${signature}`;
    	
    	resolve(hmac_header);
    });
};

var performRequest = (hmacAuthToken,requestType,host, endpoint) => {
    
    return new Promise((resolve, reject) => {
        
        var headers = { 
            Authorization: hmacAuthToken,
        }   
    
        var options = { 
            method: requestType,
            host: host,
            path: endpoint,
            contentType: 'application/json',
            headers: headers
        };
        
        const req = http.request(options, (res) => {
        var chunks = [];

        res.on("data", function (chunk) {
            chunks.push(chunk);
        });
        
        res.on("end", function () {
            var api_result = Buffer.concat(chunks).toString();
            if(checkJSON(api_result)){
                api_result = JSON.parse(api_result);   
            }
            
            var r = {
                "status": res.statusCode,
                "message": api_result
            };
            
            resolve(r);
          });
        });

        req.on('error', (e) => {
          reject(e.message);
        });
        
        req.end();
    });
};

var sendResponse = (output, callback) => {
  
  var result;
  var response = output;
  
  var response_message = response['message'];
  var response_status = response['status'];
  
  var r = createResponse(response_status,response_message);
  callback(null, r);
};

var createResponse = (status, result) => {
  var responseBody = result;
  
  var response = {
    "statusCode": status,
    "headers": { 'Content-Type': 'application/json' },
    "body":  JSON.stringify(responseBody)
  };
  
  return response;
};

var checkJSON = (str) => {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}
