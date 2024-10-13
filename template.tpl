___TERMS_OF_SERVICE___

By creating or modifying this file you agree to Google Tag Manager's Community
Template Gallery Developer Terms of Service available at
https://developers.google.com/tag-manager/gallery-tos (or such other URL as
Google may provide), as modified from time to time.


___INFO___

{
  "type": "MACRO",
  "id": "cvt_temp_public_id",
  "version": 1,
  "securityGroups": [],
  "displayName": "Clean or Redact PII from URLs",
  "description": "Cleans PII from URLs by deleting, redacting, or masking query parameters based on key or value, with support for regular expressions.",
  "containerContexts": [
    "SERVER"
  ]
}


___TEMPLATE_PARAMETERS___

[
  {
    "type": "TEXT",
    "name": "url",
    "displayName": "URL",
    "simpleValueType": true,
    "valueHint": "https://domain.com"
  },
  {
    "type": "PARAM_TABLE",
    "name": "paramKeys",
    "displayName": "Query Parameter Keys",
    "paramTableColumns": [
      {
        "param": {
          "type": "TEXT",
          "name": "keyContents",
          "displayName": "Parameter key",
          "simpleValueType": true,
          "help": "The parameter key or name"
        },
        "isUnique": false
      },
      {
        "param": {
          "type": "SELECT",
          "name": "matchCondition",
          "displayName": "Match Condition",
          "macrosInSelect": false,
          "selectItems": [
            {
              "value": "equals",
              "displayValue": "equals"
            },
            {
              "value": "equalsIgnore",
              "displayValue": "equals (ignore case)"
            },
            {
              "value": "matchesRegEx",
              "displayValue": "matches RegEx"
            },
            {
              "value": "matchesRegExIgnore",
              "displayValue": "matches RegEx (ignore case)"
            }
          ],
          "simpleValueType": true
        },
        "isUnique": false
      },
      {
        "param": {
          "type": "SELECT",
          "name": "replacementType",
          "displayName": "Replacement Type",
          "macrosInSelect": false,
          "selectItems": [
            {
              "value": "Redact",
              "displayValue": "Redact"
            },
            {
              "value": "Delete",
              "displayValue": "Delete"
            },
            {
              "value": "Mask",
              "displayValue": "Mask"
            }
          ],
          "simpleValueType": true
        },
        "isUnique": false
      },
      {
        "param": {
          "type": "TEXT",
          "name": "replacement",
          "displayName": "Replacement",
          "simpleValueType": true,
          "defaultValue": "[redact]",
          "enablingConditions": [
            {
              "paramName": "replacementType",
              "paramValue": "Redact",
              "type": "EQUALS"
            }
          ]
        },
        "isUnique": false
      }
    ],
    "help": "List the query parameter keys to redact, delete or mask. You can use different matching condition options.",
    "newRowButtonText": "New Parameter Key"
  },
  {
    "type": "PARAM_TABLE",
    "name": "paramValues",
    "displayName": "Query Parameter Values",
    "paramTableColumns": [
      {
        "param": {
          "type": "TEXT",
          "name": "regex",
          "displayName": "Parameter value regex",
          "simpleValueType": true,
          "help": "Examples: \u003csmall\u003e\u003cbr\u003eEmail: \u003cem\u003e[aA-zZ0-9._]+(@|%40)[aA-zZ0-9.-]+.[aA-zZ]\u003c/em\u003e\u003cbr\u003ePhone: \u003cem\u003e(\\+\\d+\\s)?\\(?\\d+\\)?[\\s.-]\\d+[\\s.-]\\d+\u003c/em\u003e\u003c/small\u003e"
        },
        "isUnique": false
      },
      {
        "param": {
          "type": "SELECT",
          "name": "replacementType",
          "displayName": "Replacement Type",
          "macrosInSelect": false,
          "selectItems": [
            {
              "value": "Redact",
              "displayValue": "Redact"
            },
            {
              "value": "Delete",
              "displayValue": "Delete"
            },
            {
              "value": "Mask",
              "displayValue": "Mask"
            }
          ],
          "simpleValueType": true
        },
        "isUnique": false
      },
      {
        "param": {
          "type": "TEXT",
          "name": "replacement",
          "displayName": "Replacement",
          "simpleValueType": true,
          "defaultValue": "[redact]",
          "enablingConditions": [
            {
              "paramName": "replacementType",
              "paramValue": "Redact",
              "type": "EQUALS"
            }
          ]
        },
        "isUnique": false
      }
    ],
    "help": "Query parameter values with dynamic or unknown keys can be redacted if the value matches a specified regular expression.",
    "newRowButtonText": "New Parameter Value"
  }
]


___SANDBOXED_JS_FOR_SERVER___

// APIs
// const log = require('logToConsole');
const decodeUri = require('decodeUri');
const decodeUriComponent = require('decodeUriComponent');

const encodeUriComponent = require('encodeUriComponent');
const Object = require('Object');
const getType = require('getType');
const parseUrl = require('parseUrl');
const sha256Sync = require('sha256Sync');


// Inputs
const config = {
  // 
  uri: data.url || '',
  paramKeys: data.paramKeys || [],
  paramValues: data.paramValues || [],
  // advanced
  decodeUri: getType(data.decodeUri) !== 'undefined' ? data.decodeUri : true
};

// functions

const doReplacements = function(text, row) {
  const match = text.match(row.regex);
  let textReplacement = row.replacement || '[redacted]';
  
  if (row.replacementType && row.replacementType == 'Delete') {
    textReplacement = '[delete]';
  }

  if (match) {
    if (row.replacementType && row.replacementType == 'Mask') {
      textReplacement = sha256Sync(match[0], {outputEncoding: 'hex'});
    }
    
    return doReplacements(
      text.replace(match[0], textReplacement),
      row
    );
  }

  return text;
};


const shouldRedact = function(key, row) {
  // we find if any of the query patterns match
  if (row.matchCondition == "equals") {
     return row.keyContents === key; 
  }

  if (row.matchCondition == "equalsIgnore") {
     return row.keyContents.toLowerCase() === key.toLowerCase(); 
  }
  
  if (row.matchCondition == "matchesRegEx") {
     return key.match(row.keyContents); 
  }  
  
  // regex ignore case
  return key.toLowerCase().match(row.keyContents.toLowerCase());
};

// logic

const urlObject = config.decodeUri ? 
      parseUrl(decodeUriComponent(config.uri)) : parseUrl(config.uri);

// double checking 
if (getType(urlObject) === 'undefined' || !urlObject.search) {
  return config.uri;
}

const newParams = Object.entries(urlObject.searchParams).map((entry) => {
  // if the value type is not string (could be array), replacement is not supported 
  if (getType(entry[1]) !== 'string') {
    return entry[0] + '=' + entry[1];
  }
  
  for (let i = 0; i < config.paramKeys.length; i++) {
    let row = config.paramKeys[i];
    
    if (shouldRedact(entry[0], row)) {
      if (row.replacementType && row.replacementType == "Delete") {
        return null;
      }
      
      if (!entry[1]) {
        return entry[0] + '=';
      }
      
      if (row.replacementType && row.replacementType == "Mask") {
        return entry[0] + '=' + sha256Sync(entry[1], {outputEncoding: 'hex'});
      }      
      
      return entry[0] + '=' + row.replacement;
    }
  }

  
  let paramValue = encodeUriComponent(entry[1]);
  
  paramValue = Object.values(config.paramValues)
    .reduce((value, row) => {
      return doReplacements(
        value, 
        row);
      }, paramValue);
  
  if (paramValue == '[delete]') {
    return null;
  }
  
  return entry[0] + '=' + paramValue;  
}, '').filter(a => a).join('&');


const newParamsText = newParams ? '?' + newParams : '';
// return
return urlObject.origin + urlObject.pathname + newParamsText + urlObject.hash;


___TESTS___

scenarios:
- name: Test parameter key patterns - Not decoding URI
  code: |-
    const mockData = {
      url: 'https://mydomain.com/?foo=bar&other_param=Keep&1_Param1=My%20Value%20Here&20_Name=John&30_Phone=123456890&30_Email=test%40domain.com&40_Message=this%20is%20just%20a%20test%20msg',
      paramKeys: [
        {
           keyContents: '\\d+',
           replacement: '[redacted]'
        }
      ],
      decodeUri: false
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://mydomain.com/?foo=bar&other_param=Keep&1_Param1=[redacted]&20_Name=[redacted]&30_Phone=[redacted]&30_Email=[redacted]&40_Message=[redacted]');
- name: Test parameter key patterns - Decoding URI
  code: |-
    const mockData = {
      url: 'https://mydomain.com/?foo=bar&other=Keep&1_Value=My%20Values%20Here&10_Name=Maria&20_Phone=123456890&30_Email=test%40domain.com&40_Message=this%20is%20just%20a%20test%20msg',
      paramKeys: [
        {
           keyContents: '\\d+',
           replacement: '[redacted]'
        }
      ],
      decodeUri: false
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://mydomain.com/?foo=bar&other=Keep&1_Value=[redacted]&10_Name=[redacted]&20_Phone=[redacted]&30_Email=[redacted]&40_Message=[redacted]');
- name: Test Query Parameter Key Patterns - Double encoding
  code: |-
    const mockData = {
      url: 'https://mydomain.com/?foo=bar&1_Param=My%252520Test%252520Message&10_Name=test&20_Phone=123456890&30_Email=test%40domain.com&40_Message=this%2520is%2520just%2520a%2520test%2520msg',
      paramKeys: [
        {
           keyContents: '\\d+',
           replacement: '[redacted]'
        }
      ],  decodeUri: false
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://mydomain.com/?foo=bar&1_Param=[redacted]&10_Name=[redacted]&20_Phone=[redacted]&30_Email=[redacted]&40_Message=[redacted]');
- name: Test param values
  code: |-
    const mockData = {
      url: 'https://mydomain.com/?30_Email=test%40domain.com&foo=bar',
      paramKeys: '',
      paramValues: [
        {
          regex: '[aA-zZ0-9._]+(@|%40)[aA-zZ0-9.-]+.[aA-zZ]',
          replacement: '[email]'
        }
      ],
      decodeUri: true
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://mydomain.com/?30_Email=[email]&foo=bar');
- name: Test param values 2
  code: |-
    const mockData = {
      url: 'https://mydomain.com/?1_Phone=1234568900&2_Phone=123-456-8900&3_Phone=123.456.8900&4_Phone=(123)-456.8900&5_Phone=123 456 7890&6_Phone=+91(123) 456-7890&foo=bar',
      paramKeys: '',
      paramValues: [
        {
          regex: '(%20[0-9]+(%20| )?)?(\\(|%28)?[0-9]{3}(\\)|%29)?(%20| )?[.-]?[0-9]{3}(%20| )?[.-]?[0-9]{4}',
          replacement: '[phone]'
        }
      ],
      decodeUri: true
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://mydomain.com/?1_Phone=[phone]&2_Phone=[phone]&3_Phone=[phone]&4_Phone=[phone]&5_Phone=[phone]&6_Phone=[phone]&foo=bar');
- name: Test with spaces
  code: |-
    const mockData = {
      url: 'https://www.test.com/subpath?success=1&10_Name=my%20name&20_Email=support@test.com&30_Phone=1234567890&40_Message=this%20is%20a%20test%20message,%20please%20ignore',
      paramKeys: [
        {
           keyContents: '\\d+',
           replacement: '[redacted]'
        }
      ],  decodeUri: false
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://www.test.com/subpath?success=1&10_Name=[redacted]&20_Email=[redacted]&30_Phone=[redacted]&40_Message=[redacted]');
- name: Test without query parameters
  code: |-
    const mockData = {
      url: 'https://www.test.com/thank-you-info/',
      paramKeys: [
        {
           keyContents: '\\d+',
           replacement: '[redacted]'
        }
      ],  decodeUri: false
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://www.test.com/thank-you-info/');
- name: Test with empty params
  code: |-
    const mockData = {
      url: 'https://www.test.com/thank-you-info/?Foo=bar+foo&5_From_Page=https://www.site.com/&10_Name=&20_Email=support@test.com&30_Phone=1234567890&40_Message=this%20is%20a%20test%20message,%20please%20ignore',
      paramKeys: [
        {
           keyContents: '\\d+',
           replacement: '[redacted]'
        }
      ],  decodeUri: false
    };

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo('https://www.test.com/thank-you-info/?Foo=bar%20foo&5_From_Page=[redacted]&10_Name=&20_Email=[redacted]&30_Phone=[redacted]&40_Message=[redacted]');
- name: Test more than 1
  code: "const mockData = {\n  url: 'https://www.test.com/path/?foo=bar+foo&10_Name=&20_Email=support@test.com&30_Phone=1234567890&40_Message=this%20is%20a%20test%20message,%20please%20ignore&utm_content=content&utm_source=newsletter&utm_medium=email&keep=this',\n\
    \  paramKeys: [\n    {\n      keyContents: 'foo',\n      replacement: '[redacted]'\n\
    \    },\n    {\n      keyContents: 'utm_',\n      replacement: '[redacted]'\n\
    \    },\n    {\n      keyContents: '\\\\d+',\n      replacement: '[redacted]'\n\
    \    },\n  ],  \n  decodeUri: false\n};\n\n// Call runCode to run the template's\
    \ code.\nlet variableResult = runCode(mockData);\n\n// Verify that the variable\
    \ returns a result.\nassertThat(variableResult).isEqualTo('https://www.test.com/path/?foo=[redacted]&10_Name=&20_Email=[redacted]&30_Phone=[redacted]&40_Message=[redacted]&utm_content=[redacted]&utm_source=[redacted]&utm_medium=[redacted]&keep=this');"
- name: Test key diff cases
  code: "const mockData = {\n  url: 'https://www.test.com/?foo=encode&foOO=KEEP&equalsIgnorE=encode&dontIgnoreCasE=KEEP&redactThis=encode&myregENCODEthis=encode',\n\
    \  paramKeys: [\n    {\n      keyContents: 'foo',\n      replacement: '[redacted]',\n\
    \      matchCondition: 'equals'\n    },\n    {\n      keyContents: 'fooO',\n \
    \     replacement: '[redacted]',\n      matchCondition: 'equals'\n    },    \n\
    \    {\n      keyContents: 'equalsIgnore',\n      replacement: '[redacted]',\n\
    \      matchCondition: 'equalsIgnore'      \n    },\n    {\n      keyContents:\
    \ 'dontIgnoreCase',\n      replacement: '[redacted]',\n      matchCondition: 'matchesRegEx'\n\
    \    },\n    {\n      keyContents: 'redactThis',\n      replacement: '[redacted]',\n\
    \      matchCondition: 'matchesRegEx'\n    },    \n    {\n      keyContents: 'myregEncode',\n\
    \      replacement: '[redacted]',\n      matchCondition: 'matchesRegExIgnore'\n\
    \    },\n  ],\n  decodeUri: false\n};\n\n// Call runCode to run the template's\
    \ code.\nlet variableResult = runCode(mockData);\n\n// Verify that the variable\
    \ returns a result.\nassertThat(variableResult).isEqualTo('https://www.test.com/?foo=[redacted]&foOO=KEEP&equalsIgnorE=[redacted]&dontIgnoreCasE=KEEP&redactThis=[redacted]&myregENCODEthis=[redacted]');"
- name: Test key diff cases - Delete
  code: "const mockData = {\n  url: 'https://www.test.com/?foo=encode&foOO=KEEP&equalsIgnorE=encode&dontIgnoreCasE=KEEP&redactThis=encode&myregENCODEthis=encode',\n\
    \   paramKeys: [\n    {\n      keyContents: 'foo',\n      replacement: '[redacted]',\n\
    \      matchCondition: 'equals',\n      replacementType: 'Delete'\n    },\n  \
    \  {\n      keyContents: 'fooO',\n      replacement: '[redacted]',\n      matchCondition:\
    \ 'equals',\n      replacementType: 'Delete'      \n    },    \n    {\n      keyContents:\
    \ 'equalsIgnore',\n      replacement: '[redacted]',\n      matchCondition: 'equalsIgnore',\n\
    \      replacementType: 'Delete'      \n    },\n    {\n      keyContents: 'dontIgnoreCase',\n\
    \      replacement: '[redacted]',\n      matchCondition: 'matchesRegEx',\n   \
    \   replacementType: 'Delete'      \n    },\n    {\n      keyContents: 'redactThis',\n\
    \      replacement: '[redacted]',\n      matchCondition: 'matchesRegEx',\n   \
    \   replacementType: 'Delete'      \n    },     \n    {\n      keyContents: 'myregEncode',\n\
    \      replacement: '[redacted]',\n      matchCondition: 'matchesRegExIgnore',\n\
    \      replacementType: 'Delete'   \n    },\n  ],\n  decodeUri: false\n};\n\n\
    // Call runCode to run the template's code.\nlet variableResult = runCode(mockData);\n\
    \n// Verify that the variable returns a result.\nassertThat(variableResult).isEqualTo('https://www.test.com/?foOO=KEEP&dontIgnoreCasE=KEEP');"
- name: Test key diff cases - Mask
  code: "const mockData = {\n  url: 'https://www.test.com/?foo=encode1&foOO=KEEP&equalsIgnorE=encode2&dontIgnoreCasE=KEEP&redactThis=encode3&myregENCODEthis=encode4',\n\
    \   paramKeys: [\n    {\n      keyContents: 'foo',\n      replacement: '[redacted]',\n\
    \      matchCondition: 'equals',\n      replacementType: 'Mask'\n    },\n    {\n\
    \      keyContents: 'fooO',\n      replacement: '[redacted]',\n      matchCondition:\
    \ 'equals',\n      replacementType: 'Mask'      \n    },    \n    {\n      keyContents:\
    \ 'equalsIgnore',\n      replacement: '[redacted]',\n      matchCondition: 'equalsIgnore',\n\
    \      replacementType: 'Mask'      \n    },\n    {\n      keyContents: 'dontIgnoreCase',\n\
    \      replacement: '[redacted]',\n      matchCondition: 'matchesRegEx',\n   \
    \   replacementType: 'Mask'      \n    },\n    {\n      keyContents: 'redactThis',\n\
    \      replacement: '[redacted]',\n      matchCondition: 'matchesRegEx',\n   \
    \   replacementType: 'Mask'      \n    },     \n    {\n      keyContents: 'myregEncode',\n\
    \      replacement: '[redacted]',\n      matchCondition: 'matchesRegExIgnore',\n\
    \      replacementType: 'Mask'   \n    },\n  ],\n  decodeUri: false\n};\n\n//\
    \ Call runCode to run the template's code.\nlet variableResult = runCode(mockData);\n\
    \n// Verify that the variable returns a result.\nassertThat(variableResult).isEqualTo('https://www.test.com/?foo=1ff34b0a335cb280c6771fe316bf5c4930885a6bf8eaaeb96e0658d527e04656&foOO=KEEP&equalsIgnorE=e70ebb2e5b6aad2b9f0cc6528919912b0e0b9f00d5e5c6960739cede48199a48&dontIgnoreCasE=KEEP&redactThis=61d31032d59cb9db0a94c4737403fa23e63b9e753e26f20ba47ed3313098cb8d&myregENCODEthis=05c08c6ab8e1edb4ac9896d223c4cb3033e26c8ed2b37f7735bbdbc3469838dc');"


___NOTES___

Created on 9/10/2024, 12:38:15 AM


