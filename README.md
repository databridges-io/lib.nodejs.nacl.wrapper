![](https://img.shields.io/badge/Licence-MIT-green.svg)![](https://shields.io/badge/node.js-%3E=10.0%20LTS-blue)

# Databridges NodeJS NaCl Wrapper Library

Databridges NACL wrapper gives you a simple write and read function using implementation of the secretbox encryption standard defined in NaCl.

Databridges NACL wrapper is available for 

- [JavaScript](https://github.com/databridges-io/lib.javascript.nacl.wrapper.git) 
- [NodeJS](https://github.com/databridges-io/lib.nodejs.nacl.wrapper.git)
- [C#](https://github.com/databridges-io/lib.csharp.nacl.wrapper.git)
- [Python](https://github.com/databridges-io/lib.python.nacl.wrapper.git)
- [Java for Android](https://github.com/databridges-io/lib.android.nacl.wrapper.git)
- [iOS Swift](https://github.com/databridges-io/lib.ios.nacl.wrapper.git)

The above wrappers can be used to send encrypted messages between them.

> The Databridges NACL wrapper for NodeJS Language binding uses `tweetnacl` to deliver implementation of the secretbox encryption standard defined in NaCl.

## Usage Overview

The following topics are covered:

  - [Supported platforms](#supported-platforms)
  - [Installation.](#installation)
  - [Initialization](#initialization)
  - [Global Configuration](#global-configuration)
  - [How to use with Databridges Nodejs Library](#how-to-use-with-databridges-nodejs-library)
  - [Change Log](#change-log)
  - [License](#license)

## Supported platforms

Node.js version 10 or newer. (The current Long Term Support (LTS) release is an ideal starting point).

## Installation.

You can use NPM package manager to install the package.

```bash
npm install databridges-nacl-wrapper --save
```


## Initialization

```js
const dbNaClWrapper = require('databridges-nacl-wrapper');
const secretData = new dbNaClWrapper();
```

## Global Configuration

### Required

The following is the required properties before using to dataBridges NaCl wrapper.

```javascript
secretData.secret = '32 char alphanumeric string';
```

| Properties | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| `secret`   | *(string)* 32 char alpha numeric string. NaCl encryption secret. |

## Encrypt data

To encrypt data using NaCl, databridges wrapper exposes a method named `write`, This will return encrypted data if successful else it will throw error.

#### write() 

```javascript
try {
    const encData = secretData.write("Your Data..");
    console.log('Encrypted:', encData);
} catch (err) {
    console.log('Errors:', err.source, err.code, err.message);
}
```

| Parameter | Description                        |
| --------- | ---------------------------------- |
| `data`    | *(string)* *data* to be encrypted. |

| Return Values | Description        |
| ------------- | ------------------ |
| `string`      | Encrypted  string. |

##### Exceptions: 

| Source             | Code           | Description                                    |
| ------------------ | -------------- | ---------------------------------------------- |
| DBLIB_NACL_WRAPPER | INVALID_SECRET | `secret` is not set with the wrapper instance. |
| DBLIB_NACL_WRAPPER | INVALID_DATA   | If `data` is not passed to the function.       |
| DBLIB_NACL_WRAPPER | NACL_EXCEPTION | Exceptions generated by NaCl library.          |

## Decrypt data

To decrypt data using NaCl, databridges wrapper exposes a method named `read`, This will return decrypted data if successful else it will throw error.

#### read() 

```javascript
try {
    const decData = secretData.read("<Encrypted data.>");
    console.log('Decrypted:', decData);
} catch (err) {
    console.log('Errors', err.source, err.code, err.message);
}
```

| Parameter | Description                        |
| --------- | ---------------------------------- |
| `data`    | *(string)* *data* to be encrypted. |

| Return Values | Description        |
| ------------- | ------------------ |
| `string`      | Encrypted  string. |

##### Exceptions: 

| Source             | Code                | Description                                                  |
| ------------------ | ------------------- | ------------------------------------------------------------ |
| DBLIB_NACL_WRAPPER | INVALID_SECRET      | `secret` is not set with the wrapper instance.               |
| DBLIB_NACL_WRAPPER | INVALID_DATA        | If `data` is not passed to the function OR `data` is not a valid encrypted string. |
| DBLIB_NACL_WRAPPER | NACL_EXCEPTION      | Exceptions generated by NaCl library.                        |
| DBLIB_NACL_WRAPPER | NACL_DECRYPT_FAILED | If decryption fails due to invalid secret or manipulated data. |

## How to use with Databridges Nodejs Library

Below code shows how to integrate the NaCl wrapper with the Databridges library. After initialize you can use the wrapper library to encrypt and decrypt the data when publishing and receiving events.

```javascript
// Initialize both databridges-sio-client-lib and databridges-nacl-wrapper
const dBridges = require('databridges-sio-client-lib');
const dbNaClWrapper = require('databridges-nacl-wrapper');

const dbridge = new dBridges();
const secretData = new dbNaClWrapper();
secretData.secret = "Your32 char secret.";

// .... Your databridges code comes here.

// On Subscription success event.
subscribeChannel.bind("dbridges:subscribe.success", (payload, metadata) => {
    console.log('Channel subscribe => bind', metadata.eventname, payload, JSON.stringify(metadata));
    try {
        // Encrypt data to publish.
        const encData = secretData.write("Your Data.."); 
        subscribeChannel.publish("eventName", encData, "1") 
    } catch (err) {
        console.log('Error:', err.source, err.code, err.message);
    }
});

// On payload Received event.
subscribeChannel.bind("eventName", (payload, metadata) => {
    console.log('eventName=> bind', metadata.eventname, payload, JSON.stringify(metadata));
    try {
        // Decrypt data received in the event.
        const decData = secretData.read(payload);
        console.log('Decrypted:', decData);
    } catch (err) {
        console.log('Error:', err.source, err.code, err.message);
    }
});
```



## Change Log
  * [Change log](CHANGELOG.md): Changes in the recent versions

## License

DataBridges NaCl Wrapper is released under the [MIT license](LICENSE).

```
    Copyright 2022 Optomate Technologies Private Limited.

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

