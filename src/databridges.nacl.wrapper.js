
/*
    DataBridges Node.js NaCl wrapper for databridges library.
    https://www.databridges.io/ 

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
*/
const nacl = require('./nacl'); 
nacl.util = require('./nacl-util');

class databridges_nacl_wrapper 
{

    constructor(){
        this.secret = undefined;
    }

    write(data) {
        if (!(this.secret)) {
            throw (new dBError("INVALID_SECRET",""));
            return false;
        }
        if (!(data)) {
            throw (new dBError("INVALID_DATA", ""));
            return false;
        }
        try {
            const msecretKey = nacl.util.decodeUTF8(this.secret);
            const nonce = nacl.randomBytes(24);
            const secretData = nacl.util.decodeUTF8(data);
            const box = nacl.secretbox(secretData, nonce, msecretKey);
            const result = nacl.util.encodeBase64(nonce) + ":" + nacl.util.encodeBase64(box);
            return result;
        } catch (err) {
            throw (new dBError("NACL_EXCEPTION", err.message));
        }
    } 

    read(encrypData) {
        if (!(this.secret)) {
            throw (new dBError("INVALID_SECRET", ""));
            return false;
        }
        if (!(encrypData)) {
            throw (new dBError("INVALID_DATA", ""));
            return false;
        }
        if (!(encrypData.includes(":"))) {
            throw (new dBError("INVALID_DATA", ""));
            return false;
        }
        try {
            const msecretKey = nacl.util.decodeUTF8(this.secret);
            let encrypted = encrypData.split(':');
            let nonce = nacl.util.decodeBase64(encrypted[0]);
            encrypted = nacl.util.decodeBase64(encrypted[1]);
            const decrypted = nacl.secretbox.open(encrypted, nonce, msecretKey);
            if (!decrypted) {
                throw (new dBError("NACL_DECRYPT_FAILED", "Decryption failed, either data is encrypted with different secret or data is manipulated."));
                return false;
            } else {
                const decryptedm = nacl.util.encodeUTF8(decrypted);
                return decryptedm;
            }
        } catch (err) {
            throw (new dBError("NACL_EXCEPTION", err.message));
        }
    }
}

class dBError extends Error {
    constructor(errCode,errMessage) {
        super(errCode, errMessage);
        this.source = "DBLIB_NACL_WRAPPER";
        this.code = errCode;
        this.message = errMessage;
        Error.captureStackTrace(this, this.constructor);
    }
     
}

module.exports = databridges_nacl_wrapper;