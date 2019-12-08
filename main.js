import { generateRsaKeys, stringToHex, stringFromHex, sign, decryptSignature, sha256 } from './lib.js';

const generateKeysButton = document.getElementById('generate-keys');
const keySizeInput = document.getElementById('key-size');
const nTextarea = document.getElementById('n-value');
const eTextarea = document.getElementById('e-value');
const dTextarea = document.getElementById('d-value');

const signMessageButton = document.getElementById('sign-message');
const messageTextarea = document.getElementById('message');
const messageBigIntTextarea = document.getElementById('message-bigint');
const messageSha256BigIntTextarea = document.getElementById('message-sha256-bigint');
const plainRsaSignatureTextarea = document.getElementById('plain-rsa-signature');
const sha256RsaSignatureTextarea = document.getElementById('sha256-rsa-signature');

const verifyRsaSignatureButton = document.getElementById('verify-rsa-signature');
const verifySha256SignatureButton = document.getElementById('verify-sha256-signature');
const messageToVerifyTextarea = document.getElementById('message-to-verify');
const rsaSignatureToVerifyTextarea = document.getElementById('rsa-signature-to-verify');
const decryptedMessageBigIntTextarea = document.getElementById('decrypted-message-bigint');
const decryptedMessageTextarea = document.getElementById('decrypted-message');

const verifyForgedButton = document.getElementById('verify-forged');
const forgedMessage1Textarea = document.getElementById('forged-message-1');
const forgedMessage2Textarea = document.getElementById('forged-message-2');
const forgedSignature1Textarea = document.getElementById('forged-signature-1');
const forgedSignature2Textarea = document.getElementById('forged-signature-2');

let keys;

generateKeysButton.onclick = async function() {
    const keySize = parseInt(keySizeInput.value);
    keys = await generateRsaKeys(keySize);
    nTextarea.value = keys.n;
    eTextarea.value = keys.e;
    dTextarea.value = keys.d;
};

signMessageButton.onclick = async function() {
    const message = messageTextarea.value;
    let timeStart = +Date.now()
    const messageBigInt = BigInt(stringToHex(message) || 0);
    const plainSignature = sign(messageBigInt, keys.d, keys.n);
    console.log(`Plain signing took ${+Date.now() - timeStart} ms.`);
    messageBigIntTextarea.value = messageBigInt;
    plainRsaSignatureTextarea.value = plainSignature;
    timeStart = +Date.now();
    const digest = await sha256(message);
    const digestBigInt = BigInt('0x' + digest);
    const digestSignature = sign(digestBigInt, keys.d, keys.n);
    console.log(`Digest signing took ${+Date.now() - timeStart} ms.`);
    messageSha256BigIntTextarea.value = digestBigInt;
    sha256RsaSignatureTextarea.value = digestSignature;
}

verifyRsaSignatureButton.onclick = function() {
    const message = messageToVerifyTextarea.value;
    const signature = BigInt(rsaSignatureToVerifyTextarea.value || 0);
    let timeStart = +Date.now()
    const messageBigInt = BigInt(stringToHex(message) || 0);
    const decryptedMessage = decryptSignature(signature, keys.e, keys.n);
    const correct = messageBigInt === decryptedMessage;
    console.log(`Plain verifying took ${+Date.now() - timeStart} ms.`);
    decryptedMessageBigIntTextarea.value = decryptedMessage;
    decryptedMessageTextarea.value = stringFromHex(decryptedMessage.toString(16));
    alert(`Signature is ${correct ? 'correct' : 'incorrect'}`);
}

verifySha256SignatureButton.onclick = async function() {
    const message = messageToVerifyTextarea.value;
    const signature = BigInt(rsaSignatureToVerifyTextarea.value || 0);
    let timeStart = +Date.now()
    const digest = await sha256(message);
    const digestBigInt = BigInt('0x' + digest);
    const decryptedMessage = decryptSignature(signature, keys.e, keys.n);
    const correct = digestBigInt === decryptedMessage;
    console.log(`Digest verifying took ${+Date.now() - timeStart} ms.`);
    decryptedMessageTextarea.value = stringFromHex(decryptedMessage.toString(16));
    alert(`Signature is ${correct ? 'correct' : 'incorrect'}`);
}

verifyForgedButton.onclick = function() {
    const messageBigInt = (BigInt(forgedMessage1Textarea.value) * BigInt(forgedMessage2Textarea.value)) % keys.n;
    const signature = (BigInt(forgedSignature1Textarea.value) * BigInt(forgedSignature2Textarea.value)) % keys.n;
    const correct = messageBigInt === decryptSignature(signature, keys.e, keys.n);;
    alert(`Signature is ${correct ? 'correct' : 'incorrect'}`);
}