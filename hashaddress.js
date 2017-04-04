// Hashes as addresses, and utility functions for Kademlia-like routing.
//

let length = 96/6;
let tests = {};
// # Base64 alphabet
let base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
tests.TEST_base64 = () => {
  base64[63] === '/' || throwError();
}

async function hashAddress(src) { // #
  if(typeof src === 'string') {
    src = ascii2buf(src);
  }
  let hash = await crypto.subtle.digest('SHA-256', src);
  return btoa(buf2ascii(new Uint8Array(hash))).slice(0,length);
}
tests.TEST_hashAddress = async () => {
  (await hashAddress('hello')) === 'LPJNul+wow4m6Dsq' || throwError();
}

// # `dist(a,b)`
//
// Calculate xor-distance between two base64 addresses.
//
function dist(a, b) {
  let len = Math.min(a.length, b.length);
  let dist = 0;
  let i = 0;
  for(;;) {
    va = base64.indexOf(a[i]);
    vb = base64.indexOf(b[i]);
    if(va === -1 || vb === -1) {
      return dist;
    }
    dist += (va ^ vb) * (2 ** (-5 - 6*i));
    ++i;
  }
}
tests.TEST_distBit = () => {
  dist('Abracadabra', 'Abracadabra') === 0 || throwError();
  dist('A', 'B') ===  2 ** -5 || throwError();
}

// # `distBit(a,b)`
//
// Get the position of the first bit that differs in a,b. This is logarithmic xor-distance.
//
function distBit(a, b) {
  return Math.ceil(Math.log(1/dist(a,b)) / Math.log(2));
}
tests.TEST_distBit = () => {
  distBit('A', base64[32]) === 0 || throwError();
  distBit('A', base64[31]) === 1 || throwError();
  distBit('AA', 'A/') === 6 || throwError();
  distBit('A', 'A') === Infinity || throwError();
}

// # `flipBitAndRandom(addr, bitpos)`
//
// Create a new address, preserving the first `bitpos - 1` bits, the bit at `bitpos` is flipped, and the rest of the bits are random.
//
function flipBitAndRandom(addr, bitpos) {
  let result = addr.slice(0, bitpos / 6 | 0);

  let word = base64.indexOf(addr[bitpos / 6 | 0]);
  if(word === -1) {
    word = 0;
  }
  let flipBits = 64 + (Math.random() * 64) >> ((bitpos % 6) + 1);
  word = word ^ flipBits;
  result += base64[word];

  for(let i = (bitpos / 6)+1 | 0; i < length; ++i) {
    result += base64[Math.random() * 64 | 0];
  }

  return result;
}
tests.TEST_flipBitAndRandom = () => {
  flipBitAndRandom('AAAAAA', 11).startsWith('AB') || throwError();
  flipBitAndRandom('//////', 17).startsWith('//+') || throwError();
  flipBitAndRandom('A', 6).startsWith('A') || throwError();
  flipBitAndRandom('B', 5).startsWith('A') || throwError();
  for(let i = 0; i < 10; ++i) {
    "CD".indexOf(flipBitAndRandom('A', 4)[0]) !== -1 || throwError();
    "EFGH".indexOf(flipBitAndRandom('A', 3)[0]) !== -1 || throwError();
  }
}

// # Exports

if(typeof module !== 'undefined') {
  exports.hashAddress = hashAddress;
  exports.dist = dist;
  exports.distBit = distBit;
  exports.flipBitAndRandom = flipBitAndRandom;
  exports.TESTS = tests;
}

// # Utility functions

function hex2buf(str) { // ##
  let a = new Uint8Array(str.length / 2);
  for(let i = 0; i < str.length; i += 2) {
    a[i / 2] = parseInt(str.slice(i, i+2), 16);
  }
  return a.buffer;
}
function buf2hex(buf) { // ##
  let a = new Uint8Array(buf);
  let str = '';
  for(var i = 0; i < a.length; ++i) {
    str += (0x100 + a[i]).toString(16).slice(1);
  }
  return str;
}
function ascii2buf(str) { // ##
  let a = new Uint8Array(str.length);
  for(let i = 0; i < a.length; ++i) {
    a[i] = str.charCodeAt(i);
  }
  return a.buffer;
}

function buf2ascii(buf) { // ##
  let a = new Uint8Array(buf);
  return String.fromCharCode.apply(String, a);
}

function throwError(msg) { // ##
  throw new Error(msg);
}
