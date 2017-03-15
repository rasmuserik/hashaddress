/*
 * Hashes as addresses, and utility functions for Kademlia-like routing.
 */
class HashAddress { // #

  constructor(o) { // ##
    if(o instanceof Uint8Array && o.length === 32) {
      this.data = o;
    } else {
      throw new Error();
    }
  }

  static async generate (src /*ArrayBuffer | String*/) { // ##
    if(typeof src === 'string') {
      src = ascii2buf(src);
    }
    let hash = await crypto.subtle.digest('SHA-256', src);
    return new HashAddress(new Uint8Array(hash));
  }

  equals(addr) { // ##
    for(let i = 0; i < 32; ++i) {
      if(this.data[i] !== addr.data[i]) {
        return false;
      }
    }
    return true;
  }

  static async TEST_constructor_generate_equals() { // ##
    if(typeof crypto === 'undefined') {
      return;
    }
    let a = await HashAddress.generate('hello world');
    let b = await HashAddress.generate('hello world');
    let c = await HashAddress.generate('hello wørld');
    a.equals(b) || throwError('equals1');
    !a.equals(c) || throwError('equals2');
  }

  static fromArrayBuffer(buf) { // ##
    return new HashAddress(new Uint8Array(buf));
  }

  static fromString(str) { // ##
    return HashAddress.fromArrayBuffer(ascii2buf(atob(str)));
  }

  static fromHex(str) {  // ##
    return HashAddress.fromArrayBuffer(hex2buf(str));
  }

  toArrayBuffer() { // ##
    return this.data.slice().buffer;
  }

  toString() { // ##
    return btoa(buf2ascii(this.toArrayBuffer()));
  }

  toHex() { // ##
    return buf2hex(this.toArrayBuffer());
  }


  static async TEST_from_toArrayBuffer_toString() { // ##
    let a = await HashAddress.generate('hello');
    let b = HashAddress.fromArrayBuffer(a.toArrayBuffer());
    let c = HashAddress.fromString(a.toString());
    let x80 = HashAddress.fromString('gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
    a.equals(b) || throwError();
    a.equals(c) || throwError();
    x80.toHex().startsWith('800') || throwError();
  }

  // ## .dist(addr)
  /*
   * xor-distance between two addresses, - with 24 significant bits, 
   * and with an offset such that the distance between `0x000..` 
   * and `0x800...` is `2 ** 123`, and distance `0b1111..` and 
   * `0b1010111..` is `2**122 + 2**120`. 
   * This also means that the distance can be represented 
   * within a single precision float. (with some loss on least significant bits)
   */
  dist(addr) {
    let a = new Uint8Array(this.data);
    let b = new Uint8Array(addr.data);
    for(let i = 0; i < 32; ++i) {
      if(a[i] !== b[i]) {
        return (2 ** (93 - i*8)) *
          (((a[i] ^ b[i]) << 23) |
          ((a[i + 1] ^ b[i + 1]) << 15) |
          ((a[i + 2] ^ b[i + 2]) << 7) |
          ((a[i + 3] ^ b[i + 3]) >> 1));
      }
    }
    return 0;
  }

  // ## distBit(addr)
  /* 
   * index of first bit in addr that is different. 
   */
  distBit(addr) {
    return HashAddress.distBit(this.dist(addr));
  }

  // ## static distBit(addr)
  /*
   * addr1.logDist(addr2) === HashAddress.logDist(addr1.dist(addr2))
   */
  static distBit(dist) {
    return 123 - Math.floor(Math.log2(dist));
  }

  static TEST_dist() { // ##
    let h;
    let zero = 
      HashAddress.fromHex('0000000000000000000000000000000000000000000000000000000000000000');

    h=HashAddress.fromHex('0000000000000000000000000000001000000000000000000000000000000000');
    zero.dist(h) === 1 || throwError();

    h=HashAddress.fromHex('8000000000000000000000000000000000000000000000000000000000000000');
    zero.dist(h) === 2 ** 123 || throwError();
    zero.distBit(h) === 0 || throwError();

    h=HashAddress.fromHex('0000000000000000000000000000000000000000000000000000000000000001');
    zero.dist(h) === 2 ** -132|| throwError();
    zero.distBit(h) === 255 || throwError();

    h=HashAddress.fromHex('0f00000000000000000000000000000000000000000000000000000000000000');
    zero.distBit(h) === 4 || throwError();
  }

  // ## flipBitRandomise
  /**
   * Flip the bit at pos, and randomise every bit after that
   */
  flipBitRandomise(pos) {
    let src = new Uint8Array(this.data);
    let dst = src.slice();
    let bytepos = pos >> 3;
    crypto.getRandomValues(dst.subarray(bytepos));

    let mask = 0xff80 >> (pos & 7);
    let inverse = 0x80 >> (pos & 7);
    dst[pos >> 3] = (src[bytepos] & mask) | (dst[bytepos] & ~mask) ^ inverse;

    return new HashAddress(dst);
  }

  static TEST_flipBitRandomise() { // ##
    let zero = 
      HashAddress.fromHex('0000000000000000000000000000000000000000000000000000000000000000');

    zero.flipBitRandomise(3).toHex().startsWith('1') || throwError();
    zero.flipBitRandomise(7).toHex().startsWith('01') || throwError();
    zero.flipBitRandomise(7+8).toHex().startsWith('0001') || throwError();
  }
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

// # Export + testrunner
(()=>{
  let runTest = (cls) => Promise.all(
      Object.getOwnPropertyNames(HashAddress)
      .filter(k => k.startsWith('TEST_'))
      .map(k => (console.log(k), k))
      .map(k => HashAddress[k]())
      .map(v => Promise.resolve(v)));

  if(typeof module !== 'undefined') {
    module.exports = HashAddress;
    if(require.main === module) {
      runTest(HashAddress)
        .then(() => process.exit(0))
        .catch(e => {
          console.log(e);
          process.exit(0);
        });
    }
  } else if(typeof RUNTEST_hashaddress !== 'undefind') {
    runTest(HashAddress);
  }
})()
