/*
 * Hashes as addresses, and utility functions for Kademlia-like routing.
 */
class HashAddress {

  static async generate (addr /*ArrayBuffer | String*/) {
    /* ...await crypto.subtle.digest ...*/
    return new HashAddress(/*...*/);
  }

  static from(addr /*ArrayBuffer | String*/) {
    return new HashAddress(/*...*/);
  }

  constructor(o) {
    if(o instanceof Uint8Array && o.length === 32) {
      this.data = o;
    } else {
      throw new Error();
    }
  }

  randomise(startBit) {
    return new HashAddress(/*...*/);
  }

  toArrayBuffer() {
  }

  toString() {
  }

  equals(addr) {
  }
  /*
   * xor-distance between two addresses, - with 24 significant bits, 
   * and with an offset such that the distance between `0x000..` 
   * and `0x800...` is `2 ** 126`, and distance `0b1111..` and 
   * `0b1010111..` is `2**125 + 2**123`. 
   * Smallest distance is `2**-97`. 
   * This also means that the distance can be represented 
   * within a single precision float.
   */
  dist(addr) {
  }

  /*
   * addr1.logDist(addr2) === HashAddress.logDist(addr1.dist(addr2))
   */
  static logDist(dist) {
  }

  /* 
   * index of first bit in addr that is different. 
   */
  logDist(addr) {

  }
}

module.exports = HashAddress;
