# HashAddress

**Under development, not ready yet**


Hashes as addresses, and utility functions for Kademlia-like routing.

- `HashAddress.generate(ArrayBuffer | String) →  Promise(addr)`
- `HashAddress.from(ArrayBuffer | String) →  addr`
- `addr.randomise(startBit)  →   addr`
- `addr.toArrayBuffer() →  ArrayBuffer`
- `addr.toString() →  String`
- `addr.equals(addr)  →   Boolean`
- `addr.dist(addr)  →  Number` xor-distance between two addresses, - with 24 significant bits, and with an offset such that the distance between `0x000..` and `0x800...` is `2 ** 126`, and distance `0b1111..` and `0b1010111..` is `2**125 + 2**123`. Smallest distance is `2**-97`. This also means that the distance can be represented within a single precision float.
- `addr.logDist() →  Number` index of first bit in addr that is different.
