function println(str) {
  process.stdout.write(str + "\n");
}

function xorBytes(a, b) {
  // Pad the key
  let key = '';
  while(key.length < a.length) {
    key = key.concat(b);
  }

  let result = [];
  for(let i = 0; i < a.length; i++) {
    result.push(a[i] ^ key.charCodeAt(i));
  }

  return result;
}

function singleByteKeys(chars) {
	let pairs = []

  for(let i = 0; i <= 255; i++) {
    let key = new Buffer([i]);
    let val = xorBytes(chars, key);

    pairs.push({'key': key, 'value': new Buffer(val)});
  }

	return pairs;
}

function englishGuess(pairs) {
	let best = 0;
  let frequency = 'zqjxkvbpgyfwmculdrhsnioate';
	let result = null;

  for (const p of pairs) {
    let score = 0;

    for (const i of p.value) {
      let letterScore = frequency.indexOf(String.fromCharCode(i));
      if (letterScore > 0) score += letterScore;
    }
    if (score > best) {
      best = score;
      result = p;
    }
  }

	return result;
}

function distance(a, b) {
  let result = 0;

  for (let c of xorBytes(new Buffer(a), new Buffer(b))) {
    for (let i = 0; i < 8; i++) {
      result += c & 1;
      c >>= 1;
    }
  }

  return result;
}

function guessKeySize(chars, minSize, maxSize) {
  let result = 0;
  let best = 0;
  let checks = chars.byteLength / maxSize;

  for (let keySize = minSize; keySize <= maxSize; keySize++) {
    let dist = 0;
    let first = chars.slice(0, keySize);

    for (let i = 1; i < checks; i++) {
      let next = chars.slice(keySize * i, keySize * (i + 1));
      dist += distance(first, next);
    }
    dist /= keySize;
    if (best === 0 || dist < best) {
      best = dist;
      result = keySize;
    }
  }

  return result;
}

function transpose(chars, size) {
	let result = [];
  let i = 0;

  for (char of chars) {
    if (result[i] === undefined) {
      result[i] = [];
    }

    result[i].push(char);
    i++;
    if (i == size) {
      i = 0;
    }
  }

	return result;
}

/*************************/
/*         Tasks         */
/*************************/

// Convert hex to base64
function task1(str) {
  let bytes = new Buffer(str, 'hex');

  return bytes.toString('base64');
}

// Fixed XOR
function task2(first, second) {
  let firstBytes = new Buffer(first, 'hex');
  let secondBytes = new Buffer(second, 'hex');

  return new Buffer(xorBytes(firstBytes, secondBytes)).toString('hex');
}

// Single-byte XOR cipher
function task3(str) {
  let bytes = new Buffer(str, 'hex');
  let pairs = singleByteKeys(bytes);
  let guess = englishGuess(pairs);

  return guess.key + ': ' + guess.value;
}

// Detect single-character XOR
function task4(path) {
  return new Promise((resolve, reject) => {
    let lineReader = require('readline').createInterface({
      input: require('fs').createReadStream(path)
    });

    let all = [];

    lineReader.on('line', function(line) {
      let bytes = new Buffer(line, 'hex');
      let pairs = singleByteKeys(bytes);

      for (const p of pairs) {
        all.push(p);
      }
    });

    lineReader.on('close', function() {
      let guess = englishGuess(all);

      resolve(guess.key + ': ' + guess.value);
    });
  });
}

// Repeating key XOR
function task5(str, key) {
  return new Buffer(xorBytes(new Buffer(str), new Buffer(key))).toString('hex');
}

// Break repeating-key XOR
function task6(path, minKeySize, maxKeySize) {
  let data = require('fs').readFileSync(path);
  let decoded = new Buffer(data.toString(), 'base64');

  // Estimate key size
  let keySize = guessKeySize(decoded, minKeySize, maxKeySize);

  let key = '';

  // Transpose blocks
  let blocks = transpose(decoded, keySize);
  for (block of blocks) {
    // Solve each block
    let guess = englishGuess(singleByteKeys(new Buffer(block)));

    // Compose key
    key += guess.key.toString();
  }

  // Decrypt
  value = xorBytes(decoded, key);
  return "Key: " + key + "\n" + new Buffer(value).toString();
}

// Decrypt AES
function task7(path, key) {
  let data = require('fs').readFileSync(path, 'utf8');
  let decoded = new Buffer(data, 'base64');
  let crypto = require('crypto');
  let alg = 'aes-128-ecb';

  let decipher = crypto.createDecipheriv(alg, new Buffer(key), '');
  decipher.setAutoPadding(false);
  let plain = decipher.update(decoded);

  return plain;
}

// Detect AES
function task8(path) {
  return new Promise((resolve, reject) => {
    let lineReader = require('readline').createInterface({
      input: require('fs').createReadStream(path)
    });

    lineReader.on('line', function(line) {
      let encrypted = Buffer.from(line, 'hex');
      let encSize = encrypted.length;

      // Keep track of each 16-byte block
      let blocks = {};
      for (let i=0; i < encSize; i += 16) {
        let block = encrypted.slice(i, i + 16).toString('hex');
        if (blocks[block]) {
          lineReader.close();
          return resolve(line);
        } else {
          blocks[block] = true;
        }
      }
    });
  });
}

function main()
{
  // Challenge 1
  println("1: " + task1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));

  // Challenge 2
  println("2: " + task2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"));

  // Challenge 3
  println("3: " + task3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));

  // Challenge 4
  task4("data/4.txt").then((out) => println("4: " + out));

  // Challenge 5
  println("5: " + task5("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"));

  // Challenge 6
  println(distance("this is a test", "wokka wokka!!!"));
  println("6: " + task6("data/6.txt", 2, 40));

  // Challenge 7
  println("7: " + task7("data/7.txt", "YELLOW SUBMARINE"));

  // Challenge 8
  task8("data/8.txt").then((out) => println("8: " + out));
}

main();
