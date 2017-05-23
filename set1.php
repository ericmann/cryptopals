<?php
ini_set("auto_detect_line_endings", true);
error_reporting(E_ALL ^ E_NOTICE);

function println($str)
{
  echo "$str\n";
}

class charPair {
  public $key;
  public $value;

  public function __construct($key, $val)
  {
    $this->key = $key;
    $this->value = $val;
  }
}

function xorBytes($a, $b)
{
  // Pad the key
  $key = '';
  while(strlen($key) < strlen($a)) {
    $key .= $b;
  }

  $arrayA = str_split($a);
  $arrayKey = str_split($key);

  $result = '';
  foreach($arrayA as $i => $val) {
    $result .= $val ^ $arrayKey[$i];
  }

  return $result;
}

function singleByteKeys($chars)
{
	$pairs = [];

  for($i = 0; $i <= 255; $i++) {
    $key = chr($i);
    $val = xorBytes($chars, $key);

    array_push($pairs, new charPair($key, $val));
  }

	return $pairs;
}

function englishGuess($pairs)
{
	$best = 0;
  $frequency = str_split('zqjxkvbpgyfwmculdrhsnioate');
	$result = null;

  foreach($pairs as $p) {
    $score = 0;
    $vals = str_split($p->value);
    foreach($vals as $i) {
      $score += array_search($i, $frequency);
    }
    if ($score > $best) {
      $best = $score;
      $result = $p;
    }
	}

	return $result;
}

function distance($a, $b)
{
  $result = 0;
  $arrayA = str_split($a);
  $arrayB = str_split($b);
  foreach($arrayA as $i => $val) {
    $result += gmp_hamdist(ord($val), ord($b[$i]));
  }
  return $result;
}

function guessKeySize($chars, $minSize = 2, $maxSize = 40)
{
  $result = 0;
  $best = 0;
  $checks = strlen($chars) / $maxSize;

  for ($keySize = $minSize; $keySize <= $maxSize; $keySize++) {
    $dist = 0;
    $first = substr($chars, 0, $keySize);

    for ($i = 1; $i < $checks; $i++) {
      $next = substr($chars, $keySize * $i, $keySize * ($i + 1));
      $dist += distance($first, $next);
    }
    $dist /= $keySize;
    if ($best === 0 || $dist < $best) {
      $best = $dist;
      $result = $keySize;
    }
  }

  return $result;
}

function transpose($chars, $keySize)
{
  $result = [];
  $split = str_split($chars);
  $i = 0;
  foreach($split as $char) {
    $result[$i] .= $char;
    $i++;
    if ($i == $keySize) {
      $i = 0;
    }
  }

  return $result;
}

/*************************/
/*         Tasks         */
/*************************/

// Convert hex to base64
function task1($str)
{
  $bytes = hex2bin($str);

  return base64_encode($bytes);
}

// Fixed XOR
function task2($first, $second)
{
  $firstBytes = hex2bin($first);
  $secondBytes = hex2bin($second);

  return bin2hex(xorBytes($firstBytes, $secondBytes));
}

// Single-byte XOR cipher
function task3($str)
{
	$bytes = hex2bin($str);
	$pairs = singleByteKeys($bytes);

	$guess = englishGuess($pairs);

	return $guess->key . ": " . $guess->value;
}

// Detect single-character XOR
function task4($path)
{
  $all = [];

  $handle = fopen($path, 'r');
  if ($handle) {
    while(($buffer = fgets($handle, 4906)) !== false) {
      $line = trim(preg_replace('/\s+/', '', $buffer));
      $bytes = hex2bin($line);
      $pairs = singleByteKeys($bytes);
      foreach($pairs as $pair) {
        array_push($all, $pair);
      }
    }

    fclose($handle);

    $guess = englishGuess($all);
    return $guess->key . ": " . $guess->value;
  }

  return 'fopen Error';
}

// Repeating key XOR
function task5($str, $key)
{
  return bin2hex(xorBytes($str, $key));
}

// Break repeating-key XOR
function task6($path, $minKeySize, $maxKeySize)
{
  $data = file_get_contents($path);
  $decoded = base64_decode($data);

  // Estimate key size
  $keySize = guessKeySize($decoded, $minKeySize, $maxKeySize);

  $key = '';

  // Transpose blocks
  $blocks = transpose($decoded, $keySize);
  foreach($blocks as $block) {
    // Solve each block
    $guess = englishGuess(singleByteKeys($block));

    // Compose key
    $key .= $guess->key;
  }

  // Decrypt
  $value = xorBytes($decoded, $key);
  return "Key: {$key}\n{$value}";
}

// Decrypt AES
function task7($path, $key)
{
  $data = file_get_contents($path);
  $decoded = base64_decode($data);

  return mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $decoded, MCRYPT_MODE_ECB);
}

// Detect AES
function task8($path)
{
  $all = [];

  $handle = fopen($path, 'r');
  if ($handle) {
    while(($buffer = fgets($handle, 4906)) !== false) {
      $line = trim(preg_replace('/\s+/', '', $buffer));

      $encrypted = base64_decode($line);
      $encSize = strlen($encrypted);

      // Keep track of each 16-byte block
      $blocks = [];
      for ($i = 0; $i < $encSize; $i += 16) {
        $block = substr($encrypted, $i, 16);
        $exists = in_array($block, $blocks);

        // If we find a duplicate ciphertext, we've found a duplicate plaintext
        if ($exists) {
          fclose($handle);
          return $line;
        }

        // No duplicate exists
        array_push($blocks, $block);
      }
    }

    fclose($handle);

    return 'No AES';
  }

  return 'fopen Error';
}

function main()
{
  // Challenge 1
  println("1: " . task1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));

  // Challenge 2
  println("2: " . task2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"));

  // Challenge 3
  println("3: " . task3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));

  // Challenge 4
  println("4: " . task4("data/4.txt"));

  // Challenge 5
  println("5: " . task5("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"));

  // Challenge 6
  println(distance("this is a test", "wokka wokka!!!"));
  println("6: " . task6("data/6.txt", 2, 40));

  // Challenge 7
  println("7: " . task7("data/7.txt", "YELLOW SUBMARINE"));

  // Challenge 8
  println("8: " . task8("data/8.txt"));
}

main();
