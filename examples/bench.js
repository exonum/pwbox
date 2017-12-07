#!/usr/bin/env node

/**
 * @license
 * Copyright 2017 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const program = require('commander');
const bench = require('benchmark');
const pwbox = require('..');
const manifest = require('../package.json');
const sodiumPwbox = pwbox.withCrypto('libsodium');

// Tested message lengths
const DEFAULT_SIZES = [
  32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
];

function createSuites (messageSizes, pwboxOptions) {
  const password = 'correct horse battery staple';
  // Interval (in seconds) between bench cycles
  const testDelay = 0.15;

  const tweetnaclSuite = new bench.Suite('pwbox.withCrypto(\'tweetnacl\')');
  const libsodiumSuite = new bench.Suite('pwbox.withCrypto(\'libsodium\')');

  messageSizes.forEach(len => {
    const data = new Uint8Array(len);
    for (let i = 0; i < data.length; i++) {
      data[i] = Math.floor(Math.random() * 256);
    }

    tweetnaclSuite.add(tweetnaclSuite.name + ', message.length = ' + len, {
      defer: true,
      delay: testDelay,
      fn: (deferred) => {
        pwbox(data, password, pwboxOptions).then(box => {
          if (!(box instanceof Uint8Array) || box.length !== len + pwbox.overheadLength) {
            throw new Error('Invalid box returned');
          }
          deferred.resolve();
        });
      }
    });

    libsodiumSuite.add(libsodiumSuite.name + ', message.length = ' + len, {
      defer: true,
      delay: 0.05,
      fn: (deferred) => {
        sodiumPwbox(data, password, pwboxOptions).then(box => {
          if (!(box instanceof Uint8Array) || box.length !== len + pwbox.overheadLength) {
            throw new Error('Invalid box returned');
          }
          deferred.resolve();
        });
      }
    });
  });

  return [tweetnaclSuite, libsodiumSuite];
}

function runSuites (suites, events) {
  if (suites.length === 0) {
    events.complete();
    return;
  }

  const suite = suites.shift();
  suite
    .on('cycle', events.cycle)
    .on('complete', () => runSuites(suites, events))
    .run();
}

/**
 * Parses an integer with an optional metric suffix 'k', 'M', or 'G'
 * (case-insensitive).
 *
 * @param {string} number
 * @returns {?number}
 */
function parseSuffixedNumber (number) {
  const matches = number.toUpperCase().match(/^(\d+)(K|M|G)?$/);
  if (!matches) return undefined;

  let value = parseInt(matches[1]);
  const suffix = matches[2];
  switch (suffix) {
    case 'K': value *= 1024; break;
    case 'M': value *= 1024 * 1024; break;
    case 'G': value *= 1024 * 1024 * 1024; break;
  }
  return value;
}

program
  .version(manifest.version)
  .arguments('[sizes]')
  .description('Benchmark pwbox performance.\n\n' +
    '  [sizes] is an optional comma-separated list of message sizes\n' +
    '  to benchmark. Numbers in sizes and options may be appended with "k", "M"\n' +
    '  or "G" suffixes to multiply the number by 2**10, 2**20, or\n' +
    '  2**30 respectively.')
  .option('-o --opslimit <ops>', 'Operations limit for pwbox', parseSuffixedNumber)
  .option('-m --memlimit <ops>', 'Memory limit for pwbox', parseSuffixedNumber)
  .on('--help', () => {
    console.log('');
    console.log('  Example:');
    console.log('');
    console.log('    $ bench.js -o 512k --memlimit 16M 1k,4k,16k,1M');
    console.log('');
  })
  .parse(process.argv);

const messageSizes = program.args.length === 0
  ? DEFAULT_SIZES
  : program.args[0].split(',').map(parseSuffixedNumber);

program.opslimit = program.opslimit || pwbox.defaultOpslimit;
program.memlimit = program.memlimit || pwbox.defaultMemlimit;

if (
  typeof program.opslimit !== 'number' ||
  typeof program.memlimit !== 'number' ||
  !messageSizes.every(size => size > 0)
) {
  program.outputHelp();
  process.exit(1);
}

const pwboxOptions = {
  opslimit: program.opslimit,
  memlimit: program.memlimit
};
console.log('pwbox options:', pwboxOptions);
console.log('Message sizes:', messageSizes);
console.log('');

const suites = createSuites(messageSizes, pwboxOptions);
runSuites(suites, {
  cycle (event) {
    console.log(event.target.toString());
  },
  complete () {}
});
