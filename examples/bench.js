'use strict';

const bench = require('benchmark');
const pwbox = require('..');
const sodiumPwbox = pwbox.withCrypto('libsodium');

// Tested message lengths
const dataLengths = [
  32, 64, 128, 256, 512, 1024, 4096, 16384, 65536
];
const password = 'correct horse battery staple';
// Interval (in seconds) between bench cycles
const testDelay = 0.15;

const tweetnaclSuite = new bench.Suite('pwbox.withCrypto(\'tweetnacl\')');
const libsodiumSuite = new bench.Suite('pwbox.withCrypto(\'libsodium\')');

dataLengths.forEach(len => {
  const data = new Uint8Array(len);
  for (let i = 0; i < data.length; i++) {
    data[i] = Math.floor(Math.random() * 256);
  }

  tweetnaclSuite.add(tweetnaclSuite.name + ', message.length = ' + len, {
    defer: true,
    delay: testDelay,
    fn: (deferred) => {
      pwbox(data, password).then(box => {
        if (!(box instanceof Uint8Array) || box.length !== len + pwbox.overheadLength) {
          throw new Error('Invalid box returned');
        }
        deferred.resolve();
      });
    }
  });

  libsodiumSuite.add(libsodiumSuite.name + ', message.length = ' + len, {
    defer: true,
    delay: 0.15,
    fn: (deferred) => {
      sodiumPwbox(data, password).then(box => {
        if (!(box instanceof Uint8Array) || box.length !== len + pwbox.overheadLength) {
          throw new Error('Invalid box returned');
        }
        deferred.resolve();
      });
    }
  });
});

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

runSuites([tweetnaclSuite, libsodiumSuite], {
  cycle (event) {
    console.log(event.target.toString());
  },
  complete () {}
});
