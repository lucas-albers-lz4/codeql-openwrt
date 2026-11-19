'use strict';
// fs.read and other.read are comments, not accesses.
fs.read('/tmp/a');
fs['write']('/tmp/a', value);
fs[method](arg);
const saved = fs.list;
function shadow(fs) { return fs.exec('x'); }
other.read('/tmp/a');
object.fs.read('/tmp/a');
const text = 'fs.remove';
fs[123];
