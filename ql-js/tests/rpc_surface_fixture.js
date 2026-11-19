/* rpc.declare({ object: 'comment', method: 'ignored' }); */
const text = 'rpc.declare({})';
rpc.declare({ object: 'system', method: 'info' });
rpc['declare']({});
rpc[key]({});
const take = rpc.declare;
function shadow(rpc) { rpc.declare({}); }
rpc.other({});
rpc['other']({});
other.declare({});
