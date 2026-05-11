'use strict';

/**
 * mockChain(singleResult, chainResult)
 *
 * Returns a chainable Supabase-style query builder mock.
 *   - Awaiting the chain directly resolves with chainResult
 *     (e.g. const { data } = await supabase.from('x').update(...).eq(...))
 *   - Calling .single() resolves with singleResult
 *     (e.g. const { data } = await supabase.from('x').select(...).single())
 */
function mockChain(
  singleResult = { data: null,  error: null },
  chainResult  = { data: null,  error: null, count: null }
) {
  const chain = {};
  const methods = [
    'select', 'insert', 'update', 'delete', 'upsert',
    'eq', 'neq', 'in', 'filter', 'is', 'lte', 'gte', 'gt',
    'order', 'range', 'limit',
  ];
  methods.forEach(m => { chain[m] = jest.fn(() => chain); });
  chain.single = jest.fn(() => Promise.resolve(singleResult));
  chain.then   = (res, rej) => Promise.resolve(chainResult).then(res, rej);
  return chain;
}

module.exports = { mockChain };
