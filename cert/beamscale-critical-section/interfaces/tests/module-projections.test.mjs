import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const manifest = JSON.parse(fs.readFileSync('module-projections/manifest.json', 'utf8'));
const directGuestLanguages = ['erlang', 'gleam'];

function checkedExample(entry) {
  assert.ok(entry.example, `${entry.id} must provide an example`);
  assert.equal(path.isAbsolute(entry.example), false, `${entry.id}: example must be repository-relative`);
  assert.equal(entry.example.split('/').includes('..'), false, `${entry.id}: example must not traverse parents`);
  const normalized = path.normalize(entry.example);
  assert.equal(normalized.startsWith(`..${path.sep}`), false, `${entry.id}: example escapes repository`);
  return normalized;
}

test('projection manifest keeps the direct guest boundary BEAM-only', () => {
  assert.equal(manifest.version, 'bmscl.module-projections/v1');
  assert.equal(manifest.runtime_family, 'beam');
  assert.deepEqual(manifest.rules.direct_guest_languages, directGuestLanguages);
  assert.equal(manifest.rules.non_beam_projection_does_not_imply_guest_support, true);
  assert.equal(manifest.rules.capabilities_are_runtime_grants_not_imports, true);

  const ids = manifest.languages.map((entry) => entry.id);
  assert.equal(new Set(ids).size, ids.length, 'projection ids must be unique');

  const direct = manifest.languages
    .filter((entry) => entry.role === 'direct_guest')
    .map((entry) => entry.id)
    .sort();

  assert.deepEqual(direct, [...directGuestLanguages].sort());
});

test('direct guest projections have confined non-empty examples', () => {
  for (const entry of manifest.languages.filter((item) => item.role === 'direct_guest')) {
    const example = checkedExample(entry);
    assert.ok(fs.existsSync(example), `${entry.id}: missing ${example}`);
    const stat = fs.statSync(example);
    assert.ok(stat.isFile(), `${entry.id}: example must be a regular file`);
    assert.ok(stat.size > 0, `${entry.id}: empty projection`);
  }
});

test('Erlang projection retains behaviour and callback obligations', () => {
  const behaviour = fs.readFileSync('module-projections/erlang/bmscl_module.erl', 'utf8');
  const example = fs.readFileSync('module-projections/erlang/example_module.erl', 'utf8');

  assert.match(behaviour, /-callback\s+handle\([\s\S]*?\)\s*->/);
  assert.match(behaviour, /-callback\s+module_kind\(\)\s*->\s*lambda\s*\|\s*http\s*\|\s*rpc\s*\|\s*actor\s*\|\s*worker\./);
  assert.match(example, /-behaviour\(bmscl_module\)\./);
  assert.match(example, /-export\(\[handle\/2,\s*module_kind\/0,\s*module_name\/0\]\)\./);
});

test('Gleam projection stays a valid expression-oriented typed export shape', () => {
  const source = fs.readFileSync('module-projections/gleam/module_contract.gleam', 'utf8');

  assert.match(source, /pub\s+opaque\s+type\s+Module\(context,\s*input,\s*output\)/);
  assert.match(source, /handle:\s*fn\(context,\s*input\)\s*->\s*Result\(output,\s*String\)/);
  assert.doesNotMatch(source, /\breturn\b/, 'Gleam has no return keyword; the final expression is returned');
});

test('non-BEAM projections cannot claim direct guest execution', () => {
  for (const entry of manifest.languages) {
    if (!directGuestLanguages.includes(entry.id)) {
      assert.notEqual(entry.role, 'direct_guest', `${entry.id} widened the guest boundary`);
    }
  }
});

test('projection metadata cannot widen runtime capabilities', () => {
  assert.equal(manifest.rules.capabilities_are_runtime_grants_not_imports, true);
  for (const entry of manifest.languages) {
    assert.equal('capabilities' in entry, false, `${entry.id}: projection metadata must not grant capabilities`);
    assert.equal('imports' in entry, false, `${entry.id}: projection metadata must not infer capabilities from imports`);
  }
});
