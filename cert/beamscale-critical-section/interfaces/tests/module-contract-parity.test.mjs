import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const typespec = fs.readFileSync('typespec/main.tsp', 'utf8');
const schema = JSON.parse(fs.readFileSync('schema/module-contract.schema.json', 'utf8'));

const expectedKinds = ['lambda', 'http', 'rpc', 'actor', 'worker'];
const expectedCapabilities = ['cluster_call', 'log'];

function enumValues(name) {
  const match = typespec.match(new RegExp(`enum\\s+${name}\\s*\\{([\\s\\S]*?)\\}`));
  assert.ok(match, `missing TypeSpec enum ${name}`);
  return match[1].split(',').map((value) => value.trim()).filter(Boolean);
}

function requireTypeSpec(pattern, label) {
  assert.match(typespec, pattern, label);
}

test('peer authorities agree on identity and closed vocabularies', () => {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.properties.contract_version.const, 'bmscl-module-contract-v1');
  assert.equal(schema.properties.context_abi.const, 'bmscl.context/v1');
  assert.equal(schema.properties.semantics_version.const, 'bmscl.module-semantics/v2');

  assert.deepEqual(enumValues('ModuleKind'), expectedKinds);
  assert.deepEqual(schema.properties.kind.enum, expectedKinds);
  assert.deepEqual(enumValues('HostedCapability'), expectedCapabilities);
  assert.deepEqual(schema.properties.capabilities.items.enum, expectedCapabilities);
});

test('TypeSpec makes request-response execution kind-constrained', () => {
  requireTypeSpec(/model\s+RequestResponseExecution\s*\{[\s\S]*?invocation:\s*"request_response";[\s\S]*?concurrency:\s*"isolated_invocation";/, 'request-response execution must be fixed');
  for (const [model, kind] of [
    ['LambdaModuleDescriptor', 'lambda'],
    ['HttpModuleDescriptor', 'http'],
    ['RpcModuleDescriptor', 'rpc'],
  ]) {
    requireTypeSpec(new RegExp(`model\\s+${model}\\s+extends\\s+ModuleDescriptorBase\\s*\\{[\\s\\S]*?kind:\\s*"${kind}";[\\s\\S]*?execution:\\s*RequestResponseExecution;`), `${kind} must use request-response execution`);
  }
});

test('actor semantics are fixed identically in both authorities', () => {
  requireTypeSpec(/model\s+ActorExecution\s*\{[\s\S]*?invocation:\s*"mailbox";[\s\S]*?concurrency:\s*"serialized_actor";[\s\S]*?cancellation:\s*"cooperative";/, 'actor execution must be fixed');
  requireTypeSpec(/model\s+ActorModuleDescriptor\s+extends\s+ModuleDescriptorBase\s*\{[\s\S]*?kind:\s*"actor";[\s\S]*?execution:\s*ActorExecution;/, 'actor descriptor must use actor execution');

  const actorRule = schema.allOf.find((rule) => rule?.if?.properties?.kind?.const === 'actor');
  assert.ok(actorRule, 'JSON Schema missing actor rule');
  const constraints = actorRule.then.properties.execution.allOf.map((rule) => rule.properties);
  assert.deepEqual(constraints, [
    { invocation: { const: 'mailbox' } },
    { concurrency: { const: 'serialized_actor' } },
    { cancellation: { const: 'cooperative' } },
  ]);
});

test('worker invocation remains mailbox-or-event without widening capabilities', () => {
  requireTypeSpec(/model\s+WorkerExecution\s*\{[\s\S]*?invocation:\s*"mailbox"\s*\|\s*"event";/, 'worker invocation must be mailbox or event');
  requireTypeSpec(/model\s+WorkerModuleDescriptor\s+extends\s+ModuleDescriptorBase\s*\{[\s\S]*?kind:\s*"worker";[\s\S]*?execution:\s*WorkerExecution;/, 'worker descriptor must use worker execution');

  const workerRule = schema.allOf.find((rule) => rule?.if?.properties?.kind?.const === 'worker');
  assert.deepEqual(workerRule.then.properties.execution.properties.invocation.enum, ['mailbox', 'event']);
  assert.deepEqual(schema.properties.capabilities.items.enum, expectedCapabilities);
});

test('ModuleDescriptor is a closed discriminated union in TypeSpec', () => {
  requireTypeSpec(/union\s+ModuleDescriptor\s*\{[\s\S]*?lambda:\s*LambdaModuleDescriptor,[\s\S]*?http:\s*HttpModuleDescriptor,[\s\S]*?rpc:\s*RpcModuleDescriptor,[\s\S]*?actor:\s*ActorModuleDescriptor,[\s\S]*?worker:\s*WorkerModuleDescriptor,[\s\S]*?\}/, 'module descriptor union must enumerate every kind');
});
