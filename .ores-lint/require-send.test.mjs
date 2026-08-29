import assert from 'node:assert/strict';
import test from 'node:test';

import { analyzeSource } from './require-send.mjs';

const missingDelivery = [
  ['rust', 'fn emit(logger: Logger) { logger.info("ready"); }'],
  ['dart', 'void emit(Logger logger) { logger.info("ready"); }'],
  ['gleam', 'pub fn emit() {\n  logging.info("ready")\n  Nil\n}'],
];

for (const [language, source] of missingDelivery) {
  test(`${language} reports an undelivered logging chain`, () => {
    const findings = analyzeSource(source, language);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].message, 'logging chain never calls send()');
  });
}

const delivered = [
  ['rust', 'fn emit(logger: Logger) { logger.info("ready").send(); }'],
  ['dart', 'void emit(Logger logger) { logger.info("ready").send(); }'],
  ['gleam', 'pub fn emit() { logging.info("ready") |> logging.send }'],
];

for (const [language, source] of delivered) {
  test(`${language} accepts a delivered logging chain`, () => {
    assert.deepEqual(analyzeSource(source, language), []);
  });
}

test('the unified next-line suppression is honored', () => {
  const source = [
    'fn emit(logger: Logger) {',
    '  // ores-lint-disable-next-line require-send',
    '  logger.warn("expected test drop");',
    '}',
  ].join('\n');
  assert.deepEqual(analyzeSource(source, 'rust'), []);
});
