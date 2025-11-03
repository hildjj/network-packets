import {Buffer} from 'node:buffer';

/**
 * Decode hex into bytes from a template literal.
 *
 * @param strings String portions of template.
 * @param values Values to be converted to string.
 * @returns Buffer.
 */
export function hex(
  strings: TemplateStringsArray,
  ...values: unknown[]
): Buffer {
  const hx = String.raw({raw: strings}, ...values)
    .replace(/#[^\n]*/g, '')
    .replace(/\s+/g, '');
  return Buffer.from(hx, 'hex');
}
