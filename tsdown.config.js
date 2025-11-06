import {defineConfig} from 'tsdown';

export default defineConfig({
  clean: true,
  dts: true,
  entry: [
    'src/index.ts',
  ],
  minify: {
    mangle: false,
  },
  format: 'esm',
  outDir: 'lib',
  sourcemap: false,
  splitting: false,
  platform: 'neutral',
});
