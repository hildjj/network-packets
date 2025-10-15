'use strict';

/** @import {TypeDocOptions} from 'typedoc' */
/** @type {TypeDocOptions} */
module.exports = {
  entryPoints: ['src/index.ts'],
  out: 'docs',
  cleanOutputDir: true,
  sidebarLinks: {
    GitHub: 'https://github.com/hildjj/network-packets/',
    Documentation: 'http://hildjj.github.io/network-packets/',
  },
  navigation: {
    includeCategories: false,
    includeGroups: false,
  },
  includeVersion: true,
  categorizeByGroup: false,
  sort: ['static-first', 'alphabetical'],
  exclude: ['**/*.spec.ts'],
};
